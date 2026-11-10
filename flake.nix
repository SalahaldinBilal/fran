{
  description = "fran";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    crane,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux"] (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;
        craneLib = crane.mkLib pkgs;

        nativeBuildInputs = with pkgs; [
          pkg-config
          wrapGAppsHook3
        ];

        buildInputs = with pkgs; [
          webkitgtk_4_1
          gtk3
          libsoup_3
          glib-networking
          dbus
          openssl
          pam
          libayatana-appindicator
        ];

        frontend = pkgs.buildNpmPackage {
          pname = "fran-frontend";
          version = (lib.importJSON ./package.json).version;
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.difference ./. ./src-tauri;
          };
          npmDeps = pkgs.importNpmLock {npmRoot = ./.;};
          npmConfigHook = pkgs.importNpmLock.npmConfigHook;
          env.VITE_NIX_BUILD = "1";
          installPhase = "cp -r dist $out";
        };

        # The repo is a Cargo workspace: the app in src-tauri, the VPN worker and its frames in crates/.
        commonArgs = {
          src = ./.;
          cargoToml = ./src-tauri/Cargo.toml;
          cargoLock = ./Cargo.lock;
          strictDeps = true;
          inherit nativeBuildInputs buildInputs;
          cargoExtraArgs = "--locked -p fran --features tauri/custom-protocol";
        };

        # The VPN worker and service. Only it builds OpenVPN 3, and openvpn-rust-bindings links nixpkgs' OpenSSL
        # instead of building its own.
        vpnArgs =
          commonArgs
          // {
            pname = "fran-vpn";
            cargoExtraArgs = "--locked -p vpn-worker";
            OPENSSL_NO_VENDOR = "1";
            nativeBuildInputs = [pkgs.pkg-config];
            buildInputs = [pkgs.openssl];
          };

        fran-vpn = craneLib.buildPackage (
          vpnArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly vpnArgs;
            doCheck = false;
          }
        );

        fran = craneLib.buildPackage (
          commonArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly commonArgs;
            doCheck = false;
            preBuild = ''
              cp -r ${frontend} dist
            '';
            # webkitgtk's DMA-BUF renderer hits Wayland protocol errors on NVIDIA
            # The tray loads libayatana-appindicator at runtime, so it has to be on the library path.
            preFixup = ''
              gappsWrapperArgs+=(--set-default WEBKIT_DISABLE_DMABUF_RENDERER 1)
              gappsWrapperArgs+=(--prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath [pkgs.libayatana-appindicator]})
            '';
            postInstall = ''
              install -Dm644 src-tauri/icons/32x32.png $out/share/icons/hicolor/32x32/apps/fran.png
              install -Dm644 src-tauri/icons/128x128.png $out/share/icons/hicolor/128x128/apps/fran.png
              install -Dm644 src-tauri/icons/128x128@2x.png $out/share/icons/hicolor/256x256/apps/fran.png
              install -Dm644 ${desktopItem}/share/applications/*.desktop -t $out/share/applications
              # Picked up by polkit when the package is in environment.systemPackages on NixOS.
              install -Dm644 src-tauri/linux/com.fran.app.policy $out/share/polkit-1/actions/com.fran.app.policy
              # Fran looks for its VPN worker next to its own executable.
              install -Dm755 ${fran-vpn}/bin/fran-vpn $out/bin/fran-vpn
            '';
            meta = {
              description = "A desktop client for databases, SSH and VPNs";
              license = lib.licenses.gpl3Plus;
              mainProgram = "fran";
              platforms = lib.platforms.linux;
            };
          }
        );

        desktopItem = pkgs.makeDesktopItem {
          name = "fran";
          desktopName = "Fran";
          exec = "fran";
          icon = "fran";
          comment = "A desktop client for databases, SSH and VPNs";
          categories = ["Development" "Database" "Network"];
        };
      in {
        packages.default = fran;

        devShells.default = craneLib.devShell {
          inputsFrom = [fran];
          packages = with pkgs; [
            rust-analyzer
            rustfmt
            clippy
            nodejs_26
          ];
          GIO_MODULE_DIR = "${pkgs.glib-networking}/lib/gio/modules";
          WEBKIT_DISABLE_DMABUF_RENDERER = 1;
        };
      }
    )
    // {
      # Fran's VPN service, so VPNs turn on for the whole computer without the admin password each time. NixOS
      # manages /etc and has no /usr/local, so it's set up here instead of from Settings > VPN.
      nixosModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.programs.fran.vpnService;
      in {
        options.programs.fran.vpnService = {
          enable = lib.mkEnableOption "Fran's VPN service";
          access = lib.mkOption {
            type = lib.types.enum ["everyone" "group"];
            default = "everyone";
            description = ''
              Who may turn VPNs on with it. "everyone": any account signed in at this computer, not service
              accounts or SSH sessions. "group": root and members of the fran-vpn, wheel or sudo groups.
            '';
          };
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
            description = "The Fran package whose fran-vpn runs as the service.";
          };
        };
        config = lib.mkIf cfg.enable {
          users.groups.fran-vpn = lib.mkIf (cfg.access == "group") {};
          systemd.services.fran-vpn = {
            description = "Fran VPN service";
            after = ["network-online.target" "systemd-resolved.service"];
            wants = ["network-online.target"];
            wantedBy = ["multi-user.target"];
            serviceConfig = {
              ExecStart = "${cfg.package}/bin/fran-vpn --service ${cfg.access}";
              Restart = "on-failure";
              RuntimeDirectory = "fran-vpn";
              RuntimeDirectoryMode = "0755";
              RuntimeDirectoryPreserve = "yes";
              NoNewPrivileges = true;
              ProtectHome = true;
              ProtectSystem = "strict";
              CapabilityBoundingSet = "CAP_NET_ADMIN";
            };
          };
        };
      };
    };
}
