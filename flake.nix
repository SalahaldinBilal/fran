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

        runtimeLibraryPath = lib.makeLibraryPath [pkgs.libayatana-appindicator];

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

        commonArgs = {
          src = ./.;
          cargoToml = ./src-tauri/Cargo.toml;
          cargoLock = ./Cargo.lock;
          strictDeps = true;
          inherit nativeBuildInputs buildInputs;
          cargoExtraArgs = "--locked -p fran --features tauri/custom-protocol";
        };

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
            preFixup = ''
              gappsWrapperArgs+=(--set-default WEBKIT_DISABLE_DMABUF_RENDERER 1)
              gappsWrapperArgs+=(--prefix LD_LIBRARY_PATH : ${runtimeLibraryPath})
            '';
            postInstall = ''
              install -Dm644 src-tauri/icons/32x32.png $out/share/icons/hicolor/32x32/apps/fran.png
              install -Dm644 src-tauri/icons/128x128.png $out/share/icons/hicolor/128x128/apps/fran.png
              install -Dm644 src-tauri/icons/128x128@2x.png $out/share/icons/hicolor/256x256/apps/fran.png
              install -Dm644 ${desktopItem}/share/applications/*.desktop -t $out/share/applications

              install -Dm644 src-tauri/linux/com.fran.app.policy $out/share/polkit-1/actions/com.fran.app.policy
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
          LD_LIBRARY_PATH = runtimeLibraryPath;
        };
      }
    )
    // {
      nixosModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.programs.fran;
      in {
        options.programs.fran = {
          enable = lib.mkEnableOption "Fran";
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
            description = "The Fran package to install.";
          };
          vpnService = {
            enable = lib.mkEnableOption "Fran's VPN service";
            access = lib.mkOption {
              type = lib.types.enum ["everyone" "group"];
              default = "everyone";
              description = ''
                Who may turn VPNs on through the service. Root always can. Service accounts and remote sessions
                such as SSH never can. "everyone" lets in any account signed in at this computer. "group" only
                lets in members of the fran-vpn, wheel, sudo or admin groups.
              '';
            };
            package = lib.mkOption {
              type = lib.types.package;
              default = cfg.package;
              defaultText = lib.literalExpression "config.programs.fran.package";
              description = "The Fran package whose fran-vpn runs as the service.";
            };
          };
        };
        config = lib.mkMerge [
          (lib.mkIf cfg.enable {environment.systemPackages = [cfg.package];})
          (lib.mkIf cfg.vpnService.enable {
            users.groups.fran-vpn = lib.mkIf (cfg.vpnService.access == "group") {};
            systemd.services.fran-vpn = {
              description = "Fran VPN service";
              after = ["network-online.target" "systemd-resolved.service"];
              wants = ["network-online.target"];
              wantedBy = ["multi-user.target"];
              serviceConfig = {
                ExecStart = "${cfg.vpnService.package}/bin/fran-vpn --service ${cfg.vpnService.access}";
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
          })
        ];
      };
    };
}
