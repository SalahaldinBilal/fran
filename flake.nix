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

        # Outside the Cargo workspace, with its own lockfile.
        fran-sync-server = pkgs.rustPlatform.buildRustPackage {
          pname = "fran-sync-server";
          version = (lib.importTOML ./server/Cargo.toml).package.version;
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              (lib.fileset.difference ./server (lib.fileset.maybeMissing ./server/target))
              ./crates/sync-proto
            ];
          };
          sourceRoot = "source/server";
          cargoLock.lockFile = ./server/Cargo.lock;
          doCheck = false;
          meta = {
            description = "Fran's sync server, storing end-to-end encrypted records";
            license = lib.licenses.gpl3Plus;
            mainProgram = "fran-sync-server";
            platforms = lib.platforms.linux;
          };
        };

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
        packages.fran-sync-server = fran-sync-server;

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

      nixosModules.fran-sync = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.services.fran-sync;
      in {
        options.services.fran-sync = {
          enable = lib.mkEnableOption "Fran's sync server";
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.fran-sync-server;
            description = "The fran-sync-server package to run.";
          };
          environment = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            example = {
              BIND = "127.0.0.1:8787";
              SIGNUP = "closed";
            };
            description = ''
              The server's settings, as environment variables. server/README.md lists them. Without DATABASE_URL
              the database is /var/lib/fran-sync/fran-sync.db. SERVER_KEY doesn't belong here, since this ends
              up in the Nix store.
            '';
          };
          environmentFile = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            description = "A file outside the Nix store with SERVER_KEY=<64 hex characters>, from `openssl rand -hex 32`.";
          };
        };
        config = lib.mkIf cfg.enable {
          environment.systemPackages = [cfg.package];
          users.groups.fran-sync = {};
          users.users.fran-sync = {
            isSystemUser = true;
            group = "fran-sync";
          };
          systemd.services.fran-sync = {
            description = "Fran sync server";
            after = ["network.target"];
            wantedBy = ["multi-user.target"];
            environment = cfg.environment;
            serviceConfig = {
              ExecStart = lib.getExe cfg.package;
              EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
              User = "fran-sync";
              Group = "fran-sync";
              StateDirectory = "fran-sync";
              StateDirectoryMode = "0700";
              WorkingDirectory = "/var/lib/fran-sync";
              Restart = "on-failure";
              # The server stops on Ctrl+C.
              KillSignal = "SIGINT";
              NoNewPrivileges = true;
              PrivateTmp = true;
              ProtectHome = true;
              ProtectSystem = "strict";
            };
          };
        };
      };
    };
}
