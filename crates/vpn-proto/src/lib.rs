pub mod frames;
pub mod profile;

/// Bumped whenever a frame changes shape. Both sides send it in their first frame.
pub const PROTOCOL_VERSION: u32 = 2;

pub const BUILD: &str = env!("CARGO_PKG_VERSION");

pub const WORKER_ARG: &str = "--worker";
pub const SERVICE_ARG: &str = "--service";
pub const INSTALL_ARG: &str = "--install";
pub const UNINSTALL_ARG: &str = "--uninstall";
pub const ACCESS_ARG: &str = "--set-access";

#[cfg(windows)]
pub const SERVICE_PIPE: &str = r"\\.\pipe\fran-vpn";
/// Inside the systemd unit's runtime folder, the one place it can write with `ProtectSystem=strict`.
#[cfg(target_os = "linux")]
pub const SERVICE_SOCKET: &str = "/run/fran-vpn/fran-vpn.sock";
#[cfg(target_os = "macos")]
pub const SERVICE_SOCKET: &str = "/var/run/fran-vpn/fran-vpn.sock";

/// The launch daemon's label on macOS.
pub const SERVICE_LABEL: &str = "com.fran.vpn";

pub const SERVICE_NAME: &str = "FranVpn";
#[cfg(windows)]
pub const SERVICE_GROUP: &str = "Fran VPN Users";
#[cfg(not(windows))]
pub const SERVICE_GROUP: &str = "fran-vpn";
