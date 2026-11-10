use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use vpn_proto::{SERVICE_GROUP, frames::Access};

use super::{INSTALL_DIR, group_id, running_as_root, user_name};

const UNIT: &str = "/etc/systemd/system/fran-vpn.service";
const UNIT_NAME: &str = "fran-vpn.service";

fn unit_text() -> String {
    format!(
        "[Unit]
Description=Fran VPN service
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
ExecStart={INSTALL_DIR}/fran-vpn --service
Restart=on-failure
RuntimeDirectory=fran-vpn
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
"
    )
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("Couldn't run {program}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(format!("{program} {} failed: {text}", args.join(" ")))
}

fn checks() -> Result<(), String> {
    if !running_as_root() {
        return Err("Setting up Fran's VPN service needs admin rights".to_string());
    }
    if Path::new("/etc/NIXOS").exists() {
        return Err("On NixOS, turn on Fran's VPN service in your configuration with programs.fran.vpnService.enable".to_string());
    }
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("This computer doesn't run systemd, so Fran can't set up its VPN service".to_string());
    }
    Ok(())
}

/// pkexec says who asked, which is the one to add to the group. A root caller (tests, a root session) names the user.
fn caller_uid(user: Option<&str>) -> Result<u32, String> {
    std::env::var("PKEXEC_UID")
        .ok()
        .or_else(|| user.map(str::to_string))
        .and_then(|uid| uid.trim().parse().ok())
        .ok_or_else(|| "Fran didn't say which account to add".to_string())
}

fn apply_group(access: Access, user: Option<&str>) -> Result<(), String> {
    match access {
        Access::Group => {
            let (name, _) = user_name(caller_uid(user)?).ok_or_else(|| "Your account wasn't found".to_string())?;
            run("groupadd", &["--system", "-f", SERVICE_GROUP])?;
            run("usermod", &["-a", "-G", SERVICE_GROUP, &name])
        }
        Access::Everyone if group_id(SERVICE_GROUP).is_some() => run("groupdel", &[SERVICE_GROUP]),
        Access::Everyone => Ok(()),
    }
}

fn write_access(access: Access) -> Result<(), String> {
    let path = PathBuf::from(INSTALL_DIR).join("access");
    std::fs::write(&path, access.as_arg()).map_err(|error| format!("Couldn't write {}: {error}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())
}

/// Copies this binary to a folder only root can write, since the one Fran ships in can be the user's own (an
/// AppImage, a home folder install), and anything there could then run as root.
pub fn install(access: Access, user: Option<&str>) -> Result<(), String> {
    checks()?;
    let dir = Path::new(INSTALL_DIR);
    std::fs::create_dir_all(dir).map_err(|error| format!("Couldn't make {INSTALL_DIR}: {error}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let staged = dir.join("fran-vpn.new");
    std::fs::copy(&exe, &staged).map_err(|error| format!("Couldn't copy the service to {INSTALL_DIR}: {error}"))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    std::fs::rename(&staged, dir.join("fran-vpn")).map_err(|error| error.to_string())?;
    write_access(access)?;
    apply_group(access, user)?;
    std::fs::write(UNIT, unit_text()).map_err(|error| format!("Couldn't write {UNIT}: {error}"))?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", UNIT_NAME])?;
    run("systemctl", &["restart", UNIT_NAME])
}

pub fn uninstall() -> Result<(), String> {
    checks()?;
    if Path::new(UNIT).exists() {
        run("systemctl", &["disable", "--now", UNIT_NAME])?;
        std::fs::remove_file(UNIT).map_err(|error| format!("Couldn't remove {UNIT}: {error}"))?;
        run("systemctl", &["daemon-reload"])?;
    }
    super::net::clean_leftovers();
    let _ = std::fs::remove_dir_all(super::state_dir());
    if Path::new(INSTALL_DIR).exists() {
        std::fs::remove_dir_all(INSTALL_DIR).map_err(|error| format!("Couldn't remove {INSTALL_DIR}: {error}"))?;
    }
    apply_group(Access::Everyone, None)
}

pub fn set_access(access: Access, user: Option<&str>) -> Result<(), String> {
    checks()?;
    if !Path::new(INSTALL_DIR).join("fran-vpn").exists() {
        return Err("Fran's VPN service isn't set up".to_string());
    }
    write_access(access)?;
    apply_group(access, user)
}
