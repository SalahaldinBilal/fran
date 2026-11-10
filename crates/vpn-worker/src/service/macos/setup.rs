//! A classic launch daemon instead of `SMAppService`, which only registers daemons from signed apps. The plist and
//! the binary are root-owned, so only an administrator can change what runs as root.

use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

use vpn_proto::{SERVICE_LABEL, frames::Access};

use super::{INSTALL_DIR, allowed_users, running_as_root};

fn plist_path() -> String {
    format!("/Library/LaunchDaemons/{SERVICE_LABEL}.plist")
}

fn plist_text() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{INSTALL_DIR}/fran-vpn</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"#,
        vpn_proto::SERVICE_ARG
    )
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("Couldn't run {program}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!("{program} {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim()))
}

fn checks() -> Result<(), String> {
    if running_as_root() { Ok(()) } else { Err("Setting up Fran's VPN service needs admin rights".to_string()) }
}

fn write_root_file(name: &str, text: &str) -> Result<(), String> {
    let path = Path::new(INSTALL_DIR).join(name);
    std::fs::write(&path, text).map_err(|error| format!("Couldn't write {}: {error}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())
}

/// Everyone clears the list. With "group", the account that set it up is added to who's there already.
fn write_access(access: Access, user: Option<&str>) -> Result<(), String> {
    write_root_file("access", access.as_arg())?;
    let users = match access {
        Access::Everyone => Vec::new(),
        Access::Group => {
            let uid: u32 = user.and_then(|user| user.trim().parse().ok()).ok_or("Fran didn't say which account to add")?;
            let mut users = allowed_users();
            if !users.contains(&uid) {
                users.push(uid);
            }
            users
        }
    };
    let text: String = users.iter().map(|uid| format!("{uid}\n")).collect();
    write_root_file("allowed", &text)
}

fn stop_daemon() {
    let _ = run("/bin/launchctl", &["bootout", &format!("system/{SERVICE_LABEL}")]);
}

pub fn install(access: Access, user: Option<&str>) -> Result<(), String> {
    checks()?;
    let dir = Path::new(INSTALL_DIR);
    std::fs::create_dir_all(dir).map_err(|error| format!("Couldn't make {INSTALL_DIR}: {error}"))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    stop_daemon();
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let staged = dir.join("fran-vpn.new");
    std::fs::copy(&exe, &staged).map_err(|error| format!("Couldn't copy the service to {INSTALL_DIR}: {error}"))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    std::fs::rename(&staged, dir.join("fran-vpn")).map_err(|error| error.to_string())?;
    write_access(access, user)?;
    let plist = plist_path();
    std::fs::write(&plist, plist_text()).map_err(|error| format!("Couldn't write {plist}: {error}"))?;
    std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())?;
    run("/bin/launchctl", &["bootstrap", "system", &plist])
}

pub fn uninstall() -> Result<(), String> {
    checks()?;
    stop_daemon();
    let plist = plist_path();
    if Path::new(&plist).exists() {
        std::fs::remove_file(&plist).map_err(|error| format!("Couldn't remove {plist}: {error}"))?;
    }
    super::net::clean_leftovers();
    let _ = std::fs::remove_dir_all(super::state_dir());
    if Path::new(INSTALL_DIR).exists() {
        std::fs::remove_dir_all(INSTALL_DIR).map_err(|error| format!("Couldn't remove {INSTALL_DIR}: {error}"))?;
    }
    Ok(())
}

pub fn set_access(access: Access, user: Option<&str>) -> Result<(), String> {
    checks()?;
    if !Path::new(INSTALL_DIR).join("fran-vpn").exists() {
        return Err("Fran's VPN service isn't set up".to_string());
    }
    write_access(access, user)
}
