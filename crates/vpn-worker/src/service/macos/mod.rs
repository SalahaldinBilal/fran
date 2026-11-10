pub mod net;
pub mod setup;

use std::{
    ffi::{CStr, CString},
    io::BufReader,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    thread,
};

use vpn_proto::{SERVICE_SOCKET, frames::Access};

/// Root-owned, so only an administrator can change the binary, the access setting or the allowed list.
pub const INSTALL_DIR: &str = "/Library/Application Support/Fran/vpn";
const RUN_DIR: &str = "/var/run/fran-vpn";
/// macOS gives people accounts from 501 up. Below are system and service accounts.
const FIRST_USER: u32 = 501;
const ADMIN_GROUP: libc::gid_t = 80;

pub fn state_dir() -> PathBuf {
    PathBuf::from(RUN_DIR)
}

pub fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn read_access() -> Result<Access, String> {
    std::fs::read_to_string(Path::new(INSTALL_DIR).join("access"))
        .ok()
        .and_then(|text| Access::from_arg(&text))
        .ok_or_else(|| "Fran's VPN service has no access setting. Set it up again in Settings, VPN.".to_string())
}

/// The accounts allowed in with "Only me and administrators", one user id per line.
pub fn allowed_users() -> Vec<u32> {
    std::fs::read_to_string(Path::new(INSTALL_DIR).join("allowed"))
        .map(|text| text.lines().filter_map(|line| line.trim().parse().ok()).collect())
        .unwrap_or_default()
}

fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err("Fran's VPN service couldn't tell who connected".to_string());
    }
    Ok(uid)
}

pub fn user_name(uid: u32) -> Option<(String, libc::gid_t)> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let result = unsafe { libc::getpwuid_r(uid, &mut entry, buf.as_mut_ptr(), buf.len(), &mut found) };
    if result != 0 || found.is_null() {
        return None;
    }
    Some((unsafe { CStr::from_ptr(entry.pw_name) }.to_string_lossy().to_string(), entry.pw_gid))
}

/// Read from the directory service now, so someone just made an administrator doesn't have to sign in again.
fn is_admin(uid: u32) -> bool {
    let Some((name, primary)) = user_name(uid) else { return false };
    let Ok(name) = CString::new(name) else { return false };
    let mut groups = vec![0 as libc::c_int; 256];
    let mut count = groups.len() as libc::c_int;
    if unsafe { libc::getgrouplist(name.as_ptr(), primary as libc::c_int, groups.as_mut_ptr(), &mut count) } < 0 {
        return false;
    }
    groups.iter().take(count.max(0) as usize).any(|group| *group as libc::gid_t == ADMIN_GROUP)
}

/// Whoever owns the console is signed in at this computer. Someone only in over SSH, or switched away to the
/// login window, isn't.
fn console_user() -> Option<u32> {
    std::fs::metadata("/dev/console").ok().map(|meta| meta.uid())
}

fn allowed(uid: u32, access: Access) -> Result<(), String> {
    if uid == 0 {
        return Ok(());
    }
    if uid < FIRST_USER {
        return Err("Service accounts can't use Fran's VPN service".to_string());
    }
    if console_user() != Some(uid) {
        return Err("Fran's VPN service only takes the account signed in at this computer, not one over the network".to_string());
    }
    match access {
        Access::Everyone => Ok(()),
        Access::Group if is_admin(uid) || allowed_users().contains(&uid) => Ok(()),
        Access::Group => Err("Fran's VPN service only takes administrators and the accounts it was set up for. Ask an administrator to add yours.".to_string()),
    }
}

pub fn serve(_args: &[String]) -> i32 {
    if !running_as_root() {
        eprintln!("Fran's VPN service runs as root");
        return 1;
    }
    if let Err(error) = std::fs::create_dir_all(RUN_DIR).and_then(|_| std::fs::set_permissions(RUN_DIR, std::fs::Permissions::from_mode(0o755))) {
        eprintln!("Couldn't make {RUN_DIR}: {error}");
        return 1;
    }
    net::clean_leftovers();

    let socket = Path::new(SERVICE_SOCKET);
    let _ = std::fs::remove_file(socket);
    let listener = match UnixListener::bind(socket) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("Couldn't listen on {SERVICE_SOCKET}: {error}");
            return 1;
        }
    };
    // Anyone may connect. Who gets a tunnel is checked per connection from the socket's peer.
    if let Err(error) = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666)) {
        eprintln!("Couldn't open up {SERVICE_SOCKET}: {error}");
        return 1;
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        thread::spawn(move || {
            let (access, caller) = match read_access() {
                Ok(access) => (access, peer_uid(&stream).and_then(|uid| allowed(uid, access))),
                Err(error) => (Access::Group, Err(error)),
            };
            let Ok(reader) = stream.try_clone() else { return };
            super::handle(BufReader::new(reader), Box::new(stream), access, caller);
        });
    }
    0
}
