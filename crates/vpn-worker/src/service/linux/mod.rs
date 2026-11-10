pub mod net;
mod netlink;
pub mod setup;

use std::{
    ffi::{CStr, CString},
    io::BufReader,
    os::unix::{
        fs::PermissionsExt,
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    thread,
};

use vpn_proto::{SERVICE_GROUP, SERVICE_SOCKET, frames::Access};

pub const INSTALL_DIR: &str = "/usr/local/libexec/fran";
const RUN_DIR: &str = "/run/fran-vpn";
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin"];
const NOBODY: u32 = 65534;

pub fn state_dir() -> PathBuf {
    PathBuf::from(RUN_DIR)
}

pub fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// From `--service <access>` (how the NixOS module runs it), else the file setup wrote next to the binary.
fn read_access(arg: Option<&String>) -> Result<Access, String> {
    if let Some(arg) = arg {
        return Access::from_arg(arg).ok_or_else(|| format!("Unknown access setting {arg}"));
    }
    let file = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.join("access")));
    file.and_then(|file| std::fs::read_to_string(file).ok())
        .and_then(|text| Access::from_arg(&text))
        .ok_or_else(|| "Fran's VPN service has no access setting. Set it up again in Settings, VPN.".to_string())
}

fn peer(stream: &UnixStream) -> Result<libc::ucred, String> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    if result != 0 {
        return Err("Fran's VPN service couldn't tell who connected".to_string());
    }
    Ok(cred)
}

/// The first user id for people, not system accounts, from login.defs.
fn uid_min() -> u32 {
    std::fs::read_to_string("/etc/login.defs")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("UID_MIN")).then(|| words.next()?.parse().ok()).flatten()
            })
        })
        .unwrap_or(1000)
}

/// The logind session a process runs in, from its cgroup path, the way `sd_pid_get_session` finds it.
fn session_of(cgroup: &str) -> Option<String> {
    let session = cgroup.lines().flat_map(|line| line.split('/')).find_map(|part| part.strip_prefix("session-")?.strip_suffix(".scope"))?;
    session.chars().all(|character| character.is_ascii_alphanumeric()).then(|| session.to_string())
}

fn session_remote(session: &str) -> Option<bool> {
    let state = std::fs::read_to_string(Path::new("/run/systemd/sessions").join(session)).ok()?;
    Some(state.lines().any(|line| line.trim() == "REMOTE=1"))
}

/// systemd-logind marks sessions over SSH and the like as remote. A process outside any session (an app a desktop
/// started through the user's systemd) counts as local when the account has a local session. Without logind it
/// can't be told, so it's let through.
fn remote_caller(pid: libc::pid_t, uid: u32) -> bool {
    if let Some(session) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok().and_then(|cgroup| session_of(&cgroup)) {
        return session_remote(&session).unwrap_or(false);
    }
    let Ok(user) = std::fs::read_to_string(format!("/run/systemd/users/{uid}")) else {
        return false;
    };
    let sessions: Vec<&str> = user.lines().find_map(|line| line.strip_prefix("SESSIONS=")).map(|list| list.split_whitespace().collect()).unwrap_or_default();
    !sessions.iter().any(|session| session_remote(session) == Some(false))
}

pub fn user_name(uid: u32) -> Option<(String, libc::gid_t)> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let result = unsafe { libc::getpwuid_r(uid, &mut entry, buf.as_mut_ptr(), buf.len(), &mut found) };
    if result != 0 || found.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(entry.pw_name) }.to_string_lossy().to_string();
    Some((name, entry.pw_gid))
}

pub fn group_id(name: &str) -> Option<libc::gid_t> {
    let name = CString::new(name).ok()?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 64 * 1024];
    let result = unsafe { libc::getgrnam_r(name.as_ptr(), &mut entry, buf.as_mut_ptr(), buf.len(), &mut found) };
    (result == 0 && !found.is_null()).then_some(entry.gr_gid)
}

/// The groups in /etc/group (or wherever NSS reads them) right now, so someone just added doesn't have to sign in again.
fn groups_of(uid: u32) -> Vec<libc::gid_t> {
    let Some((name, primary)) = user_name(uid) else {
        return Vec::new();
    };
    let Ok(name) = CString::new(name) else {
        return Vec::new();
    };
    let mut count: libc::c_int = 64;
    loop {
        let mut groups = vec![0 as libc::gid_t; count as usize];
        let mut wanted = count;
        let result = unsafe { libc::getgrouplist(name.as_ptr(), primary, groups.as_mut_ptr(), &mut wanted) };
        if result >= 0 {
            groups.truncate(wanted.max(0) as usize);
            return groups;
        }
        if wanted <= count || wanted > 65536 {
            return Vec::new();
        }
        count = wanted;
    }
}

fn allowed(cred: &libc::ucred, access: Access) -> Result<(), String> {
    if cred.uid == 0 {
        return Ok(());
    }
    if cred.uid < uid_min() || cred.uid == NOBODY {
        return Err("Service accounts can't use Fran's VPN service".to_string());
    }
    if remote_caller(cred.pid, cred.uid) {
        return Err("Fran's VPN service only takes accounts signed in at this computer, not over the network".to_string());
    }
    match access {
        Access::Everyone => Ok(()),
        Access::Group => {
            let groups = groups_of(cred.uid);
            let wanted: Vec<libc::gid_t> = std::iter::once(SERVICE_GROUP).chain(ADMIN_GROUPS.iter().copied()).filter_map(group_id).collect();
            if groups.iter().any(|group| wanted.contains(group)) {
                Ok(())
            } else {
                Err(format!("Fran's VPN service only takes administrators and members of the {SERVICE_GROUP} group. Ask an administrator to add your account."))
            }
        }
    }
}

pub fn serve(args: &[String]) -> i32 {
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

    let access_arg = args.first().cloned();
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let access_arg = access_arg.clone();
        thread::spawn(move || {
            let (access, caller) = match read_access(access_arg.as_ref()) {
                Ok(access) => (access, peer(&stream).and_then(|cred| allowed(&cred, access))),
                Err(error) => (Access::Group, Err(error)),
            };
            let Ok(reader) = stream.try_clone() else { return };
            super::handle(BufReader::new(reader), Box::new(stream), access, caller);
        });
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_accounts_are_refused_in_both_modes() {
        let pid = std::process::id() as libc::pid_t;
        for uid in [1, 999, NOBODY] {
            let cred = libc::ucred { pid, uid, gid: uid };
            assert!(allowed(&cred, Access::Everyone).is_err(), "uid {uid} let in with everyone");
            assert!(allowed(&cred, Access::Group).is_err(), "uid {uid} let in with group");
        }
    }

    #[test]
    fn sessions_are_found_in_the_cgroup_path() {
        assert_eq!(session_of("0::/user.slice/user-1000.slice/session-3.scope\n").as_deref(), Some("3"));
        assert_eq!(session_of("0::/user.slice/user-1000.slice/session-c2.scope\n").as_deref(), Some("c2"));
        // An app started by the user's systemd, outside any login session.
        assert_eq!(session_of("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-fran.scope\n"), None);
    }
}
