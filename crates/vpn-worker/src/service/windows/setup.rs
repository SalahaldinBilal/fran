use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use vpn_proto::{SERVICE_GROUP, SERVICE_NAME, frames::Access};
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        NetworkManagement::NetManagement::{LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel},
        Security::{Authorization::ConvertStringSidToSidW, PSID},
        System::{
            Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW},
            Services::{
                CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
                SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
                StartServiceW,
            },
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use super::{SETTINGS_KEY, install_dir, net};

const NERR_GROUP_EXISTS: u32 = 2223;
const NERR_GROUP_NOT_FOUND: u32 = 2220;
const ERROR_ALIAS_EXISTS: u32 = 1379;
const ERROR_NO_SUCH_ALIAS: u32 = 1376;
const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
const STOP_WAIT: Duration = Duration::from_secs(15);

struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

fn manager() -> Result<Handle, String> {
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) }
        .map(Handle)
        .map_err(|error| format!("Setting up Fran's VPN service needs admin rights: {error}"))
}

fn existing(manager: &Handle) -> Option<Handle> {
    unsafe { OpenServiceW(manager.0, &HSTRING::from(SERVICE_NAME), SERVICE_ALL_ACCESS) }.ok().map(Handle)
}

fn stop(service: &Handle) {
    let mut status = SERVICE_STATUS::default();
    let _ = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
    let started = Instant::now();
    while started.elapsed() < STOP_WAIT {
        if unsafe { QueryServiceStatus(service.0, &mut status) }.is_err() || status.dwCurrentState == SERVICE_STOPPED {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Copying right after the service stops can still find its exe in use for a moment.
fn copy(from: &Path, to: &Path) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match std::fs::copy(from, to) {
            Ok(_) => return Ok(()),
            Err(_) if started.elapsed() < STOP_WAIT => thread::sleep(Duration::from_millis(300)),
            Err(error) => return Err(format!("Couldn't copy {} to {}: {error}", from.display(), to.display())),
        }
    }
}

fn write_access(access: Access) -> Result<(), String> {
    let mut key = HKEY::default();
    let created = unsafe { RegCreateKeyExW(HKEY_LOCAL_MACHINE, &HSTRING::from(SETTINGS_KEY), None, PCWSTR::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut key, None) };
    if created.is_err() {
        return Err(format!("Couldn't write HKLM\\{SETTINGS_KEY}"));
    }
    let value: Vec<u16> = access.as_arg().encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), value.len() * 2) };
    let written = unsafe { RegSetValueExW(key, &HSTRING::from("Access"), None, REG_SZ, Some(bytes)) };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if written.is_err() {
        return Err(format!("Couldn't write HKLM\\{SETTINGS_KEY}"));
    }
    Ok(())
}

fn apply_group(access: Access, user: Option<&str>) -> Result<(), String> {
    let group = HSTRING::from(SERVICE_GROUP);
    match access {
        Access::Everyone => {
            let code = unsafe { NetLocalGroupDel(PCWSTR::null(), &group) };
            if code != 0 && code != NERR_GROUP_NOT_FOUND && code != ERROR_NO_SUCH_ALIAS {
                return Err(format!("Couldn't remove the \"{SERVICE_GROUP}\" group (error {code})"));
            }
            Ok(())
        }
        Access::Group => {
            let user = user.ok_or("Fran didn't say which account to add")?;
            let mut comment: Vec<u16> = "Accounts allowed to turn on VPNs with Fran".encode_utf16().chain(std::iter::once(0)).collect();
            let mut name: Vec<u16> = SERVICE_GROUP.encode_utf16().chain(std::iter::once(0)).collect();
            let info = LOCALGROUP_INFO_1 { lgrpi1_name: PWSTR(name.as_mut_ptr()), lgrpi1_comment: PWSTR(comment.as_mut_ptr()) };
            let code = unsafe { NetLocalGroupAdd(PCWSTR::null(), 1, (&info as *const LOCALGROUP_INFO_1).cast(), None) };
            if code != 0 && code != NERR_GROUP_EXISTS && code != ERROR_ALIAS_EXISTS {
                return Err(format!("Couldn't make the \"{SERVICE_GROUP}\" group (error {code})"));
            }
            let mut sid = PSID::default();
            unsafe { ConvertStringSidToSidW(&HSTRING::from(user), &mut sid) }.map_err(|_| format!("{user} isn't an account"))?;
            let member = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: sid };
            let code = unsafe { NetLocalGroupAddMembers(PCWSTR::null(), &group, 0, (&member as *const LOCALGROUP_MEMBERS_INFO_0).cast(), 1) };
            unsafe {
                LocalFree(Some(HLOCAL(sid.0)));
            }
            if code != 0 && code != ERROR_MEMBER_IN_ALIAS {
                return Err(format!("Couldn't add your account to \"{SERVICE_GROUP}\" (error {code})"));
            }
            Ok(())
        }
    }
}

/// Copies this exe and wintun.dll to a folder only administrators can write, since Fran itself may be installed
/// for one user only, and anything there could then run as SYSTEM.
pub fn install(access: Access, user: Option<&str>) -> Result<(), String> {
    let manager = manager()?;
    let service = existing(&manager);
    if let Some(service) = &service {
        stop(service);
    }
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let source = exe.parent().ok_or("Fran's VPN service doesn't know its folder")?;
    let target = install_dir();
    std::fs::create_dir_all(&target).map_err(|error| format!("Couldn't make {}: {error}", target.display()))?;
    let dll = source.join("wintun.dll");
    if !dll.is_file() {
        return Err(format!("wintun.dll is missing from {}", source.display()));
    }
    if source != target {
        copy(&exe, &target.join("fran-vpn.exe"))?;
        copy(&dll, &target.join("wintun.dll"))?;
    }
    write_access(access)?;
    apply_group(access, user)?;

    let service = match service {
        Some(service) => service,
        None => {
            let command = format!("\"{}\" {}", target.join("fran-vpn.exe").display(), vpn_proto::SERVICE_ARG);
            let created = unsafe {
                CreateServiceW(
                    manager.0,
                    &HSTRING::from(SERVICE_NAME),
                    &HSTRING::from("Fran VPN"),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    &HSTRING::from(command),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                )
            };
            Handle(created.map_err(|error| format!("Couldn't add the service: {error}"))?)
        }
    };
    unsafe { StartServiceW(service.0, None) }.map_err(|error| format!("The service didn't start: {error}"))
}

pub fn uninstall() -> Result<(), String> {
    let manager = manager()?;
    if let Some(service) = existing(&manager) {
        stop(&service);
        unsafe { DeleteService(service.0) }.map_err(|error| format!("Couldn't remove the service: {error}"))?;
    }
    net::clean_leftovers();
    let dir = install_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|error| format!("Couldn't remove {}: {error}", dir.display()))?;
    }
    let _ = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, &HSTRING::from(SETTINGS_KEY)) };
    apply_group(Access::Everyone, None)
}

pub fn set_access(access: Access, user: Option<&str>) -> Result<(), String> {
    let manager = manager()?;
    if existing(&manager).is_none() {
        return Err("Fran's VPN service isn't set up".to_string());
    }
    write_access(access)?;
    apply_group(access, user)
}
