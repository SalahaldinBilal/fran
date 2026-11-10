use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        NetworkManagement::NetManagement::{LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetUserGetLocalGroups},
        Security::{
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
            GetTokenInformation, LookupAccountSidW, PSID, RevertToSelf, SID_NAME_USE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
            TokenGroups, TokenUser,
        },
        System::{
            Pipes::ImpersonateNamedPipeClient,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use super::pipe::Pipe;
use vpn_proto::{SERVICE_GROUP, frames::Access};

const SYSTEM: &str = "S-1-5-18";
/// Given to interactive and remote desktop sign-ins, never to services or network logons.
const INTERACTIVE: &str = "S-1-5-4";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

fn sid_string(sid: PSID) -> Option<String> {
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
    let value = unsafe { text.to_string() }.ok();
    unsafe {
        LocalFree(Some(HLOCAL(text.0.cast())));
    }
    value
}

fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    // u64 so the structs inside are aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), needed, &mut needed) }.ok()?;
    Some(buf)
}

/// "DOMAIN\name" for a SID, which NetUserGetLocalGroups takes.
fn account_name(sid: PSID) -> Option<String> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    unsafe { LookupAccountSidW(PCWSTR::null(), sid, Some(PWSTR(name.as_mut_ptr())), &mut name_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) }.ok()?;
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Some(if domain.is_empty() { name } else { format!("{domain}\\{name}") })
}

/// The Administrators group's name, which Windows translates.
fn administrators_name() -> Option<String> {
    let mut sid = PSID::default();
    unsafe { ConvertStringSidToSidW(&HSTRING::from(ADMINISTRATORS), &mut sid) }.ok()?;
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    let found = unsafe { LookupAccountSidW(PCWSTR::null(), sid, Some(PWSTR(name.as_mut_ptr())), &mut name_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) };
    unsafe {
        LocalFree(Some(HLOCAL(sid.0)));
    }
    found.ok()?;
    Some(String::from_utf16_lossy(&name[..name_len as usize]))
}

/// The local groups the account is in right now, read from the groups themselves rather than the sign-in.
fn local_groups(account: &str) -> Vec<String> {
    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;
    let status = unsafe { NetUserGetLocalGroups(PCWSTR::null(), &HSTRING::from(account), 0, LG_INCLUDE_INDIRECT, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total) };
    if status != 0 || buf.is_null() {
        return Vec::new();
    }
    let entries = unsafe { std::slice::from_raw_parts(buf as *const LOCALGROUP_USERS_INFO_0, read as usize) };
    let names = entries.iter().filter_map(|entry| unsafe { entry.lgrui0_name.to_string() }.ok()).collect();
    unsafe {
        let _ = NetApiBufferFree(Some(buf.cast()));
    }
    names
}

fn check_token(token: HANDLE, access: Access) -> Result<(), String> {
    let user = token_info(token, TokenUser).ok_or("Fran's VPN service couldn't tell who connected")?;
    let user_sid = unsafe { (*(user.as_ptr() as *const TOKEN_USER)).User.Sid };
    if sid_string(user_sid).as_deref() == Some(SYSTEM) {
        return Ok(());
    }
    let groups = token_info(token, TokenGroups).ok_or("Fran's VPN service couldn't read your account's groups")?;
    let groups = unsafe { &*(groups.as_ptr() as *const TOKEN_GROUPS) };
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    let interactive = entries.iter().any(|entry| {
        let usable = entry.Attributes & SE_GROUP_ENABLED != 0 && entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0;
        usable && sid_string(entry.Sid).as_deref() == Some(INTERACTIVE)
    });
    if !interactive {
        return Err("Fran's VPN service only takes accounts signed in at this computer, not services or network logons".to_string());
    }
    match access {
        Access::Everyone => Ok(()),
        Access::Group => {
            let account = account_name(user_sid).ok_or("Fran's VPN service couldn't look up your account")?;
            let groups = local_groups(&account);
            let admins = administrators_name();
            let member = groups.iter().any(|group| group.eq_ignore_ascii_case(SERVICE_GROUP) || admins.as_deref().is_some_and(|admins| group.eq_ignore_ascii_case(admins)));
            if member {
                Ok(())
            } else {
                Err(format!("Fran's VPN service only takes administrators and members of \"{SERVICE_GROUP}\". Ask an administrator to add your account."))
            }
        }
    }
}

/// Whether the account on the other end of the pipe may turn a VPN on.
pub fn check(pipe: &Pipe, access: Access) -> Result<(), String> {
    let mut token = HANDLE::default();
    unsafe { ImpersonateNamedPipeClient(pipe.handle) }.map_err(|_| "Fran's VPN service couldn't tell who connected".to_string())?;
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    let _ = unsafe { RevertToSelf() };
    opened.map_err(|_| "Fran's VPN service couldn't tell who connected".to_string())?;
    let result = check_token(token, access);
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}
