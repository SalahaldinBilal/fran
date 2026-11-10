use std::{collections::HashMap, path::PathBuf, time::Duration};

use serde::Serialize;

use super::quiet_command;

const DEFAULT_ADMIN_GROUP: &str = "OpenVPN Administrators";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// What the Interactive Service runs and who it lets use Fran's configs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCheck {
    pub exe_path: Option<String>,
    pub admin_group: String,
    /// An administrator, or a member of `admin_group` in this sign-in or in the group itself, as the service checks.
    pub allowed: bool,
}

async fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::time::timeout(Duration::from_secs(5), quiet_command(program).args(args).output()).await.ok()?.ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).to_string())
}

/// `reg query` lines look like `    exe_path    REG_SZ    C:\Program Files\OpenVPN\bin\openvpn.exe`.
fn registry_values(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let kind = ["REG_EXPAND_SZ", "REG_SZ"].into_iter().find(|kind| line.contains(&format!(" {kind} ")))?;
            let (name, data) = line.split_once(kind)?;
            Some((name.trim().to_ascii_lowercase(), data.trim().to_string()))
        })
        .collect()
}

async fn service_settings() -> HashMap<String, String> {
    run("reg", &["query", r"HKLM\SOFTWARE\OpenVPN"]).await.map(|text| registry_values(&text)).unwrap_or_default()
}

/// The OpenVPN the service starts: `exe_path`, else `bin\openvpn.exe` in the install folder.
pub async fn service_program() -> Option<PathBuf> {
    let values = service_settings().await;
    values
        .get("exe_path")
        .map(PathBuf::from)
        .or_else(|| values.get("(default)").map(|dir| PathBuf::from(dir).join("bin").join("openvpn.exe")))
}

/// `whoami /groups /fo csv /nh` lists `"name","type","sid","attributes"` per group of this sign-in.
fn in_groups(text: &str, admin_group: &str) -> bool {
    let wanted = admin_group.to_ascii_lowercase();
    text.lines().any(|line| {
        let fields: Vec<String> = line.split("\",\"").map(|field| field.trim_matches(['"', '\r', ' ']).to_string()).collect();
        let name = fields.first().map(|name| name.to_ascii_lowercase()).unwrap_or_default();
        fields.get(2).is_some_and(|sid| sid == ADMINISTRATORS_SID) || name == wanted || name.ends_with(&format!("\\{wanted}"))
    })
}

pub async fn service_check() -> ServiceCheck {
    let values = service_settings().await;
    let admin_group = values.get("ovpn_admin_group").cloned().unwrap_or_else(|| DEFAULT_ADMIN_GROUP.to_string());
    let exe_path = values
        .get("exe_path")
        .cloned()
        .or_else(|| values.get("(default)").map(|dir| PathBuf::from(dir).join("bin").join("openvpn.exe").to_string_lossy().to_string()));
    let mut allowed = run("whoami", &["/groups", "/fo", "csv", "/nh"]).await.is_some_and(|text| in_groups(&text, &admin_group));
    // Someone added to the group since signing in isn't in this sign-in's groups yet, but the service checks the group itself too.
    if !allowed {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        allowed = run("net", &["localgroup", &admin_group]).await.is_some_and(|text| is_member(&text, &user, &domain));
    }
    ServiceCheck { exe_path, admin_group, allowed }
}

/// `net localgroup <group>` lists members after a line of dashes, one per line, sometimes as `DOMAIN\user`.
fn is_member(text: &str, user: &str, domain: &str) -> bool {
    if user.is_empty() {
        return false;
    }
    let qualified = format!("{domain}\\{user}").to_ascii_lowercase();
    let user = user.to_ascii_lowercase();
    text.lines()
        .skip_while(|line| !line.trim_start().starts_with("---"))
        .skip(1)
        .map(|line| line.trim().to_ascii_lowercase())
        .any(|member| member == user || member == qualified)
}

/// The process that owns the connection from `peer_port` to Fran's `listen_port` on 127.0.0.1.
pub fn owner_pid(peer_port: u16, listen_port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};
    use windows::Win32::Networking::WinSock::AF_INET;

    fn port(raw: u32) -> u16 {
        u16::from_be((raw & 0xffff) as u16)
    }

    let mut size = 0u32;
    unsafe {
        GetExtendedTcpTable(None, &mut size, false, u32::from(AF_INET.0), TCP_TABLE_OWNER_PID_ALL, 0);
    }
    // u64s keep the table aligned. A little extra covers connections opened between the two calls.
    let mut buf = vec![0u64; (size as usize + 4096) / 8 + 1];
    size = (buf.len() * 8) as u32;
    let result = unsafe { GetExtendedTcpTable(Some(buf.as_mut_ptr().cast()), &mut size, false, u32::from(AF_INET.0), TCP_TABLE_OWNER_PID_ALL, 0) };
    if result != 0 {
        return None;
    }
    let table = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let rows: &[MIB_TCPROW_OWNER_PID] = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize) };
    rows.iter().find(|row| port(row.dwLocalPort) == peer_port && port(row.dwRemotePort) == listen_port).map(|row| row.dwOwningPid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_reg_query() {
        let text = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\OpenVPN\r\n    (Default)    REG_SZ    C:\\Program Files\\OpenVPN\\\r\n    exe_path    REG_SZ    C:\\Program Files\\OpenVPN\\bin\\openvpn.exe\r\n    ovpn_admin_group    REG_SZ    OpenVPN Administrators\r\n";
        let values = registry_values(text);
        assert_eq!(values["exe_path"], "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe");
        assert_eq!(values["ovpn_admin_group"], "OpenVPN Administrators");
        assert_eq!(values["(default)"], "C:\\Program Files\\OpenVPN\\");
    }

    #[test]
    fn reads_whoami_groups() {
        let admin = "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n\"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Group used for deny only\"\r\n";
        assert!(in_groups(admin, DEFAULT_ADMIN_GROUP));
        let member = "\"PC\\OpenVPN Administrators\",\"Alias\",\"S-1-5-21-1-2-3-1009\",\"Mandatory group\"\r\n";
        assert!(in_groups(member, DEFAULT_ADMIN_GROUP));
        assert!(!in_groups("\"BUILTIN\\Users\",\"Alias\",\"S-1-5-32-545\",\"Mandatory group\"\r\n", DEFAULT_ADMIN_GROUP));
    }

    #[test]
    fn reads_net_localgroup() {
        let text = "Alias name     OpenVPN Administrators\r\nComment\r\n\r\nMembers\r\n\r\n-------------------------------------------------------------------------------\r\nsalah\r\nWORK\\bob\r\nThe command completed successfully.\r\n";
        assert!(is_member(text, "Salah", "PC"));
        assert!(is_member(text, "bob", "WORK"));
        assert!(!is_member(text, "bob", "HOME"));
        assert!(!is_member(text, "", ""));
    }
}
