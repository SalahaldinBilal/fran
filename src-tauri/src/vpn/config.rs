use std::path::{Component, Path};

use base64ct::Encoding;
use zeroize::Zeroizing;

use super::keys;
use crate::connections::SecretSlot;
use crate::error::{AppError, AppResult};
use crate::vpn_store::{
    Compress, ImportInfo, ImportNote, RouteAll, TlsWrap, VerifyName, VerifyNameKind, VpnAuth, VpnChallenge, VpnProfile, VpnProto,
    VpnRemote,
};

const MAX_FILE: u64 = 1024 * 1024;
const MAX_REMOTES: usize = 32;
const MIN_TLS: &str = "1.2";

/// Data channel ciphers OpenVPN 3 runs with its legacy and non-preferred algorithms off.
const CURRENT_CIPHERS: &[&str] = &["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"];

const DIGESTS: &[&str] = &["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"];

const IGNORED: &[&str] = &[
    "nobind", "persist-tun", "persist-key", "verb", "mute", "mute-replay-warnings", "resolv-retry", "auth-nocache", "auth-retry",
    "float", "explicit-exit-notify", "keepalive", "ping", "ping-restart", "ping-exit", "ping-timer-rem", "connect-retry",
    "connect-retry-max", "connect-timeout", "server-poll-timeout", "hand-window", "tran-window", "mssfix", "tun-mtu", "link-mtu",
    "sndbuf", "rcvbuf", "fast-io", "route-delay", "route-method", "remote-cert-ku", "remote-cert-eku", "tls-cipher",
    "tls-ciphersuites", "tls-groups", "ecdh-curve", "push-peer-info", "allow-recursive-routing", "pull-filter", "route",
    "route-ipv6", "ifconfig-nowarn", "register-dns", "block-outside-dns", "machine-readable-output", "windows-driver",
    "dev-node", "ignore-unknown-option", "tls-timeout", "reneg-bytes", "reneg-pkts", "inactive", "dhcp-option", "lport", "bind",
    "txqueuelen", "dns", "setenv-safe", "echo", "allow-pull-fqdn", "route-metric", "tun-mtu-extra", "replay-window", "mute",
    "auth-token-user", "single-session", "tcp-nodelay", "passtos", "topology", "x509-track", "msg-channel", "data-ciphers-fallback-ignored",
];

const DROPPED_SCRIPTS: &[&str] = &[
    "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "client-connect", "client-disconnect", "learn-address",
    "auth-user-pass-verify", "up-delay", "up-restart", "down-pre", "dns-updown",
];

const DROPPED_LOCAL: &[&str] = &[
    "plugin", "management", "management-client", "management-hold", "management-query-passwords", "management-forget-disconnect",
    "management-signal", "management-up-down", "management-client-auth", "management-external-key", "management-external-cert",
    "log", "log-append", "status", "status-version", "daemon", "cd", "chroot", "user", "group", "writepid", "config", "tmp-dir",
    "askpass", "http-proxy-user-pass", "auth-user-pass-optional", "iproute", "syslog", "suppress-timestamps",
];

/// Name, how many arguments are passed on (None for all), and why an own tunnel can't run it.
const SYSTEM_ONLY: &[(&str, Option<usize>, &str)] = &[
    ("fragment", Some(1), "fragments packets, which OpenVPN 3 doesn't do"),
    ("http-proxy", Some(2), "reaches the server through an HTTP proxy"),
    ("socks-proxy", Some(2), "reaches the server through a SOCKS proxy"),
    ("providers", None, "loads OpenSSL providers"),
];

/// Static key mode would need the key in a file on disk, and OpenVPN 2.7 removed it.
const DROPPED_KEYS: &[(&str, &str)] = &[(
    "secret",
    "uses a static key instead of TLS. It would need the key in a file on disk, and OpenVPN 2.7 removed this mode. Ask for a TLS profile.",
)];

/// Asked for during import when the profile keeps its key in a PKCS#12 file. Never saved.
pub const PKCS12_SLOT: &str = "vpn:import:pkcs12";

pub fn pkcs12_slot() -> SecretSlot {
    SecretSlot::one_time(PKCS12_SLOT.to_string(), "Password of the PKCS#12 file".to_string())
}

pub struct Parsed {
    pub profile: VpnProfile,
    pub private_key: Option<Zeroizing<String>>,
    pub tls_key: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
}

struct Reader<'a> {
    dir: Option<&'a Path>,
    profile: VpnProfile,
    info: ImportInfo,
    private_key: Option<Zeroizing<String>>,
    tls_key: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    pkcs12: Option<Zeroizing<Vec<u8>>>,
    tls_auth_direction: Option<u8>,
    default_port: u16,
    default_proto: VpnProto,
    ca_seen: bool,
    no_client_cert: bool,
    wants_password: bool,
    pending_proto: Vec<usize>,
}

/// OpenVPN's tokenizer: whitespace splits, quotes group, a backslash escapes inside double quotes.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut chars = line.chars();
    while let Some(character) = chars.next() {
        match (quote, character) {
            (Some('"'), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(open), close) if open == close => quote = None,
            (Some(_), other) => current.push(other),
            (None, '"' | '\'') => {
                quote = Some(character);
                started = true;
            }
            (None, other) if other.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, '#' | ';') if !started => break,
            (None, other) => {
                current.push(other);
                started = true;
            }
        }
    }
    if started {
        out.push(current);
    }
    out
}

fn note(option: &str, reason: &str) -> ImportNote {
    ImportNote { option: option.to_string(), reason: reason.to_string() }
}

fn proto(value: &str) -> Option<VpnProto> {
    match value.to_ascii_lowercase().as_str() {
        "udp" | "udp4" | "udp6" => Some(VpnProto::Udp),
        "tcp" | "tcp4" | "tcp6" | "tcp-client" | "tcp4-client" | "tcp6-client" => Some(VpnProto::Tcp),
        _ => None,
    }
}

/// Only files in the profile's own folder or below, so a crafted profile can't read anything else.
fn read_beside(dir: Option<&Path>, name: &str) -> AppResult<String> {
    let dir = dir.ok_or_else(|| AppError::general(format!("{name} is a separate file. Paste it in the editor instead.")))?;
    let relative = Path::new(name);
    if relative.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(AppError::general(format!("{name} is outside the profile's folder, so Fran won't read it")));
    }
    let path = dir.join(relative);
    let size = std::fs::metadata(&path).map_err(|error| AppError::general(format!("Couldn't read {name}: {error}")))?.len();
    if size > MAX_FILE {
        return Err(AppError::general(format!("{name} is too large")));
    }
    std::fs::read_to_string(&path).map_err(|error| AppError::general(format!("Couldn't read {name}: {error}")))
}

fn read_beside_bytes(dir: Option<&Path>, name: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    let dir = dir.ok_or_else(|| AppError::general(format!("{name} is a separate file. Import the .ovpn from its folder.")))?;
    let relative = Path::new(name);
    if relative.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(AppError::general(format!("{name} is outside the profile's folder, so Fran won't read it")));
    }
    let path = dir.join(relative);
    let size = std::fs::metadata(&path).map_err(|error| AppError::general(format!("Couldn't read {name}: {error}")))?.len();
    if size > MAX_FILE {
        return Err(AppError::general(format!("{name} is too large")));
    }
    std::fs::read(&path).map(Zeroizing::new).map_err(|error| AppError::general(format!("Couldn't read {name}: {error}")))
}

/// Plain words only, so an argument passed on to the installed OpenVPN can't carry anything else.
fn safe_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && value.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ':'))
}

/// Free text for options written in quotes, like a certificate store selector. Line breaks would start another option.
fn safe_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

/// Options whose one argument is free text, written in quotes.
const QUOTED_SYSTEM_OPTIONS: &[&str] = &["cryptoapicert", "pkcs11-id"];

impl Reader<'_> {
    /// Kept for system mode, or dropped when it has no arguments or one of them isn't a plain word.
    fn system_only(&mut self, option: Vec<String>, reason: &str) {
        let name = option[0].clone();
        if option.len() > 1 && option[1..].iter().all(|arg| safe_token(arg)) {
            self.profile.system_options.push(option);
            self.info.system_only.push(note(&name, reason));
        } else {
            self.info.dropped.push(note(&name, "has arguments Fran won't pass on to OpenVPN"));
        }
    }

    fn used(&mut self, option: &str) {
        if !self.info.used.iter().any(|seen| seen == option) {
            self.info.used.push(option.to_string());
        }
    }

    /// The user name on the first line, the password on the second, as OpenVPN reads them.
    fn login(&mut self, text: &str) {
        let mut lines = text.lines();
        let user = lines.next().unwrap_or_default().trim();
        if user.chars().any(char::is_control) {
            self.info.dropped.push(note("auth-user-pass", "has a user name Fran can't use"));
            return;
        }
        if !user.is_empty() {
            self.profile.user = user.to_string();
        }
        if let Some(password) = lines.next().filter(|password| !password.is_empty()) {
            self.password = Some(Zeroizing::new(password.to_string()));
        }
    }

    fn content(&self, args: &[String], inline: Option<&str>) -> AppResult<Option<String>> {
        match (inline, args.first().map(String::as_str)) {
            (Some(text), _) => Ok(Some(text.to_string())),
            (None, Some("[inline]")) | (None, None) => Ok(None),
            (None, Some(name)) => read_beside(self.dir, name).map(Some),
        }
    }

    fn option(&mut self, name: &str, args: &[String], inline: Option<&str>) -> AppResult<()> {
        let first = args.first().map(String::as_str);
        match name {
            "client" | "tls-client" | "pull" => self.used(name),
            "dev" | "dev-type" => match first {
                Some(value) if value.starts_with("tun") => self.used(name),
                Some(value) if value.starts_with("tap") => {
                    self.system_only(vec!["dev".to_string(), "tap".to_string()], "uses a TAP adapter, which OpenVPN 3 doesn't have");
                }
                _ => self.used(name),
            },
            "remote" => {
                let host = first.ok_or_else(|| AppError::general("A remote line has no server"))?;
                if self.profile.remotes.len() >= MAX_REMOTES {
                    return Err(AppError::general("The profile lists too many servers"));
                }
                let port = match args.get(1) {
                    Some(port) => Some(port.parse().map_err(|_| AppError::general(format!("Bad port on remote {host}")))?),
                    None => None,
                };
                let remote_proto = args.get(2).and_then(|value| proto(value));
                // A missing port or proto comes from `port` and `proto` anywhere in the file, filled in at the end.
                if remote_proto.is_none() {
                    self.pending_proto.push(self.profile.remotes.len());
                }
                self.profile.remotes.push(VpnRemote { host: host.to_string(), port: port.unwrap_or(0), proto: remote_proto.unwrap_or_default() });
                self.used(name);
            }
            "port" | "rport" => {
                self.default_port = first.and_then(|value| value.parse().ok()).ok_or_else(|| AppError::general("Bad port"))?;
                self.used(name);
            }
            "proto" => {
                self.default_proto = first.and_then(proto).ok_or_else(|| AppError::general("Unknown proto"))?;
                self.used(name);
            }
            "remote-random" => {
                self.profile.remote_random = true;
                self.used(name);
            }
            "ca" => {
                if let Some(text) = self.content(args, inline)? {
                    self.profile.ca = keys::clean_certificates(&text, "CA")?;
                    self.ca_seen = true;
                    self.used(name);
                }
            }
            "cert" => {
                if let Some(text) = self.content(args, inline)? {
                    self.profile.cert = keys::clean_certificates(&text, "client certificate")?;
                    self.used(name);
                }
            }
            "key" => {
                if let Some(text) = self.content(args, inline)? {
                    match keys::read_client_key(&text) {
                        Ok((key, pem)) => {
                            self.profile.key_kind = Some(key.kind());
                            self.private_key = Some(pem);
                            self.used(name);
                        }
                        Err(error) => self.info.dropped.push(note(name, &error.message)),
                    }
                }
            }
            "extra-certs" => {
                if let Some(text) = self.content(args, inline)? {
                    let chain = keys::clean_certificates(&text, "certificate chain")?;
                    self.profile.cert.push_str(&chain);
                    self.used(name);
                }
            }
            "tls-auth" | "tls-crypt" | "tls-crypt-v2" => {
                let v2 = name == "tls-crypt-v2";
                let (text, rest) = match inline {
                    Some(text) => (Some(text.to_string()), args),
                    None => (self.content(args, None)?, args.get(1..).unwrap_or_default()),
                };
                if let Some(text) = text {
                    self.tls_key = Some(keys::clean_tls_key(&text, v2)?);
                }
                self.profile.tls_wrap = match name {
                    "tls-auth" => {
                        if let Some(direction) = rest.first().and_then(|value| value.parse().ok()) {
                            self.tls_auth_direction = Some(direction);
                        }
                        TlsWrap::Auth { direction: None }
                    }
                    "tls-crypt" => TlsWrap::Crypt,
                    _ => TlsWrap::CryptV2,
                };
                self.used(name);
            }
            "key-direction" => {
                self.tls_auth_direction = first.and_then(|value| value.parse().ok()).filter(|value: &u8| *value <= 1);
                self.used(name);
            }
            "auth-user-pass" => {
                self.wants_password = true;
                match self.content(args, inline) {
                    Ok(Some(text)) => self.login(&Zeroizing::new(text)),
                    Ok(None) => {}
                    Err(error) => self.info.dropped.push(note(name, &format!("{} Fran asks for the login instead.", error.message))),
                }
                self.used(name);
            }
            "static-challenge" => {
                let text = first.ok_or_else(|| AppError::general("static-challenge has no text"))?.to_string();
                let echo = args.get(1).is_some_and(|value| value == "1");
                self.profile.challenge = VpnChallenge::Static { echo, text };
                self.used(name);
            }
            "remote-cert-tls" | "ns-cert-type" => {
                if first == Some("server") {
                    self.profile.require_server_cert = true;
                    self.used(name);
                } else {
                    self.info.ignored.push(note(name, "only checking for a server certificate is supported"));
                }
            }
            "verify-x509-name" => {
                let value = first.ok_or_else(|| AppError::general("verify-x509-name has no name"))?;
                let kind = match args.get(1).map(String::as_str) {
                    None | Some("subject") => VerifyNameKind::Subject,
                    Some("name") => VerifyNameKind::Name,
                    Some("name-prefix") => VerifyNameKind::NamePrefix,
                    Some(other) => return Err(AppError::general(format!("Unknown verify-x509-name type {other}"))),
                };
                self.profile.verify_name = Some(VerifyName { name: value.to_string(), kind });
                self.used(name);
            }
            "peer-fingerprint" => {
                let text = inline.map(str::to_string).or_else(|| first.map(str::to_string)).unwrap_or_default();
                for fingerprint in text.split(['\n', ';']).map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
                    self.profile.peer_fingerprints.push(clean_fingerprint(fingerprint)?);
                }
                self.ca_seen |= !self.profile.peer_fingerprints.is_empty();
                self.used(name);
            }
            "data-ciphers" | "ncp-ciphers" => {
                let list: Vec<String> = first.unwrap_or_default().split(':').map(|value| value.trim().to_ascii_uppercase()).filter(|value| !value.is_empty()).collect();
                let (current, legacy): (Vec<String>, Vec<String>) = list.into_iter().partition(|cipher| is_current_cipher(cipher));
                if !legacy.is_empty() {
                    self.info.dropped.push(note(name, &format!("{} are legacy ciphers, left out of an own tunnel", legacy.join(", "))));
                }
                if current.is_empty() {
                    self.system_only(vec!["data-ciphers".to_string(), first.unwrap_or_default().to_string()], "only lists legacy ciphers");
                }
                self.profile.ciphers = current;
                self.used(name);
            }
            "cipher" | "data-ciphers-fallback" => {
                let cipher = first.unwrap_or_default().to_ascii_uppercase();
                if is_current_cipher(&cipher) {
                    self.profile.fallback_cipher = Some(cipher);
                    self.used(name);
                } else {
                    // Kept for the installed OpenVPN only, as the cipher for servers too old to agree on one.
                    if safe_token(&cipher) {
                        self.profile.system_options.push(vec!["data-ciphers-fallback".to_string(), cipher.clone()]);
                    }
                    self.info.dropped.push(note(
                        name,
                        &format!("{cipher} is a legacy cipher, left out of Fran's own tunnel. Servers from OpenVPN 2.4 on agree on a current one. It's still used while the VPN is on for the computer."),
                    ));
                }
            }
            "auth" => {
                let digest = first.unwrap_or_default().to_ascii_uppercase();
                if DIGESTS.contains(&digest.as_str()) {
                    self.profile.auth_digest = Some(digest);
                    self.used(name);
                } else {
                    self.system_only(vec!["auth".to_string(), digest.clone()], &format!("uses the {digest} digest"));
                }
            }
            "tls-version-min" => {
                if let Some(version) = first.filter(|version| *version == "1.3") {
                    self.profile.tls_version_min = Some(version.to_string());
                }
                self.used(name);
            }
            "tls-version-max" => {
                if let Some(version) = first.filter(|version| matches!(*version, "1.0" | "1.1")) {
                    self.system_only(vec!["tls-version-max".to_string(), version.to_string()], "caps TLS below 1.2");
                } else {
                    self.info.ignored.push(note(name, "TLS 1.2 or newer is always used"));
                }
            }
            "reneg-sec" => {
                self.profile.reneg_sec = first.and_then(|value| value.parse().ok());
                self.used(name);
            }
            "comp-lzo" => match first {
                Some("no") => {
                    self.profile.compress = Compress::LzoNo;
                    self.used(name);
                }
                _ => self.info.dropped.push(note(name, "turns on compression, which Fran refuses (VORACLE)")),
            },
            "compress" => match first {
                None | Some("stub") => {
                    self.profile.compress = Compress::Stub;
                    self.used(name);
                }
                Some("stub-v2") => {
                    self.profile.compress = Compress::StubV2;
                    self.used(name);
                }
                Some(_) => self.info.dropped.push(note(name, "turns on compression, which Fran refuses (VORACLE)")),
            },
            "allow-compression" => self.info.ignored.push(note(name, "compression is always refused")),
            "redirect-gateway" | "redirect-private" => {
                self.profile.route_all = RouteAll::FollowServer;
                self.used(name);
            }
            "route-nopull" => {
                self.profile.route_all = RouteAll::VpnNetworksOnly;
                self.used(name);
            }
            "setenv" => match (first, args.get(1).map(String::as_str)) {
                (Some("FRIENDLY_NAME"), Some(value)) => {
                    self.profile.label = value.to_string();
                    self.used(name);
                }
                (Some("CLIENT_CERT"), Some("0")) => {
                    self.no_client_cert = true;
                    self.used(name);
                }
                _ => self.info.ignored.push(note(name, "not used by Fran")),
            },
            "script-security" => {
                if first.and_then(|value| value.parse::<u8>().ok()).is_some_and(|level| level > 1) {
                    self.info.dropped.push(note(name, "would let scripts run. Fran never runs scripts."));
                } else {
                    self.info.ignored.push(note(name, "scripts never run"));
                }
            }
            _ if DROPPED_SCRIPTS.contains(&name) => self.info.dropped.push(note(name, "runs a script. Fran never runs scripts.")),
            _ if DROPPED_LOCAL.contains(&name) => self.info.dropped.push(note(name, "is about this computer, Fran sets it itself")),
            "pkcs12" => {
                let bytes = match inline {
                    Some(text) => {
                        let compact: String = text.chars().filter(|character| !character.is_whitespace()).collect();
                        Some(Zeroizing::new(
                            base64ct::Base64::decode_vec(&compact).map_err(|_| AppError::general("The <pkcs12> block isn't valid base64"))?,
                        ))
                    }
                    None => match first {
                        Some(file) if file != "[inline]" => Some(read_beside_bytes(self.dir, file)?),
                        _ => None,
                    },
                };
                if let Some(bytes) = bytes {
                    self.pkcs12 = Some(bytes);
                    self.used(name);
                }
            }
            "cryptoapicert" | "pkcs11-id" => match first.filter(|value| safe_text(value)) {
                Some(value) => {
                    self.profile.system_options.push(vec![name.to_string(), value.to_string()]);
                    let reason = if name == "cryptoapicert" {
                        "uses a key from the Windows certificate store, which only OpenVPN on Windows reads"
                    } else {
                        "uses a smartcard. Choose its library in the VPN's settings."
                    };
                    self.info.system_only.push(note(name, reason));
                }
                None => self.info.dropped.push(note(name, "has an argument Fran won't pass on to OpenVPN")),
            },
            "pkcs11-providers" => self.info.dropped.push(note(
                name,
                "names a smartcard library. Fran never takes that from a file, since it runs inside OpenVPN as admin. Choose it in the VPN's settings.",
            )),
            _ if name.starts_with("pkcs11") => self.info.ignored.push(note(name, "not used by Fran")),
            _ => match (SYSTEM_ONLY.iter().find(|(option, ..)| *option == name), DROPPED_KEYS.iter().find(|(option, _)| *option == name)) {
                (Some((_, keep, reason)), _) => {
                    let mut option = vec![name.to_string()];
                    option.extend(args.iter().take(keep.unwrap_or(args.len())).cloned());
                    self.system_only(option, reason);
                }
                (None, Some((_, reason))) => self.info.dropped.push(note(name, reason)),
                (None, None) if IGNORED.contains(&name) => self.info.ignored.push(note(name, "not needed")),
                (None, None) => self.info.ignored.push(note(name, "not used by Fran")),
            },
        }
        Ok(())
    }
}

pub fn is_current_cipher(cipher: &str) -> bool {
    CURRENT_CIPHERS.contains(&cipher)
}

pub fn clean_fingerprint(value: &str) -> AppResult<String> {
    let hex: String = value.chars().filter(|character| *character != ':').collect();
    if hex.len() != 64 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(AppError::general(format!("{value} isn't a SHA-256 fingerprint")));
    }
    let upper = hex.to_ascii_uppercase();
    Ok(upper.as_bytes().chunks(2).map(|pair| std::str::from_utf8(pair).unwrap_or_default()).collect::<Vec<_>>().join(":"))
}

/// Reads an .ovpn. Files it names are only read from its own folder, and only certificates and keys are taken from them.
pub fn parse(text: &str, file_name: &str, dir: Option<&Path>) -> AppResult<Parsed> {
    parse_with(text, file_name, dir, None)
}

/// `pkcs12_password` opens a PKCS#12 file the profile keeps its key and certificate in. Without one, such a
/// profile asks for it with `secretsRequired`.
pub fn parse_with(text: &str, file_name: &str, dir: Option<&Path>, pkcs12_password: Option<&str>) -> AppResult<Parsed> {
    if text.len() as u64 > MAX_FILE {
        return Err(AppError::general("That file is too large to be an OpenVPN profile"));
    }
    let mut reader = Reader {
        dir,
        profile: VpnProfile::default(),
        info: ImportInfo { file_name: file_name.to_string(), ..Default::default() },
        private_key: None,
        tls_key: None,
        password: None,
        pkcs12: None,
        tls_auth_direction: None,
        default_port: 1194,
        default_proto: VpnProto::Udp,
        ca_seen: false,
        no_client_cert: false,
        wants_password: false,
        pending_proto: Vec::new(),
    };
    reader.profile.require_server_cert = false;

    let mut lines = text.lines();
    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|rest| rest.strip_suffix('>')).filter(|tag| !tag.starts_with('/')) {
            let close = format!("</{tag}>");
            let mut body = Zeroizing::new(String::new());
            let mut closed = false;
            for inner in lines.by_ref() {
                if inner.trim() == close {
                    closed = true;
                    break;
                }
                body.push_str(inner);
                body.push('\n');
            }
            if !closed {
                return Err(AppError::general(format!("<{tag}> isn't closed")));
            }
            reader.option(tag, &[], Some(&body))?;
            continue;
        }
        let parts = tokens(line);
        let Some((name, args)) = parts.split_first() else {
            continue;
        };
        let name = name.trim_start_matches("--").to_ascii_lowercase();
        reader.option(&name, args, None)?;
    }

    if let Some(bytes) = reader.pkcs12.take() {
        let password = pkcs12_password.ok_or_else(|| AppError::secrets_required(vec![pkcs12_slot()]))?;
        let bundle = keys::read_pkcs12(&bytes, password)?;
        reader.profile.key_kind = Some(bundle.key.kind());
        reader.private_key = Some(bundle.pem);
        // Like OpenVPN, the bundle's other certificates are the CA when the profile names none.
        if reader.profile.ca.is_empty() && !bundle.others.is_empty() {
            reader.profile.ca = bundle.others;
            reader.ca_seen = true;
            reader.profile.cert = format!("{}{}", bundle.leaf, reader.profile.cert);
        } else {
            reader.profile.cert = format!("{}{}{}", bundle.leaf, bundle.others, reader.profile.cert);
        }
    }

    for index in std::mem::take(&mut reader.pending_proto) {
        reader.profile.remotes[index].proto = reader.default_proto;
    }
    for remote in &mut reader.profile.remotes {
        if remote.port == 0 {
            remote.port = reader.default_port;
        }
    }
    if let TlsWrap::Auth { direction } = &mut reader.profile.tls_wrap {
        *direction = reader.tls_auth_direction;
    }
    if reader.profile.tls_wrap.needs_key() && reader.tls_key.is_none() {
        let tag = reader.profile.tls_wrap.tag().unwrap_or_default();
        return Err(AppError::general(format!("The profile uses {tag} but its key isn't in the file")));
    }
    if reader.profile.remotes.is_empty() {
        return Err(AppError::general("The profile names no server"));
    }
    if !reader.ca_seen {
        return Err(AppError::general(
            "The profile has no CA and no peer fingerprint, so there's nothing to check the server against",
        ));
    }

    let has_cert = !reader.profile.cert.is_empty() && !reader.no_client_cert;
    reader.profile.auth = match (has_cert, reader.wants_password) {
        (true, true) => VpnAuth::CertAndUserPass,
        (false, true) => VpnAuth::UserPass,
        _ => VpnAuth::Cert,
    };
    if reader.profile.label.trim().is_empty() {
        reader.profile.label = Path::new(file_name).file_stem().map(|stem| stem.to_string_lossy().to_string()).unwrap_or_else(|| "VPN".to_string());
    }
    reader.info.imported_at = crate::ssh_store::now_millis();
    reader.profile.imported = Some(reader.info);
    reader.profile.needs_system = system_reasons(&reader.profile);
    Ok(Parsed { profile: reader.profile, private_key: reader.private_key, tls_key: reader.tls_key, password: reader.password })
}

/// Everything that keeps an own tunnel from running this profile.
pub fn system_reasons(profile: &VpnProfile) -> Vec<String> {
    profile.imported.iter().flat_map(|info| info.system_only.iter()).map(|note| format!("{} {}", note.option, note.reason)).collect()
}

fn plain(value: &str, what: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(|character| character.is_whitespace() || character.is_control() || matches!(character, '"' | '\'' | '\\' | '<' | '>' | '#' | ';')) {
        return Err(AppError::general(format!("The {what} \"{value}\" can't be used")));
    }
    Ok(value.to_string())
}

fn quoted(value: &str, what: &str) -> AppResult<String> {
    if value.chars().any(char::is_control) {
        return Err(AppError::general(format!("The {what} has a line break or control character")));
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

fn block(out: &mut String, tag: &str, body: &str) {
    out.push_str(&format!("<{tag}>\n{}", body));
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("</{tag}>\n"));
}

/// The profile OpenVPN 3 gets for an own tunnel. Built from the saved fields only, never from the original file.
/// The client certificate goes to OpenVPN 3 separately, and the key never does.
pub fn core_profile(profile: &VpnProfile, tls_key: Option<&str>) -> AppResult<String> {
    write_profile(profile, tls_key, false)
}

fn system_option<'a>(profile: &'a VpnProfile, name: &str) -> Option<&'a [String]> {
    profile.system_options.iter().find(|option| option.first().is_some_and(|first| first == name)).map(|option| &option[1..])
}

/// The key is in the Windows certificate store or on a smartcard, so OpenVPN signs itself and Fran has no key.
pub fn key_outside_fran(profile: &VpnProfile) -> bool {
    system_option(profile, "cryptoapicert").is_some() || system_option(profile, "pkcs11-id").is_some()
}

/// The config the installed OpenVPN gets. Same fields as an own tunnel, plus the options only it runs.
/// The key stays in Fran (`management-external-key`), and logins come over the management connection.
pub fn system_profile(profile: &VpnProfile, tls_key: Option<&str>) -> AppResult<String> {
    let mut out = write_profile(profile, tls_key, true)?;
    // `dev` is already written. vpn.json can be edited by hand, so names and arguments are checked again.
    for option in &profile.system_options {
        let Some((name, args)) = option.split_first() else { continue };
        if QUOTED_SYSTEM_OPTIONS.contains(&name.as_str()) {
            if let [value] = args {
                if safe_text(value) {
                    out.push_str(&format!("{name} {}\n", quoted(value, name)?));
                }
            }
            continue;
        }
        let passed = SYSTEM_ONLY.iter().any(|(known, ..)| known == name)
            || matches!(name.as_str(), "data-ciphers" | "data-ciphers-fallback" | "auth" | "tls-version-max");
        if passed && !args.is_empty() && args.iter().all(|arg| safe_token(arg)) {
            out.push_str(&format!("{name} {}\n", args.join(" ")));
        }
    }
    if system_option(profile, "pkcs11-id").is_some() {
        let provider = profile
            .pkcs11_provider
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| AppError::general(format!("Choose the smartcard library in the settings of VPN {}", profile.label)))?;
        out.push_str(&format!("pkcs11-providers {}\n", quoted(provider, "smartcard library")?));
    }
    if profile.route_all == RouteAll::VpnNetworksOnly {
        out.push_str("pull-filter ignore \"redirect-gateway\"\npull-filter ignore \"redirect-private\"\n");
    }
    if !profile.use_vpn_dns {
        out.push_str("pull-filter ignore \"dhcp-option DNS\"\npull-filter ignore \"dhcp-option DOMAIN\"\npull-filter ignore \"dns \"\n");
    }
    out.push_str("auth-nocache\nallow-compression no\nscript-security 1\n");
    if profile.auth.uses_cert() && !key_outside_fran(profile) {
        let cert = keys::clean_certificates(&profile.cert, "client certificate")
            .map_err(|_| AppError::general(format!("VPN {} has no client certificate", profile.label)))?;
        out.push_str("management-external-key pkcs1 pss digest\n");
        block(&mut out, "cert", &cert);
    }
    Ok(out)
}

fn write_profile(profile: &VpnProfile, tls_key: Option<&str>, system: bool) -> AppResult<String> {
    let dev = match system_option(profile, "dev").filter(|_| system) {
        Some(_) => "tap",
        None => "tun",
    };
    let mut out = format!("client\ndev {dev}\nnobind\n");
    if profile.remotes.is_empty() {
        return Err(AppError::general(format!("{} has no server", profile.label)));
    }
    for remote in &profile.remotes {
        if remote.port == 0 {
            return Err(AppError::general(format!("{} has no port", remote.host)));
        }
        let proto = match remote.proto {
            VpnProto::Udp => "udp",
            VpnProto::Tcp => "tcp",
        };
        out.push_str(&format!("remote {} {} {proto}\n", plain(&remote.host, "server")?, remote.port));
    }
    if profile.remote_random {
        out.push_str("remote-random\n");
    }
    if profile.require_server_cert {
        out.push_str("remote-cert-tls server\n");
    }
    if let Some(verify) = &profile.verify_name {
        let kind = match verify.kind {
            VerifyNameKind::Subject => "subject",
            VerifyNameKind::Name => "name",
            VerifyNameKind::NamePrefix => "name-prefix",
        };
        out.push_str(&format!("verify-x509-name {} {kind}\n", quoted(&verify.name, "name to match")?));
    }
    let raw = |name: &str| system && system_option(profile, name).is_some();
    if !raw("tls-version-max") {
        out.push_str(&format!("tls-version-min {}\n", profile.tls_version_min.as_deref().filter(|version| *version == "1.3").unwrap_or(MIN_TLS)));
    }
    let ciphers: Vec<&str> = profile.ciphers.iter().map(String::as_str).filter(|cipher| is_current_cipher(cipher)).collect();
    if !ciphers.is_empty() && !raw("data-ciphers") {
        out.push_str(&format!("data-ciphers {}\n", ciphers.join(":")));
    }
    if let Some(cipher) = profile.fallback_cipher.as_deref().filter(|cipher| is_current_cipher(cipher)) {
        out.push_str(&format!("cipher {cipher}\n"));
    }
    if let Some(digest) = profile.auth_digest.as_deref().filter(|digest| DIGESTS.contains(digest) && !raw("auth")) {
        out.push_str(&format!("auth {digest}\n"));
    }
    if let Some(seconds) = profile.reneg_sec {
        out.push_str(&format!("reneg-sec {seconds}\n"));
    }
    match profile.compress {
        Compress::Off => {}
        Compress::LzoNo => out.push_str("comp-lzo no\n"),
        Compress::Stub => out.push_str("compress stub\n"),
        Compress::StubV2 => out.push_str("compress stub-v2\n"),
    }
    if profile.auth.uses_password() {
        out.push_str("auth-user-pass\n");
    }
    if let VpnChallenge::Static { echo, text } = &profile.challenge {
        out.push_str(&format!("static-challenge {} {}\n", quoted(text, "challenge text")?, u8::from(*echo)));
    }
    if !profile.auth.uses_cert() && !system {
        out.push_str("setenv CLIENT_CERT 0\n");
    }

    let ca = if profile.ca.trim().is_empty() { String::new() } else { keys::clean_certificates(&profile.ca, "CA")? };
    if ca.is_empty() && profile.peer_fingerprints.is_empty() {
        return Err(AppError::general(format!("{} has no CA or fingerprint to check the server against", profile.label)));
    }
    if !ca.is_empty() {
        block(&mut out, "ca", &ca);
    }
    if !profile.peer_fingerprints.is_empty() {
        let lines: AppResult<Vec<String>> = profile.peer_fingerprints.iter().map(|value| clean_fingerprint(value)).collect();
        block(&mut out, "peer-fingerprint", &lines?.join("\n"));
    }
    if let Some(tag) = profile.tls_wrap.tag() {
        let key = tls_key.ok_or_else(|| AppError::general(format!("The {tag} key of {} is missing from the vault", profile.label)))?;
        let key = keys::clean_tls_key(key, matches!(profile.tls_wrap, TlsWrap::CryptV2))?;
        if let TlsWrap::Auth { direction: Some(direction) } = profile.tls_wrap {
            out.push_str(&format!("key-direction {direction}\n"));
        }
        block(&mut out, tag, &key);
    }
    Ok(out)
}

/// A standard .ovpn with the certificate and keys inline, for another computer or another client.
/// Written from the saved fields like `core_profile`, so it never carries scripts either.
pub fn portable_profile(profile: &VpnProfile, tls_key: Option<&str>, key_pem: Option<&str>) -> AppResult<String> {
    let mut out = format!("# {}, exported from Fran\n", profile.label.replace(['\r', '\n'], " "));
    out.push_str(&core_profile(profile, tls_key)?);
    if profile.auth.uses_cert() {
        let cert = keys::clean_certificates(&profile.cert, "client certificate")?;
        block(&mut out, "cert", &cert);
        let key = key_pem.ok_or_else(|| AppError::general(format!("{} has no client key", profile.label)))?;
        let (_, clean) = keys::read_client_key(key)?;
        block(&mut out, "key", &clean);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATIC_KEY: &str = "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef0123456789abcdef\n-----END OpenVPN Static key V1-----\n";

    fn ca() -> String {
        keys::test_certificate("Test CA")
    }

    fn profile(body: &str) -> String {
        format!("{body}\n<ca>\n{}</ca>\n", ca())
    }

    #[test]
    fn tokenizer_handles_quotes() {
        assert_eq!(tokens(r#"static-challenge "Enter your \"code\"" 1"#), ["static-challenge", "Enter your \"code\"", "1"]);
        assert_eq!(tokens("remote vpn.example 1194 # comment"), ["remote", "vpn.example", "1194"]);
        assert_eq!(tokens("verify-x509-name 'C=US, CN=vpn' subject"), ["verify-x509-name", "C=US, CN=vpn", "subject"]);
    }

    #[test]
    fn access_server_style_profile() {
        let text = profile(&format!(
            "setenv FRIENDLY_NAME \"Office\"\nclient\ndev tun\nproto tcp\nremote vpn.example.com 443\nremote 10.0.0.1 1194 udp\nauth-user-pass\nstatic-challenge \"Code\" 1\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nsetenv CLIENT_CERT 0\n<tls-crypt>\n{STATIC_KEY}</tls-crypt>"
        ));
        let parsed = parse(&text, "office.ovpn", None).unwrap();
        let profile = &parsed.profile;
        assert_eq!(profile.label, "Office");
        assert_eq!(profile.remotes[0], VpnRemote { host: "vpn.example.com".to_string(), port: 443, proto: VpnProto::Tcp });
        assert_eq!(profile.remotes[1].proto, VpnProto::Udp);
        assert_eq!(profile.auth, VpnAuth::UserPass);
        assert_eq!(profile.challenge, VpnChallenge::Static { echo: true, text: "Code".to_string() });
        assert_eq!(profile.tls_wrap, TlsWrap::Crypt);
        assert!(profile.require_server_cert);
        assert!(profile.needs_system.is_empty(), "{:?}", profile.needs_system);
        assert!(parsed.tls_key.is_some());
    }

    #[test]
    fn scripts_and_compression_are_dropped_and_never_written() {
        let text = profile(&format!(
            "client\nremote vpn.example 1194\nscript-security 2\nup /etc/openvpn/up.sh\ndown \"/bin/sh -c 'rm -rf ~'\"\nplugin /usr/lib/evil.so\nmanagement 0.0.0.0 7505\nlog /tmp/x\ncomp-lzo yes\ncompress lz4\ncd /\n<tls-auth>\n{STATIC_KEY}</tls-auth>\nkey-direction 1"
        ));
        let parsed = parse(&text, "evil.ovpn", None).unwrap();
        let dropped: Vec<&str> = parsed.profile.imported.as_ref().unwrap().dropped.iter().map(|note| note.option.as_str()).collect();
        for option in ["script-security", "up", "down", "plugin", "management", "log", "comp-lzo", "compress", "cd"] {
            assert!(dropped.contains(&option), "{option} not dropped: {dropped:?}");
        }
        assert_eq!(parsed.profile.tls_wrap, TlsWrap::Auth { direction: Some(1) });
        let written = core_profile(&parsed.profile, parsed.tls_key.as_deref().map(|key| key.as_str())).unwrap();
        for word in ["up ", "down", "plugin", "script", "management", "log", "lz4", "comp-lzo yes", "cd "] {
            assert!(!written.lines().any(|line| line.starts_with(word)), "{word} in:\n{written}");
        }
        assert!(written.contains("key-direction 1\n<tls-auth>\n"));
        assert!(written.contains("tls-version-min 1.2\n"));
    }

    /// Own tunnels and the service both refuse a profile `vpn_proto::profile::check` turns down, so every profile the
    /// writer makes has to pass it.
    #[test]
    fn written_profiles_pass_the_workers_check() {
        let samples = [
            profile(&format!(
                "client\nproto tcp\nremote vpn.example.com 443\nremote 10.0.0.1 1194 udp\nremote-random\nauth-user-pass\nstatic-challenge \"Your \\\"code\\\"\" 1\nremote-cert-tls server\nverify-x509-name 'C=US, CN=vpn' subject\ncipher AES-256-GCM\nauth SHA256\nreneg-sec 0\ncompress stub-v2\n<tls-crypt>\n{STATIC_KEY}</tls-crypt>"
            )),
            profile(&format!("client\nremote vpn.example 1194\ncomp-lzo no\n<tls-auth>\n{STATIC_KEY}</tls-auth>\nkey-direction 1")),
            // Only a legacy cipher, so none is left to write.
            profile("client\nremote vpn.example 1194\ndata-ciphers BF-CBC\ntls-version-min 1.3"),
        ];
        for text in samples {
            let parsed = parse(&text, "a.ovpn", None).unwrap();
            let written = core_profile(&parsed.profile, parsed.tls_key.as_deref().map(|key| key.as_str())).unwrap();
            if let Err(error) = vpn_proto::profile::check(&written) {
                panic!("{error} in:\n{written}");
            }
        }
    }

    #[test]
    fn needs_something_to_check_the_server() {
        assert!(parse("client\nremote vpn.example 1194\n", "a.ovpn", None).err().unwrap().message.contains("nothing to check"));
        let fingerprint = "AA:".repeat(31) + "AA";
        let parsed = parse(&format!("remote vpn.example 1194\npeer-fingerprint {fingerprint}\n"), "a.ovpn", None).unwrap();
        assert_eq!(parsed.profile.peer_fingerprints, vec![fingerprint]);
    }

    #[test]
    fn system_only_options_are_marked() {
        let text = format!(
            "{}<cert>\n{}</cert>\n",
            profile("dev tap\nremote vpn.example 1194\nfragment 1300\ndata-ciphers BF-CBC\nhttp-proxy proxy 8080"),
            keys::test_certificate("client")
        );
        let parsed = parse(&text, "old.ovpn", None).unwrap();
        assert_eq!(parsed.profile.needs_system.len(), 4, "{:?}", parsed.profile.needs_system);
        let written = system_profile(&parsed.profile, None).unwrap();
        for line in ["dev tap\n", "fragment 1300\n", "data-ciphers BF-CBC\n", "http-proxy proxy 8080\n", "auth-nocache\n", "allow-compression no\n"] {
            assert!(written.contains(line), "{line} missing in:\n{written}");
        }
        assert!(!written.contains("dev tun"));
    }

    #[test]
    fn smartcard_libraries_from_files_and_static_keys_are_dropped() {
        let text = profile("remote vpn.example 1194\nauth-user-pass\npkcs11-providers /usr/lib/evil.so\nsecret static.key");
        let parsed = parse(&text, "a.ovpn", None).unwrap();
        let dropped: Vec<&str> = parsed.profile.imported.as_ref().unwrap().dropped.iter().map(|note| note.option.as_str()).collect();
        assert_eq!(dropped, ["pkcs11-providers", "secret"]);
        assert!(parsed.profile.system_options.is_empty());
        let written = system_profile(&parsed.profile, None).unwrap();
        assert!(!written.contains("evil") && !written.contains("pkcs") && !written.contains("secret"));
    }

    #[test]
    fn smartcards_need_a_library_picked_in_fran() {
        let mut parsed = parse(&profile("remote vpn.example 1194\npkcs11-id 'pkcs11:token=My Card;id=%01'"), "a.ovpn", None).unwrap().profile;
        assert_eq!(parsed.system_options, vec![vec!["pkcs11-id".to_string(), "pkcs11:token=My Card;id=%01".to_string()]]);
        assert!(key_outside_fran(&parsed));
        assert!(system_profile(&parsed, None).err().unwrap().message.contains("smartcard library"));
        parsed.pkcs11_provider = Some("/usr/lib/opensc-pkcs11.so".to_string());
        let written = system_profile(&parsed, None).unwrap();
        assert!(written.contains("pkcs11-id \"pkcs11:token=My Card;id=%01\"\n"));
        assert!(written.contains("pkcs11-providers \"/usr/lib/opensc-pkcs11.so\"\n"));
        assert!(!written.contains("management-external-key"));
    }

    #[test]
    fn certificate_store_is_passed_on_quoted() {
        let parsed = parse(&profile("remote vpn.example 1194\ncryptoapicert \"SUBJ:Peter Smith\""), "a.ovpn", None).unwrap().profile;
        assert_eq!(parsed.needs_system.len(), 1);
        let written = system_profile(&parsed, None).unwrap();
        assert!(written.contains("cryptoapicert \"SUBJ:Peter Smith\"\n"));
        assert!(!written.contains("management-external-key") && !written.contains("<cert>"));
    }

    #[test]
    fn pkcs12_asks_for_its_password() {
        let text = profile("remote vpn.example 1194\n<pkcs12>\nAAAA\n</pkcs12>");
        let error = parse(&text, "a.ovpn", None).err().unwrap();
        assert!(matches!(&error.detail, crate::error::ErrorDetail::SecretsRequired { slots } if slots[0].id == PKCS12_SLOT), "{error:?}");
        let error = parse_with(&text, "a.ovpn", None, Some("pw")).err().unwrap();
        assert!(error.message.contains("PKCS#12"), "{}", error.message);
    }

    #[test]
    fn system_profile_keeps_the_key_in_fran() {
        let text = format!("{}<cert>\n{}</cert>\n", profile("remote vpn.example 1194\nroute-nopull"), keys::test_certificate("client"));
        let mut parsed = parse(&text, "a.ovpn", None).unwrap().profile;
        parsed.use_vpn_dns = false;
        let written = system_profile(&parsed, None).unwrap();
        assert!(written.contains("management-external-key pkcs1 pss digest\n<cert>\n-----BEGIN CERTIFICATE-----"));
        assert!(!written.contains("PRIVATE KEY"));
        assert!(written.contains("pull-filter ignore \"redirect-gateway\"\n"));
        assert!(written.contains("pull-filter ignore \"dhcp-option DNS\"\n"));

        parsed.system_options = vec![vec!["up".to_string(), "/bin/sh".to_string()], vec!["fragment".to_string(), "1\nup /bin/sh".to_string()]];
        let written = system_profile(&parsed, None).unwrap();
        assert!(!written.contains("up ") && !written.contains("fragment"));
    }

    #[test]
    fn legacy_ciphers_are_left_out() {
        let text = profile("remote vpn.example 1194\ndata-ciphers AES-256-GCM:BF-CBC:CHACHA20-POLY1305\ncipher BF-CBC");
        let parsed = parse(&text, "a.ovpn", None).unwrap();
        assert_eq!(parsed.profile.ciphers, ["AES-256-GCM", "CHACHA20-POLY1305"]);
        assert_eq!(parsed.profile.fallback_cipher, None);
        assert!(parsed.profile.needs_system.is_empty());
    }

    #[test]
    fn files_are_only_read_beside_the_profile() {
        let dir = std::env::temp_dir().join(format!("fran-vpn-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::write(dir.join("keys").join("ca.crt"), ca()).unwrap();
        let parsed = parse("remote vpn.example 1194\nca keys/ca.crt\n", "a.ovpn", Some(&dir)).unwrap();
        assert!(parsed.profile.ca.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(parse("remote vpn.example 1194\nca ../ca.crt\n", "a.ovpn", Some(&dir)).is_err());
        assert!(parse("remote vpn.example 1194\nca /etc/passwd\n", "a.ovpn", Some(&dir)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writer_refuses_injection() {
        let mut profile = parse(&profile("remote vpn.example 1194"), "a.ovpn", None).unwrap().profile;
        profile.remotes[0].host = "vpn.example\nup /bin/sh".to_string();
        assert!(core_profile(&profile, None).is_err());
        profile.remotes[0].host = "vpn.example".to_string();
        profile.challenge = VpnChallenge::Static { echo: false, text: "a\"\nup x".to_string() };
        assert!(core_profile(&profile, None).is_err());
        profile.challenge = VpnChallenge::Static { echo: false, text: "say \"hi\"".to_string() };
        assert!(core_profile(&profile, None).unwrap().contains("static-challenge \"say \\\"hi\\\"\" 0\n"));
        profile.ca = format!("{}</ca>\nup /bin/sh\n", ca());
        let written = core_profile(&profile, None).unwrap();
        assert!(!written.contains("up /bin/sh"));
    }

    #[test]
    fn exports_read_back_the_same() {
        let der = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &ring::rand::SystemRandom::new()).unwrap();
        let key = keys::to_pem("PRIVATE KEY", der.as_ref());
        let text = format!(
            "{}<cert>\n{}</cert>\n<key>\n{key}</key>\n<tls-crypt>\n{STATIC_KEY}</tls-crypt>\n",
            profile("remote vpn.example 443 tcp\nremote-cert-tls server"),
            keys::test_certificate("client")
        );
        let parsed = parse(&text, "office.ovpn", None).unwrap();
        let exported = portable_profile(&parsed.profile, parsed.tls_key.as_deref().map(|key| key.as_str()), parsed.private_key.as_deref().map(|key| key.as_str())).unwrap();
        assert!(exported.contains("<key>\n-----BEGIN PRIVATE KEY-----"));
        let again = parse(&exported, "office.ovpn", None).unwrap();
        assert_eq!(again.profile.remotes, parsed.profile.remotes);
        assert_eq!(again.profile.tls_wrap, TlsWrap::Crypt);
        assert_eq!(again.private_key.as_deref().map(|key| key.as_str()), parsed.private_key.as_deref().map(|key| key.as_str()));
        assert_eq!(again.profile.cert, parsed.profile.cert);
    }

    #[test]
    fn login_is_read_inline_and_from_a_file_beside() {
        let parsed = parse(&profile("remote vpn.example 1194\n<auth-user-pass>\nalice\ns3cret pass\n</auth-user-pass>"), "a.ovpn", None).unwrap();
        assert_eq!(parsed.profile.user, "alice");
        assert_eq!(parsed.password.as_deref().map(|password| password.as_str()), Some("s3cret pass"));
        assert_eq!(parsed.profile.auth, VpnAuth::UserPass);

        let dir = std::env::temp_dir().join(format!("fran-vpn-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("login.txt"), "bob\r\nhunter2\r\n").unwrap();
        let parsed = parse(&profile("remote vpn.example 1194\nauth-user-pass login.txt"), "a.ovpn", Some(&dir)).unwrap();
        assert_eq!(parsed.profile.user, "bob");
        assert_eq!(parsed.password.as_deref().map(|password| password.as_str()), Some("hunter2"));

        let parsed = parse(&profile("remote vpn.example 1194\nauth-user-pass missing.txt"), "a.ovpn", Some(&dir)).unwrap();
        assert!(parsed.password.is_none());
        assert!(parsed.profile.imported.unwrap().dropped.iter().any(|note| note.option == "auth-user-pass"));
        std::fs::remove_dir_all(dir).unwrap();

        let parsed = parse(&profile("remote vpn.example 1194\n<auth-user-pass>\ncarol\n</auth-user-pass>"), "a.ovpn", None).unwrap();
        assert_eq!(parsed.profile.user, "carol");
        assert!(parsed.password.is_none());
    }

    #[test]
    fn missing_tls_key_is_an_error() {
        assert!(parse(&profile("remote vpn.example 1194\ntls-crypt ta.key"), "a.ovpn", None).is_err());
    }
}
