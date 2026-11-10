use std::{fs, sync::Arc};

use base64ct::{Base64, Encoding};
use russh::keys::{HashAlg, PublicKey};
use serde::{Deserialize, Serialize};
use tauri::State;

use super::HostKeyInfo;
use super::config_import::home_dir;
use crate::error::{AppError, AppResult};
use crate::json_store::JsonStore;
use crate::ssh_store::now_millis;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KnownHostsFile {
    pub hosts: Vec<HostKeyInfo>,
}

pub type KnownHosts = JsonStore<KnownHostsFile>;

fn same_host(known: &HostKeyInfo, host: &str, port: u16) -> bool {
    known.host.eq_ignore_ascii_case(host) && known.port == port
}

impl KnownHosts {
    pub fn find(&self, host: &str, port: u16) -> AppResult<Option<HostKeyInfo>> {
        self.read(|file| file.hosts.iter().find(|known| same_host(known, host, port)).cloned())
    }

    /// Never replaces a different key. That goes through `replace`, which the UI only offers after the host name is typed.
    pub fn trust(&self, mut key: HostKeyInfo) -> AppResult<()> {
        key.added = Some(now_millis());
        self.update(move |file| {
            if let Some(known) = file.hosts.iter().find(|known| same_host(known, &key.host, key.port)) {
                if known.fingerprint == key.fingerprint {
                    return Ok(());
                }
                return Err(AppError::general(format!(
                    "{}:{} already has a different trusted key. Replace it from the warning instead.",
                    key.host, key.port
                )));
            }
            file.hosts.push(key);
            Ok(())
        })
    }

    pub fn replace(&self, mut key: HostKeyInfo) -> AppResult<()> {
        key.added = Some(now_millis());
        self.update(move |file| {
            file.hosts.retain(|known| !same_host(known, &key.host, key.port));
            file.hosts.push(key);
            Ok(())
        })
    }

    pub fn forget(&self, host: &str, port: u16) -> AppResult<()> {
        self.update(|file| {
            file.hosts.retain(|known| !same_host(known, host, port));
            Ok(())
        })
    }
}

/// The name OpenSSH writes for a host: bare for port 22, `[host]:port` otherwise.
fn openssh_name(host: &str, port: u16) -> String {
    if port == 22 { host.to_ascii_lowercase() } else { format!("[{}]:{port}", host.to_ascii_lowercase()) }
}

fn glob(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p].eq_ignore_ascii_case(&text[t])) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(position) = star {
            p = position + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

fn hashed_match(entry: &str, name: &str) -> bool {
    let mut parts = entry.trim_start_matches("|1|").splitn(2, '|');
    let (Some(salt), Some(hash)) = (parts.next(), parts.next()) else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (Base64::decode_vec(salt), Base64::decode_vec(hash)) else {
        return false;
    };
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    ring::hmac::verify(&key, name.as_bytes(), &hash).is_ok()
}

fn hosts_field_matches(field: &str, name: &str) -> bool {
    let mut matched = false;
    for entry in field.split(',') {
        if entry.starts_with("|1|") {
            matched |= hashed_match(entry, name);
        } else if let Some(negated) = entry.strip_prefix('!') {
            if glob(negated, name) {
                return false;
            }
        } else {
            matched |= glob(entry, name);
        }
    }
    matched
}

/// Whether OpenSSH's own known_hosts trusts this key. The file is only read.
pub fn openssh_trusts_in(text: &str, host: &str, port: u16, fingerprint: &str) -> bool {
    let name = openssh_name(host, port);
    let mut trusted = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or_default();
        let (revoked, hosts) = match first {
            "@revoked" => (true, fields.next().unwrap_or_default()),
            marker if marker.starts_with('@') => continue,
            hosts => (false, hosts),
        };
        let (Some(algorithm), Some(blob)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !hosts_field_matches(hosts, &name) {
            continue;
        }
        let Ok(key) = PublicKey::from_openssh(&format!("{algorithm} {blob}")) else {
            continue;
        };
        if key.fingerprint(HashAlg::Sha256).to_string() == fingerprint {
            if revoked {
                return false;
            }
            trusted = true;
        }
    }
    trusted
}

pub fn openssh_trusts(host: &str, port: u16, fingerprint: &str) -> bool {
    let Some(home) = home_dir() else {
        return false;
    };
    fs::read_to_string(home.join(".ssh").join("known_hosts"))
        .map(|text| openssh_trusts_in(&text, host, port, fingerprint))
        .unwrap_or(false)
}

#[tauri::command]
pub async fn trust_host_key(known_hosts: State<'_, Arc<KnownHosts>>, key: HostKeyInfo) -> AppResult<()> {
    known_hosts.trust(key)
}

/// `typed_host` is what the user typed to confirm. It has to be the host name.
#[tauri::command]
pub async fn replace_host_key(known_hosts: State<'_, Arc<KnownHosts>>, key: HostKeyInfo, typed_host: String) -> AppResult<()> {
    if !typed_host.trim().eq_ignore_ascii_case(&key.host) {
        return Err(AppError::general("Type the host name to replace its key"));
    }
    known_hosts.replace(key)
}

#[tauri::command]
pub async fn list_known_hosts(known_hosts: State<'_, Arc<KnownHosts>>) -> AppResult<Vec<HostKeyInfo>> {
    known_hosts.read(|file| file.hosts.clone())
}

#[tauri::command]
pub async fn forget_known_host(known_hosts: State<'_, Arc<KnownHosts>>, host: String, port: u16) -> AppResult<()> {
    known_hosts.forget(&host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn fingerprint() -> String {
        PublicKey::from_openssh(KEY).unwrap().fingerprint(HashAlg::Sha256).to_string()
    }

    fn hashed(name: &str) -> String {
        let salt = [7u8; 20];
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
        let tag = ring::hmac::sign(&key, name.as_bytes());
        format!("|1|{}|{}", Base64::encode_string(&salt), Base64::encode_string(tag.as_ref()))
    }

    #[test]
    fn plain_and_port_entries() {
        let text = format!("bastion.acme.io,10.0.0.1 {KEY}\n[db.acme.io]:2222 {KEY}\n");
        assert!(openssh_trusts_in(&text, "bastion.acme.io", 22, &fingerprint()));
        assert!(openssh_trusts_in(&text, "10.0.0.1", 22, &fingerprint()));
        assert!(openssh_trusts_in(&text, "db.acme.io", 2222, &fingerprint()));
        assert!(!openssh_trusts_in(&text, "db.acme.io", 22, &fingerprint()));
        assert!(!openssh_trusts_in(&text, "bastion.acme.io", 22, "SHA256:other"));
    }

    #[test]
    fn hashed_entries() {
        let text = format!("{} {KEY}\n", hashed("[api.acme.io]:2200"));
        assert!(openssh_trusts_in(&text, "api.acme.io", 2200, &fingerprint()));
        assert!(!openssh_trusts_in(&text, "api.acme.io", 22, &fingerprint()));
    }

    #[test]
    fn wildcards_negation_and_markers() {
        let text = format!("*.acme.io,!evil.acme.io {KEY}\n@cert-authority *.corp {KEY}\n");
        assert!(openssh_trusts_in(&text, "web.acme.io", 22, &fingerprint()));
        assert!(!openssh_trusts_in(&text, "evil.acme.io", 22, &fingerprint()));
        assert!(!openssh_trusts_in(&text, "a.corp", 22, &fingerprint()));

        let revoked = format!("web.acme.io {KEY}\n@revoked * {KEY}\n");
        assert!(!openssh_trusts_in(&revoked, "web.acme.io", 22, &fingerprint()));
    }
}
