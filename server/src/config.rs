use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sync_proto::{KEY_LEN, Limits, SignupMode};

pub const DEFAULT_RECORD_BYTES: u64 = 256 * 1024;
pub const DEFAULT_ACCOUNT_BYTES: u64 = 50 * 1024 * 1024;
pub const DEFAULT_BATCH_RECORDS: u64 = 5000;

#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    pub window_secs: i64,
    pub per_account: i64,
    pub per_ip: i64,
    pub signups_per_ip: i64,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self { window_secs: 15 * 60, per_account: 10, per_ip: 30, signups_per_ip: 10 }
    }
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    pub public_url: Option<String>,
    pub signup: SignupMode,
    pub server_key: [u8; KEY_LEN],
    pub limits: Limits,
    /// 0 for no total limit.
    pub server_bytes: u64,
    pub rate: RateLimits,
    pub tls: Option<TlsFiles>,
    pub trust_proxy: bool,
}

const FILE_ENV: &str = "FRAN_SYNC_CONFIG";
const DEFAULT_FILE: &str = "server.toml";

struct Source {
    file: HashMap<String, String>,
}

impl Source {
    fn load() -> Result<Self, String> {
        let named = std::env::var(FILE_ENV).ok();
        let path = named.as_deref().unwrap_or(DEFAULT_FILE);
        if named.is_none() && !Path::new(path).exists() {
            return Ok(Self { file: HashMap::new() });
        }
        let text = std::fs::read_to_string(path).map_err(|error| format!("Can't read {path}: {error}"))?;
        Ok(Self { file: parse_file(&text).map_err(|error| format!("{path}: {error}"))? })
    }

    fn get(&self, name: &str) -> Option<String> {
        let value = std::env::var(name).ok().or_else(|| self.file.get(&name.to_lowercase()).cloned())?;
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    }

    fn number(&self, name: &str, default: u64) -> Result<u64, String> {
        match self.get(name) {
            Some(value) => value.parse().map_err(|_| format!("{name} must be a whole number")),
            None => Ok(default),
        }
    }
}

fn parse_file(text: &str) -> Result<HashMap<String, String>, String> {
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| error.message().to_string())?;
    let mut values = HashMap::new();
    for (name, value) in table {
        let text = match value {
            toml::Value::String(text) => text,
            toml::Value::Integer(number) => number.to_string(),
            toml::Value::Boolean(flag) => flag.to_string(),
            _ => return Err(format!("{name} must be text, a number or true/false")),
        };
        values.insert(name.to_lowercase(), text);
    }
    Ok(values)
}

pub fn parse_server_key(text: &str) -> Result<[u8; KEY_LEN], String> {
    let bytes = hex::decode(text.trim()).map_err(|_| "SERVER_KEY must be 64 hex characters".to_string())?;
    bytes.try_into().map_err(|_| "SERVER_KEY must be 64 hex characters".to_string())
}

pub fn parse_signup(text: &str) -> Result<SignupMode, String> {
    match text {
        "open" => Ok(SignupMode::Open),
        "invite" => Ok(SignupMode::Invite),
        "closed" => Ok(SignupMode::Closed),
        _ => Err("SIGNUP must be open, invite or closed".to_string()),
    }
}

fn parse_flag(name: &str, text: &str) -> Result<bool, String> {
    match text {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

// http is only for a server on this computer, the app refuses it for anything else.
pub fn check_public_url(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err("PUBLIC_URL must start with https://".to_string());
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(host, _)| host),
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        Ok(())
    } else {
        Err("PUBLIC_URL must be https unless it points at this computer".to_string())
    }
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let source = Source::load()?;
        let server_key = source
            .get("SERVER_KEY")
            .ok_or("SERVER_KEY isn't set. Make one with `openssl rand -hex 32` and keep it, it protects the two-step sign-in secrets.")?;
        let bind = source.get("BIND").unwrap_or_else(|| "127.0.0.1:8787".to_string());
        let public_url = source.get("PUBLIC_URL");
        if let Some(url) = &public_url {
            check_public_url(url)?;
        }
        let tls = match (source.get("TLS_CERT"), source.get("TLS_KEY")) {
            (Some(cert), Some(key)) => Some(TlsFiles { cert: cert.into(), key: key.into() }),
            (None, None) => None,
            _ => return Err("TLS_CERT and TLS_KEY must be set together".to_string()),
        };
        let defaults = RateLimits::default();
        Ok(Self {
            database_url: source.get("DATABASE_URL").unwrap_or_else(|| "sqlite:fran-sync.db".to_string()),
            bind: bind.parse().map_err(|_| "BIND must be an address and port, like 127.0.0.1:8787".to_string())?,
            public_url,
            signup: parse_signup(&source.get("SIGNUP").unwrap_or_else(|| "closed".to_string()))?,
            server_key: parse_server_key(&server_key)?,
            limits: Limits {
                record_bytes: source.number("RECORD_BYTES", DEFAULT_RECORD_BYTES)?,
                account_bytes: source.number("ACCOUNT_BYTES", DEFAULT_ACCOUNT_BYTES)?,
                batch_records: source.number("BATCH_RECORDS", DEFAULT_BATCH_RECORDS)?,
            },
            server_bytes: source.number("SERVER_BYTES", 0)?,
            rate: RateLimits {
                window_secs: source.number("LOGIN_WINDOW_SECS", defaults.window_secs as u64)? as i64,
                per_account: source.number("LOGIN_ATTEMPTS_PER_ACCOUNT", defaults.per_account as u64)? as i64,
                per_ip: source.number("LOGIN_ATTEMPTS_PER_IP", defaults.per_ip as u64)? as i64,
                signups_per_ip: source.number("SIGNUPS_PER_IP", defaults.signups_per_ip as u64)? as i64,
            },
            tls,
            trust_proxy: match source.get("TRUST_PROXY") {
                Some(value) => parse_flag("TRUST_PROXY", &value)?,
                None => false,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_only_accepted_for_this_computer() {
        assert!(check_public_url("https://sync.example.com").is_ok());
        assert!(check_public_url("http://localhost:8787").is_ok());
        assert!(check_public_url("http://127.0.0.1:8787/").is_ok());
        assert!(check_public_url("http://[::1]:8787").is_ok());
        assert!(check_public_url("http://sync.example.com").is_err());
        assert!(check_public_url("http://localhost.evil.example").is_err());
        assert!(check_public_url("http://127.0.0.1.evil.example:80").is_err());
    }

    #[test]
    fn a_config_file_takes_numbers_and_text() {
        let values = parse_file("bind = \"0.0.0.0:8787\"\nrecord_bytes = 1024\ntrust_proxy = true\n").unwrap();
        assert_eq!(values["bind"], "0.0.0.0:8787");
        assert_eq!(values["record_bytes"], "1024");
        assert_eq!(values["trust_proxy"], "true");
        assert!(parse_file("limits = { record = 1 }").is_err());
    }
}
