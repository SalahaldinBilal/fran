use std::collections::HashMap;

use sync_proto::{Limits, ServerSettings, SignupMode, UpdateSettings};

use crate::config::{Config, parse_signup};

const SIGNUP: &str = "signup";
const ACCOUNT_BYTES: &str = "account_bytes";
const RECORD_BYTES: &str = "record_bytes";
const BATCH_RECORDS: &str = "batch_records";
const SERVER_BYTES: &str = "server_bytes";

const MIN_RECORD_BYTES: u64 = 1024;
const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BATCH_RECORDS: u64 = 50_000;
const MIN_SERVER_BYTES: u64 = 1024 * 1024;
pub const MIN_ACCOUNT_BYTES: u64 = 1024;

/// What the server goes by right now, after what was changed from the app.
#[derive(Debug, Clone, Copy)]
pub struct Effective {
    pub signup: SignupMode,
    pub limits: Limits,
    /// 0 for no total limit.
    pub server_bytes: u64,
}

impl Effective {
    pub fn quota_for(&self, own_quota: i64) -> u64 {
        if own_quota > 0 { own_quota as u64 } else { self.limits.account_bytes }
    }
}

fn signup_text(mode: SignupMode) -> &'static str {
    match mode {
        SignupMode::Open => "open",
        SignupMode::Invite => "invite",
        SignupMode::Closed => "closed",
    }
}

/// The config is only where each setting starts. Anything saved from the app wins over it.
pub fn effective(config: &Config, saved: &HashMap<String, String>) -> Effective {
    let number = |name: &str| saved.get(name).and_then(|value| value.parse::<u64>().ok());
    Effective {
        signup: saved.get(SIGNUP).and_then(|value| parse_signup(value).ok()).unwrap_or(config.signup),
        limits: Limits {
            account_bytes: number(ACCOUNT_BYTES).unwrap_or(config.limits.account_bytes),
            record_bytes: number(RECORD_BYTES).unwrap_or(config.limits.record_bytes),
            batch_records: number(BATCH_RECORDS).unwrap_or(config.limits.batch_records),
        },
        server_bytes: number(SERVER_BYTES).unwrap_or(config.server_bytes),
    }
}

pub fn shown(current: &Effective) -> ServerSettings {
    ServerSettings {
        signup: current.signup,
        account_bytes: current.limits.account_bytes,
        record_bytes: current.limits.record_bytes,
        batch_records: current.limits.batch_records,
        server_bytes: current.server_bytes,
    }
}

/// The rows to save for a change from the app, checked.
pub fn changes(current: &Effective, update: &UpdateSettings) -> Result<Vec<(&'static str, String)>, String> {
    let mut rows = Vec::new();
    if let Some(mode) = update.signup {
        rows.push((SIGNUP, signup_text(mode).to_string()));
    }
    let record_bytes = update.record_bytes.unwrap_or(current.limits.record_bytes);
    if let Some(value) = update.record_bytes {
        if !(MIN_RECORD_BYTES..=MAX_RECORD_BYTES).contains(&value) {
            return Err("The largest record has to be between 1 KiB and 64 MiB".to_string());
        }
        rows.push((RECORD_BYTES, value.to_string()));
    }
    if let Some(value) = update.account_bytes {
        if value < MIN_ACCOUNT_BYTES.max(record_bytes) {
            return Err("The storage per account has to hold at least one record of the largest size".to_string());
        }
        rows.push((ACCOUNT_BYTES, value.to_string()));
    }
    if let Some(value) = update.batch_records {
        if !(1..=MAX_BATCH_RECORDS).contains(&value) {
            return Err("Records per push has to be between 1 and 50,000".to_string());
        }
        rows.push((BATCH_RECORDS, value.to_string()));
    }
    if let Some(value) = update.server_bytes {
        if value != 0 && value < MIN_SERVER_BYTES {
            return Err("The total limit has to be at least 1 MiB, or 0 for none".to_string());
        }
        rows.push((SERVER_BYTES, value.to_string()));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimits;

    fn config() -> Config {
        Config {
            database_url: String::new(),
            bind: "127.0.0.1:0".parse().unwrap(),
            public_url: None,
            signup: SignupMode::Closed,
            server_key: [0; 32],
            limits: Limits { record_bytes: 1000, account_bytes: 5000, batch_records: 10 },
            server_bytes: 0,
            rate: RateLimits::default(),
            tls: None,
            trust_proxy: false,
        }
    }

    #[test]
    fn a_value_saved_from_the_app_beats_the_one_the_server_started_with() {
        let saved: HashMap<String, String> = [("signup", "open"), ("account_bytes", "9000")].into_iter().map(|(a, b)| (a.into(), b.into())).collect();
        let current = effective(&config(), &saved);
        assert_eq!((current.signup, current.limits.account_bytes, current.limits.record_bytes), (SignupMode::Open, 9000, 1000));
    }

    #[test]
    fn a_limit_that_cant_work_is_refused() {
        let current = effective(&config(), &HashMap::new());
        let smaller_than_a_record = UpdateSettings { account_bytes: Some(999), ..UpdateSettings::default() };
        assert!(changes(&current, &smaller_than_a_record).is_err());
        assert!(changes(&current, &UpdateSettings { server_bytes: Some(10), ..UpdateSettings::default() }).is_err());
        assert_eq!(changes(&current, &UpdateSettings { server_bytes: Some(0), ..UpdateSettings::default() }).unwrap(), [("server_bytes", "0".to_string())]);
    }
}
