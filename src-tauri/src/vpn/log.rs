use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

const MAX_LINES: usize = 2000;
const MAX_LINE_CHARS: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LogSource {
    /// What Fran did and decided.
    Fran,
    /// OpenVPN's or WireGuard's own log and events.
    Vpn,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnLogLine {
    pub at: u64,
    pub source: LogSource,
    pub error: bool,
    pub text: String,
}

/// The recent history of one VPN profile, kept in memory only.
#[derive(Default)]
pub struct VpnLog {
    lines: Mutex<VecDeque<VpnLogLine>>,
}

impl VpnLog {
    pub fn fran(&self, text: impl Into<String>) {
        self.add(LogSource::Fran, false, text.into());
    }

    pub fn fran_error(&self, text: impl Into<String>) {
        self.add(LogSource::Fran, true, text.into());
    }

    pub fn vpn(&self, error: bool, text: impl Into<String>) {
        self.add(LogSource::Vpn, error, text.into());
    }

    fn add(&self, source: LogSource, error: bool, text: String) {
        let text = clean(&text);
        if text.is_empty() {
            return;
        }
        let at = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or_default();
        if let Ok(mut lines) = self.lines.lock() {
            if lines.len() == MAX_LINES {
                lines.pop_front();
            }
            lines.push_back(VpnLogLine { at, source, error, text });
        }
    }

    pub fn lines(&self) -> Vec<VpnLogLine> {
        self.lines.lock().map(|lines| lines.iter().cloned().collect()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.clear();
        }
    }
}

/// A server can push a session token that works like a password, and OpenVPN logs the push. Management commands
/// echoed back can carry the login, so only their mention is kept.
fn clean(text: &str) -> String {
    if let Some(start) = text.find("MANAGEMENT: CMD") {
        return format!("{}MANAGEMENT: CMD [hidden]", &text[..start]);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.trim_end();
    while let Some(start) = rest.find("auth-token") {
        let (before, after) = rest.split_at(start);
        out.push_str(before);
        let end = after.find([',', '\'', '"']).unwrap_or(after.len());
        let name_end = after[..end].find(' ').unwrap_or(end);
        out.push_str(&after[..name_end]);
        if name_end < end {
            out.push_str(" [hidden]");
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    match out.char_indices().nth(MAX_LINE_CHARS) {
        Some((cut, _)) => format!("{}...", &out[..cut]),
        None => out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pushed_session_token_never_reaches_the_log() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,auth-token SESS_ID_abc123,auth-token-user dXNlcg==,ifconfig 10.8.0.2 255.255.255.0'";
        let cleaned = clean(line);
        assert!(!cleaned.contains("SESS_ID_abc123"), "{cleaned}");
        assert!(!cleaned.contains("dXNlcg=="), "{cleaned}");
        assert!(cleaned.contains("route-gateway 10.8.0.1"));
        assert!(cleaned.contains("ifconfig 10.8.0.2"));
    }

    #[test]
    fn an_echoed_management_login_never_reaches_the_log() {
        let cleaned = clean("MANAGEMENT: CMD 'password \"Auth\" hunter2'");
        assert!(!cleaned.contains("hunter2"), "{cleaned}");
    }
}
