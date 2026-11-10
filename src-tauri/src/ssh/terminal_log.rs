use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::daylog::{DayLog, now_ms};
use crate::error::AppResult;
use crate::vault::Vault;

const MAGIC: &[u8; 8] = b"FRDBTRM1";
const KEY_ID: &str = "terminal:logKey";
pub const FLUSH_EVERY: Duration = Duration::from_secs(1);
const FLUSH_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogKind {
    Opened,
    Output,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRecord {
    pub terminal_id: String,
    pub host_id: String,
    pub host_label: String,
    pub at: u64,
    pub kind: LogKind,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSession {
    pub terminal_id: String,
    pub host_id: String,
    pub host_label: String,
    pub started_at: u64,
    pub ended_at: u64,
    pub bytes: u64,
}

/// What terminals printed, never what was typed, in one encrypted file per UTC day. Off unless the setting is on.
pub struct TerminalLogs {
    log: DayLog,
}

impl TerminalLogs {
    pub fn new(dir: PathBuf) -> Self {
        Self { log: DayLog::new(dir, MAGIC, KEY_ID, "terminal log") }
    }

    pub fn unlock(&self, vault: &Vault) -> AppResult<()> {
        self.log.unlock(vault)
    }

    pub fn is_unlocked(&self) -> bool {
        self.log.is_unlocked()
    }

    pub fn seal(&self) {
        self.log.seal();
    }

    pub fn is_sealed(&self) -> bool {
        self.log.is_sealed()
    }

    pub fn forget(&self) -> AppResult<()> {
        self.log.forget()
    }

    fn append(&self, record: &LogRecord) {
        if let Err(error) = self.log.append(record.at, record) {
            eprintln!("terminal log: {}", error.message);
        }
    }
}

/// How many bytes at the end of `bytes` are the start of a UTF-8 character that isn't finished yet.
fn unfinished_tail(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let byte = bytes[bytes.len() - back];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue;
        }
        let needed = match byte {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        };
        return if needed > back { back } else { 0 };
    }
    0
}

/// One pane's log. Output is batched so a busy shell doesn't write a record per chunk.
pub struct PaneLog {
    logs: Arc<TerminalLogs>,
    terminal_id: String,
    host_id: String,
    host_label: String,
    pending: Vec<u8>,
    last_flush: Instant,
    closed: bool,
}

impl PaneLog {
    pub fn start(logs: Arc<TerminalLogs>, terminal_id: String, host_id: String, host_label: String) -> Self {
        let pane = Self { logs, terminal_id, host_id, host_label, pending: Vec::new(), last_flush: Instant::now(), closed: false };
        pane.record(LogKind::Opened, String::new());
        pane
    }

    fn record(&self, kind: LogKind, text: String) {
        self.logs.append(&LogRecord {
            terminal_id: self.terminal_id.clone(),
            host_id: self.host_id.clone(),
            host_label: self.host_label.clone(),
            at: now_ms(),
            kind,
            text,
        });
    }

    pub fn output(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
        if self.pending.len() >= FLUSH_BYTES || self.last_flush.elapsed() >= FLUSH_EVERY {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        self.last_flush = Instant::now();
        let keep = unfinished_tail(&self.pending);
        if self.pending.len() == keep {
            return;
        }
        let tail = self.pending.split_off(self.pending.len() - keep);
        let text = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending = tail;
        self.record(LogKind::Output, text);
    }

    pub fn close(mut self, reason: Option<&str>) {
        self.finish(reason);
    }

    fn finish(&mut self, reason: Option<&str>) {
        if self.closed {
            return;
        }
        self.closed = true;
        if !self.pending.is_empty() {
            let text = String::from_utf8_lossy(&self.pending).into_owned();
            self.pending.clear();
            self.record(LogKind::Output, text);
        }
        self.record(LogKind::Closed, reason.unwrap_or_default().to_string());
    }
}

// A pane closed from the app drops its task mid-read, so the last output is written here.
impl Drop for PaneLog {
    fn drop(&mut self) {
        self.finish(Some("Closed in Fran"));
    }
}

fn ready(logs: &TerminalLogs, vault: &Vault) -> AppResult<()> {
    if logs.is_unlocked() { Ok(()) } else { logs.unlock(vault) }
}

#[tauri::command]
pub async fn list_terminal_logs(
    logs: State<'_, Arc<TerminalLogs>>,
    vault: State<'_, Arc<Vault>>,
    from: u64,
    to: u64,
) -> AppResult<Vec<LogSession>> {
    ready(&logs, &vault)?;
    let mut sessions: BTreeMap<String, LogSession> = BTreeMap::new();
    for record in logs.log.read_days::<LogRecord>(from, to)? {
        if record.at < from || record.at > to {
            continue;
        }
        let session = sessions.entry(record.terminal_id.clone()).or_insert_with(|| LogSession {
            terminal_id: record.terminal_id.clone(),
            host_id: record.host_id.clone(),
            host_label: record.host_label.clone(),
            started_at: record.at,
            ended_at: record.at,
            bytes: 0,
        });
        session.started_at = session.started_at.min(record.at);
        session.ended_at = session.ended_at.max(record.at);
        if record.kind == LogKind::Output {
            session.bytes += record.text.len() as u64;
        }
    }
    let mut list: Vec<LogSession> = sessions.into_values().collect();
    list.sort_by_key(|session| std::cmp::Reverse(session.started_at));
    Ok(list)
}

/// The text one terminal printed between two times, with how it ended on the last line.
#[tauri::command]
pub async fn get_terminal_log(
    logs: State<'_, Arc<TerminalLogs>>,
    vault: State<'_, Arc<Vault>>,
    terminal_id: String,
    from: u64,
    to: u64,
) -> AppResult<String> {
    ready(&logs, &vault)?;
    let mut text = String::new();
    for record in logs.log.read_days::<LogRecord>(from, to)? {
        if record.terminal_id != terminal_id {
            continue;
        }
        match record.kind {
            LogKind::Output => text.push_str(&record.text),
            LogKind::Closed if !record.text.is_empty() => text.push_str(&format!("\r\n[{}]\r\n", record.text)),
            _ => {}
        }
    }
    Ok(text)
}

#[tauri::command]
pub async fn get_terminal_log_size(logs: State<'_, Arc<TerminalLogs>>) -> AppResult<u64> {
    logs.log.size()
}

#[tauri::command]
pub async fn clear_terminal_logs(logs: State<'_, Arc<TerminalLogs>>) -> AppResult<()> {
    logs.log.clear()
}

#[tauri::command]
pub async fn prune_terminal_logs(logs: State<'_, Arc<TerminalLogs>>, keep_days: u32) -> AppResult<()> {
    logs.log.prune(keep_days.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_unfinished_characters_for_the_next_batch() {
        assert_eq!(unfinished_tail(b"abc"), 0);
        assert_eq!(unfinished_tail("é".as_bytes()), 0);
        assert_eq!(unfinished_tail(&"é".as_bytes()[..1]), 1);
        assert_eq!(unfinished_tail(&"€".as_bytes()[..2]), 2);
        assert_eq!(unfinished_tail(&"😀".as_bytes()[..3]), 3);
        assert_eq!(unfinished_tail("😀".as_bytes()), 0);
    }

    #[test]
    fn splits_output_on_character_boundaries() {
        let dir = std::env::temp_dir().join(format!("fran-termlog-{}", uuid::Uuid::new_v4()));
        let logs = Arc::new(TerminalLogs::new(dir));
        logs.log.set_test_key(vec![4u8; 32]);
        let mut pane = PaneLog::start(logs.clone(), "t1".into(), "h1".into(), "web".into());
        let bytes = "ok €".as_bytes();
        pane.output(&bytes[..5]);
        pane.flush();
        pane.output(&bytes[5..]);
        pane.close(Some("The shell exited"));

        let now = now_ms();
        let records: Vec<LogRecord> = logs.log.read_days(now.saturating_sub(60_000), now).unwrap();
        let text: String = records.iter().filter(|record| record.kind == LogKind::Output).map(|record| record.text.as_str()).collect();
        assert_eq!(text, "ok €");
        assert!(records.iter().all(|record| !record.text.contains('\u{FFFD}')));
        logs.log.clear().unwrap();
    }
}
