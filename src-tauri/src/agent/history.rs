use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::daylog::now_ms;
use crate::daylog::{DAY_MS, DayLog};
use crate::error::AppResult;
use crate::vault::Vault;

const MAGIC: &[u8; 8] = b"FRDBHIS1";
const KEY_ID: &str = "agent:historyKey";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum HistoryEvent {
    Call,
    SessionClosed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Ok,
    Error,
    /// Turned away by the connection's access or a global switch.
    Refused,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalAnswer {
    Approved,
    Rejected,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    pub answer: ApprovalAnswer,
    pub requested_at: u64,
    pub answered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: String,
    pub at: u64,
    pub event: HistoryEvent,
    pub agent: Option<String>,
    pub session_id: Option<String>,
    pub connection_id: Option<String>,
    pub connection_name: Option<String>,
    pub database: Option<String>,
    pub tool: Option<String>,
    pub arguments: Option<Value>,
    pub statements: Vec<String>,
    pub approval: Option<ApprovalRecord>,
    pub outcome: Outcome,
    pub message: Option<String>,
    pub duration_ms: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<Value>,
}

/// Agent calls in one encrypted file per UTC day, appended record by record.
pub struct History {
    log: DayLog,
}

impl History {
    pub fn new(dir: PathBuf) -> Self {
        Self { log: DayLog::new(dir, MAGIC, KEY_ID, "agent history") }
    }

    /// Loads the history key from the vault, making one the first time.
    pub fn unlock(&self, vault: &Vault) -> AppResult<()> {
        self.log.unlock(vault)
    }

    /// For the app lock. Calls made meanwhile are written once it's unlocked.
    pub fn seal(&self) {
        self.log.seal();
    }

    /// Drops the key and every file, for a vault reset that makes the history unreadable.
    pub fn forget(&self) -> AppResult<()> {
        self.log.forget()
    }

    pub fn append(&self, entry: &HistoryEntry) -> AppResult<()> {
        self.log.append(entry.at, entry)
    }

    /// Entries between two times, newest first, without the replies.
    pub fn list(&self, from: u64, to: u64) -> AppResult<Vec<HistoryEntry>> {
        let mut entries: Vec<HistoryEntry> = self
            .log
            .read_days::<HistoryEntry>(from, to)?
            .into_iter()
            .filter(|entry| entry.at >= from && entry.at <= to)
            .map(|entry| HistoryEntry { reply: None, ..entry })
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.at));
        Ok(entries)
    }

    pub fn get(&self, id: &str, at: u64) -> AppResult<Option<HistoryEntry>> {
        let day = at - at % DAY_MS;
        Ok(self.log.read_days::<HistoryEntry>(day, day)?.into_iter().find(|entry| entry.id == id))
    }

    pub fn prune(&self, keep_days: u32) -> AppResult<()> {
        self.log.prune(keep_days)
    }

    pub fn size(&self) -> AppResult<u64> {
        self.log.size()
    }

    pub fn clear(&self) -> AppResult<()> {
        self.log.clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, at: u64) -> HistoryEntry {
        HistoryEntry {
            id: id.to_string(),
            at,
            event: HistoryEvent::Call,
            agent: Some("claude-code".to_string()),
            session_id: None,
            connection_id: None,
            connection_name: None,
            database: None,
            tool: Some("run_query".to_string()),
            arguments: None,
            statements: vec!["SELECT 1".to_string()],
            approval: None,
            outcome: Outcome::Ok,
            message: None,
            duration_ms: 1.0,
            reply: Some(serde_json::json!({ "rows": [[1]] })),
        }
    }

    #[test]
    fn appends_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("fran-history-{}", uuid::Uuid::new_v4()));
        let history = History::new(dir.clone());
        history.log.set_test_key(vec![7u8; 32]);

        let day = 20_752 * DAY_MS;
        history.append(&entry("a", day + 10)).unwrap();
        history.append(&entry("b", day + 20)).unwrap();
        history.append(&entry("c", day + DAY_MS + 5)).unwrap();

        let listed = history.list(day, day + DAY_MS * 2).unwrap();
        assert_eq!(listed.iter().map(|entry| entry.id.as_str()).collect::<Vec<_>>(), ["c", "b", "a"]);
        assert!(listed.iter().all(|entry| entry.reply.is_none()));
        assert!(history.get("b", day + 20).unwrap().unwrap().reply.is_some());

        let path = history.log.test_path(20_752);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(&[9, 0, 0]);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(history.list(day, day + DAY_MS - 1).unwrap().len(), 2);

        history.log.set_test_key(vec![8u8; 32]);
        assert!(history.list(day, day).is_err());

        history.clear().unwrap();
        assert!(!dir.exists());
    }
}
