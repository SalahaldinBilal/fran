use serde::{Deserialize, Serialize};

use super::config::AgentConfig;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum AgentMode {
    #[default]
    Off,
    ReadOnly,
    /// Changes are allowed, each one after the user approves it.
    Ask,
    /// Changes run without asking.
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseRule {
    pub name: String,
    pub mode: AgentMode,
}

/// What agents may do with one connection. Stored on the connection profile.
/// Where a session is bound to one database (Postgres, D1) the names are those databases, elsewhere the ones tools take.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", from = "StoredAccess")]
pub struct AgentAccess {
    pub mode: AgentMode,
    /// Whether databases without a rule get `mode`. Off hides them.
    pub all_databases: bool,
    pub exceptions: Vec<DatabaseRule>,
}

impl Default for AgentAccess {
    fn default() -> Self {
        Self { mode: AgentMode::Off, all_databases: true, exceptions: Vec::new() }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredAccess {
    #[serde(default)]
    mode: AgentMode,
    all_databases: Option<bool>,
    #[serde(default)]
    exceptions: Vec<DatabaseRule>,
    /// Before exceptions: the only databases shared, all when empty.
    #[serde(default)]
    databases: Vec<String>,
}

impl From<StoredAccess> for AgentAccess {
    fn from(stored: StoredAccess) -> Self {
        let (all_databases, rules) = match stored.all_databases {
            Some(all) => (all, stored.exceptions),
            None if stored.databases.is_empty() => (true, stored.exceptions),
            None => (
                false,
                stored.databases.into_iter().map(|name| DatabaseRule { name, mode: stored.mode }).collect(),
            ),
        };
        let mut exceptions: Vec<DatabaseRule> = Vec::with_capacity(rules.len());
        for rule in rules {
            if !rule.name.is_empty() && !exceptions.iter().any(|kept| kept.name == rule.name) {
                exceptions.push(rule);
            }
        }
        Self { mode: stored.mode, all_databases, exceptions }
    }
}

fn clamp(mode: AgentMode, config: &AgentConfig) -> AgentMode {
    if !config.allow_changes && mode > AgentMode::ReadOnly { AgentMode::ReadOnly } else { mode }
}

impl AgentAccess {
    fn raw_level(&self, database: &str) -> AgentMode {
        if self.mode == AgentMode::Off {
            return AgentMode::Off;
        }
        match self.exceptions.iter().find(|rule| rule.name == database) {
            Some(rule) => rule.mode,
            None if self.all_databases => self.mode,
            None => AgentMode::Off,
        }
    }

    pub fn allows(&self, database: &str) -> bool {
        self.raw_level(database) != AgentMode::Off
    }

    /// The level for one database, made read only when changes are switched off for every agent.
    pub fn level(&self, database: &str, config: &AgentConfig) -> AgentMode {
        clamp(self.raw_level(database), config)
    }

    /// The connection's level, made read only when changes are switched off for every agent.
    pub fn effective_mode(&self, config: &AgentConfig) -> AgentMode {
        clamp(self.mode, config)
    }

    /// No database is hidden.
    pub fn sees_everything(&self) -> bool {
        self.mode != AgentMode::Off
            && self.all_databases
            && self.exceptions.iter().all(|rule| rule.mode != AgentMode::Off)
    }

    /// Every database takes changes without asking, so SQL that can name any of them may skip approval too.
    pub fn writes_everywhere(&self, config: &AgentConfig) -> bool {
        config.allow_changes
            && self.mode == AgentMode::Write
            && self.all_databases
            && self.exceptions.iter().all(|rule| rule.mode == AgentMode::Write)
    }

    /// The highest level any database on the connection has.
    pub fn highest(&self, config: &AgentConfig) -> AgentMode {
        if self.mode == AgentMode::Off {
            return AgentMode::Off;
        }
        let unlisted = if self.all_databases { self.mode } else { AgentMode::Off };
        let highest = self.exceptions.iter().map(|rule| rule.mode).fold(unlisted, AgentMode::max);
        clamp(highest, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(value: serde_json::Value) -> AgentAccess {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_list_saved_before_exceptions_still_hides_the_other_databases() {
        let config = AgentConfig::default();
        let old = access(serde_json::json!({ "mode": "ask", "databases": ["shop"] }));
        assert_eq!(old.level("shop", &config), AgentMode::Ask);
        assert_eq!(old.level("payroll", &config), AgentMode::Off);

        let everything = access(serde_json::json!({ "mode": "readOnly", "databases": [] }));
        assert_eq!(everything.level("payroll", &config), AgentMode::ReadOnly);
        assert!(everything.sees_everything());
    }

    #[test]
    fn raw_sql_only_skips_approval_when_no_database_is_held_back() {
        let config = AgentConfig::default();
        let scratch_only = access(serde_json::json!({
            "mode": "write", "allDatabases": false, "exceptions": [{ "name": "scratch", "mode": "write" }],
        }));
        assert_eq!(scratch_only.level("scratch", &config), AgentMode::Write);
        assert!(!scratch_only.writes_everywhere(&config));

        let prod_asks = access(serde_json::json!({
            "mode": "write", "allDatabases": true, "exceptions": [{ "name": "prod", "mode": "ask" }],
        }));
        assert!(!prod_asks.writes_everywhere(&config));

        let everywhere = access(serde_json::json!({ "mode": "write", "allDatabases": true }));
        assert!(everywhere.writes_everywhere(&config));
        let changes_off = AgentConfig { allow_changes: false, ..AgentConfig::default() };
        assert!(!everywhere.writes_everywhere(&changes_off));
        assert_eq!(everywhere.level("any", &changes_off), AgentMode::ReadOnly);
    }
}
