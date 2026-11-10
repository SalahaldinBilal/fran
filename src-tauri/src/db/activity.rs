use serde::{Deserialize, Serialize};

/// The most statements a history returns, highest first by the order asked for.
pub const HISTORY_LIMIT: usize = 200;

/// Which column picks the statements a history returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HistoryOrder {
    Calls,
    TotalMs,
    MeanMs,
    MaxMs,
    Rows,
}

/// Which parts of the slow queries view a session can fill.
#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitySupport {
    pub history: bool,
    pub running: bool,
}

/// Statements grouped by shape, with times summed over every run the server saw.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryHistory {
    /// Where the numbers come from, like `performance_schema statement digests`.
    pub source: String,
    /// When the counters started, as the server reports it.
    pub since: Option<String>,
    pub statements: Vec<StatementStats>,
    /// The server had more statements than `HISTORY_LIMIT`, so a different order may pick different ones.
    pub limited: bool,
    pub notice: Option<ActivityNotice>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementStats {
    pub id: String,
    /// The statement with its values replaced by placeholders.
    pub text: String,
    /// One real run of it, with its values, when the server keeps one.
    pub sample: Option<String>,
    pub database: Option<String>,
    pub user: Option<String>,
    pub calls: u64,
    pub total_ms: f64,
    pub mean_ms: f64,
    pub max_ms: Option<f64>,
    pub rows: Option<u64>,
    pub rows_examined: Option<u64>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningQueries {
    pub queries: Vec<RunningQuery>,
    /// The server only counts whole seconds, so `running_ms` is a multiple of 1000.
    pub whole_seconds: bool,
    pub notice: Option<ActivityNotice>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningQuery {
    pub id: String,
    pub user: Option<String>,
    pub database: Option<String>,
    pub client: Option<String>,
    pub state: Option<String>,
    pub running_ms: Option<f64>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NoticeKind {
    /// Nothing can be shown until the steps are done.
    Unavailable,
    /// What's shown is incomplete.
    Limited,
}

/// What's missing on the server and how to turn it on. Fran never runs the steps itself.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityNotice {
    pub kind: NoticeKind,
    pub title: String,
    pub detail: String,
    pub steps: Vec<SetupStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StepLanguage {
    Sql,
    Config,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupStep {
    pub label: String,
    pub code: Option<String>,
    pub language: StepLanguage,
    pub restart: bool,
}

impl SetupStep {
    pub fn sql(label: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            code: Some(code.into()),
            language: StepLanguage::Sql,
            restart: false,
        }
    }

    pub fn config(label: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            code: Some(code.into()),
            language: StepLanguage::Config,
            restart: true,
        }
    }

    pub fn text(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            code: None,
            language: StepLanguage::Config,
            restart: false,
        }
    }
}

impl ActivityNotice {
    pub fn unavailable(title: impl Into<String>, detail: impl Into<String>, steps: Vec<SetupStep>) -> Self {
        Self {
            kind: NoticeKind::Unavailable,
            title: title.into(),
            detail: detail.into(),
            steps,
        }
    }

    pub fn limited(title: impl Into<String>, detail: impl Into<String>, steps: Vec<SetupStep>) -> Self {
        Self {
            kind: NoticeKind::Limited,
            title: title.into(),
            detail: detail.into(),
            steps,
        }
    }
}

impl QueryHistory {
    pub fn unavailable(source: impl Into<String>, notice: ActivityNotice) -> Self {
        Self {
            source: source.into(),
            since: None,
            statements: Vec::new(),
            limited: false,
            notice: Some(notice),
        }
    }
}
