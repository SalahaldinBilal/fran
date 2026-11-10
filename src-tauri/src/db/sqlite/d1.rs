use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::connection::{RawColumn, RawResult, SqlValue, SqliteConnection, SqliteConnector};
use super::session::SqliteSession;
use crate::connections::{SecretBag, SecretSlot};
use crate::daylog::{DAY_MS, day_name, now_ms};
use crate::db::activity::{
    ActivityNotice, ActivitySupport, HISTORY_LIMIT, HistoryOrder, QueryHistory, SetupStep, StatementStats,
};
use crate::db::types::BatchOutcome;
use crate::error::{AppError, AppResult, ErrorDetail};

pub const API_TOKEN_SLOT: &str = "apiToken";
const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const DATABASES_PER_PAGE: usize = 1000;
const INSIGHTS_SOURCE: &str = "Cloudflare D1 query insights for the last 24 hours";
const INSIGHTS_WINDOW_MS: u64 = DAY_MS;

/// The same dataset `wrangler d1 insights` reads.
const INSIGHTS_QUERY: &str = "query D1Insights($accountTag: string, $filter: ZoneWorkersRequestsFilter_InputObject) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      d1QueriesAdaptiveGroups(limit: LIMIT, filter: $filter, orderBy: [ORDER]) {
        sum { queryDurationMs rowsRead rowsReturned }
        avg { queryDurationMs }
        count
        dimensions { query }
      }
    }
  }
}";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct D1Options {
    pub account_id: String,
    /// A database name or its UUID.
    pub database: String,
    pub timeout_secs: u32,
}

impl Default for D1Options {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            database: String::new(),
            timeout_secs: 30,
        }
    }
}

impl D1Options {
    pub fn required_secrets(&self) -> Vec<SecretSlot> {
        vec![SecretSlot::new(API_TOKEN_SLOT, "API token")]
    }

    pub fn optional_secrets(&self) -> Vec<SecretSlot> {
        Vec::new()
    }
}

pub async fn connect(options: &D1Options, secrets: &SecretBag) -> AppResult<SqliteSession> {
    SqliteSession::open(Arc::new(D1Connector::new(options, secrets).await?)).await
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct ApiMessage {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize, Clone)]
struct DatabaseEntry {
    uuid: String,
    name: String,
}

#[derive(Deserialize)]
struct GraphqlResponse {
    data: Option<InsightsData>,
    errors: Option<Vec<ApiMessage>>,
}

#[derive(Deserialize)]
struct InsightsData {
    viewer: InsightsViewer,
}

#[derive(Deserialize)]
struct InsightsViewer {
    #[serde(default)]
    accounts: Vec<InsightsAccount>,
}

#[derive(Deserialize)]
struct InsightsAccount {
    #[serde(rename = "d1QueriesAdaptiveGroups", default)]
    groups: Vec<QueryGroup>,
}

#[derive(Deserialize)]
struct QueryGroup {
    sum: GroupNumbers,
    avg: GroupNumbers,
    count: u64,
    dimensions: GroupDimensions,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupNumbers {
    #[serde(default)]
    query_duration_ms: f64,
    rows_read: Option<f64>,
    rows_returned: Option<f64>,
}

#[derive(Deserialize)]
struct GroupDimensions {
    query: String,
}

/// `2026-11-08T09:30:00Z`
fn iso_time(ms: u64) -> String {
    let seconds = (ms % DAY_MS) / 1000;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        day_name(ms / DAY_MS),
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// D1 keeps no max time, so the view never offers that column and it falls back to the mean.
fn insights_order(order: HistoryOrder) -> &'static str {
    match order {
        HistoryOrder::Calls => "count_DESC",
        HistoryOrder::TotalMs => "sum_queryDurationMs_DESC",
        HistoryOrder::MeanMs | HistoryOrder::MaxMs => "avg_queryDurationMs_DESC",
        HistoryOrder::Rows => "sum_rowsReturned_DESC",
    }
}

fn insights_history(response: GraphqlResponse, database: &str, since: String) -> QueryHistory {
    let errors = response.errors.unwrap_or_default();
    let groups = match response.data {
        Some(data) if errors.is_empty() => data.viewer.accounts.into_iter().flat_map(|account| account.groups),
        _ => {
            let messages = errors.iter().map(|error| error.message.as_str()).collect::<Vec<_>>().join("\n");
            return QueryHistory::unavailable(
                INSIGHTS_SOURCE,
                ActivityNotice::unavailable(
                    "Cloudflare didn't return query insights",
                    format!("{messages}\nReading D1 query insights needs an API token with the Account Analytics Read permission."),
                    vec![SetupStep::text(
                        "In the Cloudflare dashboard, edit this connection's API token and add Account, Account Analytics, Read.",
                    )],
                ),
            );
        }
    };

    let mut statements: Vec<StatementStats> = groups
        .map(|group| StatementStats {
            id: group.dimensions.query.clone(),
            text: group.dimensions.query,
            sample: None,
            database: Some(database.to_string()),
            user: None,
            calls: group.count,
            total_ms: group.sum.query_duration_ms,
            mean_ms: group.avg.query_duration_ms,
            max_ms: None,
            rows: group.sum.rows_returned.map(|rows| rows as u64),
            rows_examined: group.sum.rows_read.map(|rows| rows as u64),
            last_seen: None,
        })
        .collect();
    let limited = statements.len() > HISTORY_LIMIT;
    statements.truncate(HISTORY_LIMIT);

    QueryHistory {
        source: INSIGHTS_SOURCE.to_string(),
        since: Some(since),
        statements,
        limited,
        notice: None,
    }
}

#[derive(Deserialize, Default)]
struct RawEntry {
    results: Option<RawRows>,
    #[serde(default)]
    meta: Meta,
}

#[derive(Deserialize, Default)]
struct RawRows {
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    rows: Vec<Vec<Value>>,
}

#[derive(Deserialize, Default)]
struct Meta {
    #[serde(default)]
    changes: u64,
    #[serde(default)]
    last_row_id: i64,
    duration: Option<f64>,
}

/// D1 wraps SQLite errors as `D1_ERROR: <message>: SQLITE_ERROR`, and only the middle part says anything.
fn clean_message(message: &str) -> String {
    let message = message.trim();
    let message = message.strip_prefix("D1_ERROR: ").unwrap_or(message);
    match message.rsplit_once(": SQLITE_") {
        Some((head, code)) if code.chars().all(|character| character.is_ascii_uppercase() || character == '_') => {
            head.to_string()
        }
        _ => message.to_string(),
    }
}

fn api_error(errors: &[ApiMessage], status: reqwest::StatusCode) -> AppError {
    let Some(first) = errors.first() else {
        return AppError::general(format!("Cloudflare answered with HTTP {status}"));
    };
    let message = errors.iter().map(|error| clean_message(&error.message)).collect::<Vec<_>>().join("\n");
    AppError::new(
        message,
        ErrorDetail::Database {
            code: u16::try_from(first.code).ok(),
            sql_state: None,
        },
    )
}

struct Api {
    client: reqwest::Client,
    token: Zeroizing<String>,
    account_id: String,
}

impl Api {
    fn url(&self, path: &str) -> String {
        format!("{API_BASE}/accounts/{}/d1/database{path}", self.account_id)
    }

    async fn send<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> AppResult<T> {
        let response = request
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .map_err(|error| AppError::general(format!("Couldn't reach Cloudflare: {error}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| AppError::general(format!("Couldn't read Cloudflare's answer: {error}")))?;
        let envelope: Envelope<T> = serde_json::from_str(&body)
            .map_err(|_| AppError::general(format!("Cloudflare answered with HTTP {status}")))?;
        match envelope.result {
            Some(result) if envelope.success => Ok(result),
            _ => Err(api_error(&envelope.errors, status)),
        }
    }

    async fn databases(&self) -> AppResult<Vec<DatabaseEntry>> {
        let mut databases = Vec::new();
        for page in 1.. {
            let request = self.client.get(self.url(&format!("?page={page}&per_page={DATABASES_PER_PAGE}")));
            let found: Vec<DatabaseEntry> = self.send(request).await?;
            let done = found.len() < DATABASES_PER_PAGE;
            databases.extend(found);
            if done {
                break;
            }
        }
        Ok(databases)
    }
}

/// One D1 database in a Cloudflare account, reached over the HTTP API.
pub struct D1Connector {
    api: Arc<Api>,
    database: DatabaseEntry,
}

impl D1Connector {
    async fn new(options: &D1Options, secrets: &SecretBag) -> AppResult<Self> {
        let token = secrets
            .get(API_TOKEN_SLOT)
            .ok_or_else(|| AppError::secrets_required(options.required_secrets()))?;
        let account_id = options.account_id.trim();
        if account_id.is_empty() {
            return Err(AppError::general("Enter the Cloudflare account ID"));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(u64::from(options.timeout_secs.max(1))))
            .build()
            .map_err(|error| AppError::general(error.to_string()))?;
        let api = Arc::new(Api {
            client,
            token: Zeroizing::new(token.to_string()),
            account_id: account_id.to_string(),
        });
        let database = Self::find(&api, options.database.trim()).await?;
        Ok(Self { api, database })
    }

    async fn find(api: &Api, wanted: &str) -> AppResult<DatabaseEntry> {
        if wanted.is_empty() {
            return Err(AppError::general("Enter the D1 database name or ID"));
        }
        api.databases()
            .await?
            .into_iter()
            .find(|database| database.name == wanted || database.uuid.eq_ignore_ascii_case(wanted))
            .ok_or_else(|| AppError::not_found(format!("There's no D1 database called {wanted} in this account")))
    }
}

#[async_trait]
impl SqliteConnector for D1Connector {
    fn product(&self) -> &'static str {
        "Cloudflare D1"
    }

    async fn connect(&self) -> AppResult<Arc<dyn SqliteConnection>> {
        Ok(Arc::new(D1Connection {
            api: self.api.clone(),
            url: self.api.url(&format!("/{}/raw", self.database.uuid)),
        }))
    }

    fn is_internal_table(&self, name: &str) -> bool {
        name.starts_with("sqlite_") || name.starts_with("_cf_")
    }

    fn catalog(&self) -> Option<String> {
        Some(self.database.name.clone())
    }

    async fn list_catalogs(&self) -> AppResult<Vec<String>> {
        let mut names: Vec<String> = self.api.databases().await?.into_iter().map(|database| database.name).collect();
        names.sort();
        Ok(names)
    }

    async fn with_catalog(&self, catalog: &str) -> AppResult<Arc<dyn SqliteConnector>> {
        Ok(Arc::new(Self {
            api: self.api.clone(),
            database: Self::find(&self.api, catalog).await?,
        }))
    }

    fn activity_support(&self) -> ActivitySupport {
        ActivitySupport {
            history: true,
            running: false,
        }
    }

    async fn query_history(&self, order: HistoryOrder) -> AppResult<QueryHistory> {
        let end = now_ms();
        let start = end.saturating_sub(INSIGHTS_WINDOW_MS);
        // One past the limit, to tell whether there were more.
        let query = INSIGHTS_QUERY
            .replace("LIMIT", &(HISTORY_LIMIT + 1).to_string())
            .replace("ORDER", insights_order(order));
        let body = json!({
            "query": query,
            "variables": {
                "accountTag": self.api.account_id,
                "filter": { "AND": [{
                    "datetimeHour_geq": iso_time(start),
                    "datetimeHour_leq": iso_time(end),
                    "databaseId": self.database.uuid,
                }] },
            },
        });
        let response = self
            .api
            .client
            .post(format!("{API_BASE}/graphql"))
            .bearer_auth(self.api.token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|error| AppError::general(format!("Couldn't reach Cloudflare: {error}")))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| AppError::general(format!("Couldn't read Cloudflare's answer: {error}")))?;
        let parsed: GraphqlResponse = serde_json::from_str(&text)
            .map_err(|_| AppError::general(format!("Cloudflare answered with HTTP {status}")))?;
        let since = iso_time(start).replace('T', " ").replace('Z', " UTC");
        Ok(insights_history(parsed, &self.database.name, since))
    }
}

/// Every call is its own HTTP request, so nothing carries over between statements,
/// and BEGIN and COMMIT aren't allowed. A batch request runs as one transaction instead.
struct D1Connection {
    api: Arc<Api>,
    url: String,
}

fn param_text(value: &SqlValue) -> AppResult<String> {
    match value {
        SqlValue::Text(value) => Ok(value.clone()),
        SqlValue::Integer(value) => Ok(value.to_string()),
        SqlValue::Real(value) => Ok(value.to_string()),
        SqlValue::Null | SqlValue::Blob(_) => Err(AppError::general("D1 only takes text parameters")),
    }
}

/// D1 sends blobs as arrays of byte values.
fn sql_value(value: Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Bool(value) => SqlValue::Integer(i64::from(value)),
        Value::Number(number) => match number.as_i64() {
            Some(value) => SqlValue::Integer(value),
            None => SqlValue::Real(number.as_f64().unwrap_or(f64::NAN)),
        },
        Value::String(value) => SqlValue::Text(value),
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> =
                items.iter().map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok())).collect();
            match bytes {
                Some(bytes) => SqlValue::Blob(bytes),
                None => SqlValue::Text(Value::Array(items).to_string()),
            }
        }
        other => SqlValue::Text(other.to_string()),
    }
}

fn is_insert(sql: &str) -> bool {
    let first = sql.split_whitespace().next().unwrap_or_default();
    ["INSERT", "REPLACE"].iter().any(|keyword| first.eq_ignore_ascii_case(keyword))
}

fn raw_result(sql: &str, entry: RawEntry, row_limit: usize) -> RawResult {
    let rows = entry.results.unwrap_or_default();
    let row_limit = if row_limit == 0 { usize::MAX } else { row_limit };
    let truncated = rows.rows.len() > row_limit;
    let changes = entry.meta.changes;
    RawResult {
        columns: rows
            .columns
            .into_iter()
            .map(|name| RawColumn {
                name,
                ..Default::default()
            })
            .collect(),
        rows: rows
            .rows
            .into_iter()
            .take(row_limit)
            .map(|row| row.into_iter().map(sql_value).collect())
            .collect(),
        truncated,
        changes,
        last_insert_id: (changes > 0 && is_insert(sql)).then_some(entry.meta.last_row_id),
        server_ms: entry.meta.duration,
    }
}

#[async_trait]
impl SqliteConnection for D1Connection {
    async fn query(&self, sql: &str, params: &[SqlValue], row_limit: usize) -> AppResult<RawResult> {
        let params = params.iter().map(param_text).collect::<AppResult<Vec<_>>>()?;
        let request = self.api.client.post(&self.url).json(&json!({ "sql": sql, "params": params }));
        let entries: Vec<RawEntry> = self.api.send(request).await?;
        let entry = entries.into_iter().next().unwrap_or_default();
        Ok(raw_result(sql, entry, row_limit))
    }

    /// D1 doesn't say which statement of a batch failed, only that the whole batch rolled back.
    async fn run_batch(&self, statements: &[String], _transactional: bool) -> BatchOutcome {
        let batch: Vec<Value> = statements.iter().map(|sql| json!({ "sql": sql })).collect();
        let request = self.api.client.post(&self.url).json(&json!({ "batch": batch }));
        match self.api.send::<Vec<RawEntry>>(request).await {
            Ok(_) => BatchOutcome {
                executed: statements.len(),
                failed_index: None,
                error: None,
                rolled_back: false,
            },
            Err(error) => BatchOutcome {
                executed: 0,
                failed_index: None,
                error: Some(error),
                rolled_back: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_raw_results() {
        let body = r#"{"success":true,"errors":[],"result":[{"success":true,
            "meta":{"changes":1,"last_row_id":7,"duration":0.25},
            "results":{"columns":["id","name","data","score"],"rows":[[1,"a",[222,173],1.5],[2,null,null,2]]}}]}"#;
        let envelope: Envelope<Vec<RawEntry>> = serde_json::from_str(body).unwrap();
        let entry = envelope.result.unwrap().into_iter().next().unwrap();
        let raw = raw_result("insert into t values (1)", entry, 1);

        assert_eq!(raw.columns.len(), 4);
        assert!(raw.truncated);
        assert_eq!(raw.rows, vec![vec![
            SqlValue::Integer(1),
            SqlValue::Text("a".into()),
            SqlValue::Blob(vec![222, 173]),
            SqlValue::Real(1.5),
        ]]);
        assert_eq!(raw.last_insert_id, Some(7));
        assert_eq!(raw.server_ms, Some(0.25));
    }

    #[test]
    fn only_inserts_report_a_row_id() {
        let entry = RawEntry {
            meta: Meta { changes: 3, last_row_id: 7, duration: None },
            ..Default::default()
        };
        assert_eq!(raw_result("UPDATE t SET a = 1", entry, 10).last_insert_id, None);
    }

    #[test]
    fn reads_query_insights() {
        let body = r#"{"data":{"viewer":{"accounts":[{"d1QueriesAdaptiveGroups":[
            {"sum":{"queryDurationMs":812.5,"rowsRead":40000,"rowsReturned":200},
             "avg":{"queryDurationMs":4.0625,"rowsRead":200,"rowsReturned":1},
             "count":200,"dimensions":{"query":"SELECT * FROM orders WHERE customer = ?"}}
        ]}]}},"errors":null}"#;
        let response: GraphqlResponse = serde_json::from_str(body).unwrap();
        let history = insights_history(response, "shop", "2026-11-07 10:00:00 UTC".to_string());

        assert!(history.notice.is_none());
        let stats = &history.statements[0];
        assert_eq!(stats.text, "SELECT * FROM orders WHERE customer = ?");
        assert_eq!(stats.calls, 200);
        assert_eq!(stats.total_ms, 812.5);
        assert_eq!(stats.mean_ms, 4.0625);
        assert_eq!(stats.rows, Some(200));
        assert_eq!(stats.rows_examined, Some(40000));
        assert_eq!(stats.database.as_deref(), Some("shop"));
    }

    #[test]
    fn a_token_without_analytics_says_what_to_add() {
        let body = r#"{"data":null,"errors":[{"message":"not authorized for that account","path":["viewer","accounts"]}]}"#;
        let response: GraphqlResponse = serde_json::from_str(body).unwrap();
        let history = insights_history(response, "shop", String::new());

        let notice = history.notice.expect("a notice");
        assert!(history.statements.is_empty());
        assert!(notice.detail.contains("not authorized for that account"));
        assert!(notice.detail.contains("Account Analytics"));
    }

    #[test]
    fn filters_by_utc_time() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_time(1_762_597_845_000), "2025-11-08T10:30:45Z");
    }

    #[test]
    fn cleans_error_messages() {
        assert_eq!(clean_message("D1_ERROR: no such table: users: SQLITE_ERROR"), "no such table: users");
        assert_eq!(clean_message("Authentication error"), "Authentication error");
        let body = r#"{"success":false,"errors":[{"code":7500,"message":"D1_ERROR: near \"SELEC\": syntax error: SQLITE_ERROR"}],"result":null}"#;
        let envelope: Envelope<Vec<RawEntry>> = serde_json::from_str(body).unwrap();
        let error = api_error(&envelope.errors, reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "near \"SELEC\": syntax error");
    }
}
