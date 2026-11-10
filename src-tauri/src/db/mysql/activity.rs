use std::collections::HashMap;

use mysql_async::{Conn, Row, prelude::Queryable};

use super::metadata::{name, non_empty, number, text};
use super::sqlgen::Dialect;
use crate::db::activity::{
    ActivityNotice, HISTORY_LIMIT, HistoryOrder, QueryHistory, RunningQueries, RunningQuery, SetupStep, StatementStats,
};

const DIGEST_SOURCE: &str = "performance_schema statement digests";
const SLOW_LOG_SOURCE: &str = "the slow query log (mysql.slow_log)";
const PICOSECONDS_PER_MS: f64 = 1e9;
const SLOW_LOG_ROWS: usize = 5000;
/// Access denied to a database (1044) or a table (1142).
const ACCESS_DENIED: [u16; 2] = [1044, 1142];

fn denied(error: &mysql_async::Error) -> bool {
    matches!(error, mysql_async::Error::Server(server) if ACCESS_DENIED.contains(&server.code))
}

/// `CURRENT_USER()` gives `user@host`, GRANT wants `'user'@'host'`.
fn account_literal(dialect: Dialect, current: &str) -> String {
    let (user, host) = current.rsplit_once('@').unwrap_or((current, "%"));
    format!("{}@{}", dialect.string_literal(user), dialect.string_literal(host))
}

async fn account(conn: &mut Conn, dialect: Dialect) -> Result<String, mysql_async::Error> {
    let rows: Vec<Row> = conn.query("SELECT CURRENT_USER()").await?;
    Ok(account_literal(dialect, &rows.first().map(|row| name(row, 0)).unwrap_or_default()))
}

fn major_version(version: &str) -> u32 {
    version
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or(0)
}

pub async fn query_history(
    conn: &mut Conn,
    dialect: Dialect,
    mariadb: bool,
    version: &str,
    order: HistoryOrder,
) -> Result<QueryHistory, mysql_async::Error> {
    let rows: Vec<Row> = conn.query("SELECT @@performance_schema").await?;
    if rows.first().and_then(|row| number(row, 0)) == Some(1) {
        digest_history(conn, dialect, mariadb, version, order).await
    } else {
        slow_log_history(conn, dialect, mariadb, order).await
    }
}

fn digest_order(order: HistoryOrder) -> &'static str {
    match order {
        HistoryOrder::Calls => "COUNT_STAR",
        HistoryOrder::TotalMs => "SUM_TIMER_WAIT",
        HistoryOrder::MeanMs => "AVG_TIMER_WAIT",
        HistoryOrder::MaxMs => "MAX_TIMER_WAIT",
        HistoryOrder::Rows => "SUM_ROWS_SENT",
    }
}

async fn digest_denied(conn: &mut Conn, dialect: Dialect) -> Result<QueryHistory, mysql_async::Error> {
    let account = account(conn, dialect).await?;
    Ok(QueryHistory::unavailable(
        DIGEST_SOURCE,
        ActivityNotice::unavailable(
            "This login can't read performance_schema",
            "The server keeps statement digests, but reading them needs SELECT on performance_schema.",
            vec![SetupStep::sql("Run as an admin", format!("GRANT SELECT ON performance_schema.* TO {account};"))],
        ),
    ))
}

fn consumers_off(off: &[String]) -> ActivityNotice {
    let names = off.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ");
    let config = off
        .iter()
        .map(|name| format!("performance-schema-consumer-{}=ON", name.replace('_', "-")))
        .collect::<Vec<_>>()
        .join("\n");
    ActivityNotice::unavailable(
        "Statement digests are switched off",
        "performance_schema is on, but it isn't collecting statement digests. Once they're on, counting starts from that moment.",
        vec![
            SetupStep::sql(
                "Turn them on now (needs UPDATE on performance_schema). This lasts until the server restarts.",
                format!("UPDATE performance_schema.setup_consumers SET ENABLED = 'YES' WHERE NAME IN ({names});"),
            ),
            SetupStep::config("To keep them on after a restart, add this to the [mysqld] section of my.cnf", config),
        ],
    )
}

fn picoseconds_to_ms(row: &Row, index: usize) -> f64 {
    text(row, index).and_then(|value| value.parse::<f64>().ok()).unwrap_or(0.0) / PICOSECONDS_PER_MS
}

async fn digest_history(
    conn: &mut Conn,
    dialect: Dialect,
    mariadb: bool,
    version: &str,
    order: HistoryOrder,
) -> Result<QueryHistory, mysql_async::Error> {
    let consumers: Vec<Row> = match conn
        .query(
            "SELECT NAME, ENABLED FROM performance_schema.setup_consumers \
             WHERE NAME IN ('global_instrumentation', 'statements_digest')",
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) if denied(&error) => return digest_denied(conn, dialect).await,
        Err(error) => return Err(error),
    };
    let off: Vec<String> = consumers
        .iter()
        .filter(|row| !text(row, 1).is_some_and(|enabled| enabled.eq_ignore_ascii_case("YES")))
        .map(|row| name(row, 0))
        .collect();
    if !off.is_empty() {
        return Ok(QueryHistory::unavailable(DIGEST_SOURCE, consumers_off(&off)));
    }

    // MariaDB and MySQL before 8.0 keep no sample of the real statement.
    let sample = if !mariadb && major_version(version) >= 8 { "QUERY_SAMPLE_TEXT" } else { "NULL" };
    // One past the limit, to tell whether there were more.
    let sql = format!(
        "SELECT DIGEST, SCHEMA_NAME, DIGEST_TEXT, {sample}, COUNT_STAR, SUM_TIMER_WAIT, AVG_TIMER_WAIT, MAX_TIMER_WAIT, \
         SUM_ROWS_SENT, SUM_ROWS_EXAMINED, LAST_SEEN \
         FROM performance_schema.events_statements_summary_by_digest \
         WHERE DIGEST_TEXT IS NOT NULL ORDER BY {} DESC LIMIT {}",
        digest_order(order),
        HISTORY_LIMIT + 1
    );
    let rows: Vec<Row> = match conn.query(sql).await {
        Ok(rows) => rows,
        Err(error) if denied(&error) => return digest_denied(conn, dialect).await,
        Err(error) => return Err(error),
    };
    let first_seen: Vec<Row> = conn
        .query("SELECT MIN(FIRST_SEEN) FROM performance_schema.events_statements_summary_by_digest")
        .await?;

    let limited = rows.len() > HISTORY_LIMIT;
    let statements = rows
        .iter()
        .take(HISTORY_LIMIT)
        .map(|row| {
            let database = non_empty(text(row, 1));
            StatementStats {
                id: format!("{}:{}", database.as_deref().unwrap_or_default(), name(row, 0)),
                text: name(row, 2),
                sample: non_empty(text(row, 3)),
                database,
                user: None,
                calls: number(row, 4).unwrap_or(0),
                total_ms: picoseconds_to_ms(row, 5),
                mean_ms: picoseconds_to_ms(row, 6),
                max_ms: Some(picoseconds_to_ms(row, 7)),
                rows: number(row, 8),
                rows_examined: number(row, 9),
                last_seen: text(row, 10),
            }
        })
        .collect();

    Ok(QueryHistory {
        source: DIGEST_SOURCE.to_string(),
        since: first_seen.first().and_then(|row| text(row, 0)),
        statements,
        limited,
        notice: None,
    })
}

fn history_off(mariadb: bool, log_output: &str) -> ActivityNotice {
    let output = if log_output.split(',').any(|part| part.trim() == "FILE") { "FILE,TABLE" } else { "TABLE" };
    let detail = if mariadb {
        "performance_schema is off, which is MariaDB's default, and the slow query log isn't written to a table."
    } else {
        "performance_schema is off, and the slow query log isn't written to a table."
    };
    ActivityNotice::unavailable(
        "The server isn't keeping a query history",
        detail,
        vec![
            SetupStep::config(
                "Turn on performance_schema in the [mysqld] section of my.cnf. This counts every statement.",
                "performance_schema=ON",
            ),
            SetupStep::sql(
                "Or log slow statements to a table without a restart (needs SUPER or SYSTEM_VARIABLES_ADMIN). \
                 This only catches statements that take a second or more, and lasts until the server restarts.",
                format!("SET GLOBAL log_output = '{output}';\nSET GLOBAL slow_query_log = ON;\nSET GLOBAL long_query_time = 1;"),
            ),
        ],
    )
}

async fn slow_log_history(
    conn: &mut Conn,
    dialect: Dialect,
    mariadb: bool,
    order: HistoryOrder,
) -> Result<QueryHistory, mysql_async::Error> {
    let settings: Vec<Row> = conn.query("SELECT @@slow_query_log, @@log_output, @@long_query_time").await?;
    let settings = settings.first();
    let logging = settings.and_then(|row| number(row, 0)) == Some(1);
    let log_output = settings.and_then(|row| text(row, 1)).unwrap_or_default().to_ascii_uppercase();
    let long_query_time = settings.and_then(|row| text(row, 2)).unwrap_or_default();
    if !logging || !log_output.split(',').any(|part| part.trim() == "TABLE") {
        return Ok(QueryHistory::unavailable(SLOW_LOG_SOURCE, history_off(mariadb, &log_output)));
    }

    let sql = format!(
        "SELECT start_time, user_host, query_time, rows_sent, rows_examined, db, sql_text \
         FROM mysql.slow_log ORDER BY start_time DESC LIMIT {SLOW_LOG_ROWS}"
    );
    let rows: Vec<Row> = match conn.query(sql).await {
        Ok(rows) => rows,
        Err(error) if denied(&error) => {
            let account = account(conn, dialect).await?;
            return Ok(QueryHistory::unavailable(
                SLOW_LOG_SOURCE,
                ActivityNotice::unavailable(
                    "This login can't read the slow query log",
                    "Slow statements are logged to mysql.slow_log, but reading it needs SELECT on that table.",
                    vec![SetupStep::sql("Run as an admin", format!("GRANT SELECT ON mysql.slow_log TO {account};"))],
                ),
            ));
        }
        Err(error) => return Err(error),
    };

    let entries: Vec<SlowLogEntry> = rows
        .iter()
        .map(|row| SlowLogEntry {
            started: name(row, 0),
            user: text(row, 1).map(|user_host| slow_log_user(&user_host)),
            query_ms: text(row, 2).and_then(|time| time_ms(&time)).unwrap_or(0.0),
            rows_sent: number(row, 3).unwrap_or(0),
            rows_examined: number(row, 4).unwrap_or(0),
            database: non_empty(text(row, 5)),
            sql: name(row, 6),
        })
        .collect();

    let mut detail = format!(
        "performance_schema is off, so this comes from the slow query log, which only has statements that took longer than long_query_time ({}s).",
        trim_seconds(&long_query_time)
    );
    if entries.len() == SLOW_LOG_ROWS {
        detail.push_str(&format!(" Only the latest {SLOW_LOG_ROWS} entries are read."));
    }

    let (statements, limited) = group_slow_log(&entries, !dialect.no_backslash_escapes, order);
    Ok(QueryHistory {
        source: SLOW_LOG_SOURCE.to_string(),
        since: entries.last().map(|entry| entry.started.clone()),
        statements,
        limited,
        notice: Some(ActivityNotice::limited(
            "Only slow statements are counted",
            detail,
            vec![SetupStep::config(
                "To count every statement, turn on performance_schema in the [mysqld] section of my.cnf",
                "performance_schema=ON",
            )],
        )),
    })
}

/// `10.000000` reads better as `10`.
fn trim_seconds(value: &str) -> &str {
    if value.contains('.') { value.trim_end_matches('0').trim_end_matches('.') } else { value }
}

/// `app[app] @ web-1 [10.0.0.5]` is the user `app`.
fn slow_log_user(user_host: &str) -> String {
    user_host.split('[').next().unwrap_or_default().trim().to_string()
}

/// A TIME value like `00:00:02.500123`.
fn time_ms(time: &str) -> Option<f64> {
    let mut parts = time.trim().splitn(3, ':');
    let hours: f64 = parts.next()?.parse().ok()?;
    let minutes: f64 = parts.next()?.parse().ok()?;
    let seconds: f64 = parts.next()?.parse().ok()?;
    Some(((hours * 60.0 + minutes) * 60.0 + seconds) * 1000.0)
}

struct SlowLogEntry {
    started: String,
    user: Option<String>,
    query_ms: f64,
    rows_sent: u64,
    rows_examined: u64,
    database: Option<String>,
    sql: String,
}

fn order_value(stats: &StatementStats, order: HistoryOrder) -> f64 {
    match order {
        HistoryOrder::Calls => stats.calls as f64,
        HistoryOrder::TotalMs => stats.total_ms,
        HistoryOrder::MeanMs => stats.mean_ms,
        HistoryOrder::MaxMs => stats.max_ms.unwrap_or(0.0),
        HistoryOrder::Rows => stats.rows.unwrap_or(0) as f64,
    }
}

/// Entries come newest first, so the first one seen of each shape is its latest run.
/// Also says whether there were more shapes than `HISTORY_LIMIT`.
fn group_slow_log(entries: &[SlowLogEntry], backslash_escapes: bool, order: HistoryOrder) -> (Vec<StatementStats>, bool) {
    let mut groups: HashMap<(Option<String>, String), StatementStats> = HashMap::new();
    for entry in entries {
        let text = normalize(&entry.sql, backslash_escapes);
        let stats = groups.entry((entry.database.clone(), text.clone())).or_insert_with(|| StatementStats {
            id: format!("{}:{text}", entry.database.as_deref().unwrap_or_default()),
            text,
            sample: Some(entry.sql.clone()),
            database: entry.database.clone(),
            user: entry.user.clone(),
            calls: 0,
            total_ms: 0.0,
            mean_ms: 0.0,
            max_ms: Some(0.0),
            rows: Some(0),
            rows_examined: Some(0),
            last_seen: Some(entry.started.clone()),
        });
        stats.calls += 1;
        stats.total_ms += entry.query_ms;
        stats.max_ms = stats.max_ms.map(|max| max.max(entry.query_ms));
        stats.rows = stats.rows.map(|rows| rows + entry.rows_sent);
        stats.rows_examined = stats.rows_examined.map(|rows| rows + entry.rows_examined);
        if stats.user.as_ref() != entry.user.as_ref() {
            stats.user = None;
        }
    }

    let mut statements: Vec<StatementStats> = groups
        .into_values()
        .map(|mut stats| {
            stats.mean_ms = stats.total_ms / stats.calls as f64;
            stats
        })
        .collect();
    statements.sort_by(|a, b| order_value(b, order).total_cmp(&order_value(a, order)));
    let limited = statements.len() > HISTORY_LIMIT;
    statements.truncate(HISTORY_LIMIT);
    (statements, limited)
}

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_' || character == '$'
}

/// Index just past the closing quote. A doubled quote stays inside.
fn skip_quoted(chars: &[char], start: usize, quote: char, backslash_escapes: bool) -> usize {
    let mut index = start + 1;
    while index < chars.len() {
        let character = chars[index];
        if character == '\\' && backslash_escapes && quote != '`' {
            index += 2;
        } else if character == quote {
            if chars.get(index + 1) == Some(&quote) {
                index += 2;
            } else {
                return index + 1;
            }
        } else {
            index += 1;
        }
    }
    chars.len()
}

fn is_number(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|character| character.is_ascii_hexdigit());
    }
    if let Some(bits) = lower.strip_prefix("0b") {
        return !bits.is_empty() && bits.chars().all(|character| character == '0' || character == '1');
    }
    lower.parse::<f64>().is_ok()
}

/// String prefixes that make the quoted text after them a literal: X'..', B'..', N'..', _utf8mb4'..'.
fn is_literal_prefix(word: &str) -> bool {
    matches!(word.to_ascii_lowercase().as_str(), "x" | "b" | "n") || word.starts_with('_')
}

fn tokens(sql: &str, backslash_escapes: bool) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < chars.len() {
        let character = chars[index];
        let next = chars.get(index + 1).copied();

        if character.is_whitespace() {
            index += 1;
        } else if character == '#' || (character == '-' && next == Some('-') && chars.get(index + 2).is_none_or(|after| after.is_whitespace())) {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
        } else if character == '/' && next == Some('*') {
            let start = index;
            index += 2;
            while index < chars.len() && !(chars[index] == '*' && chars.get(index + 1) == Some(&'/')) {
                index += 1;
            }
            index = (index + 2).min(chars.len());
            // `/*! ... */` runs on MySQL, so it's part of the statement.
            if chars.get(start + 2) == Some(&'!') {
                tokens.push(chars[start..index].iter().collect());
            }
        } else if character == '\'' || character == '"' {
            index = skip_quoted(&chars, index, character, backslash_escapes);
            tokens.push("?".to_string());
        } else if character == '`' {
            let end = skip_quoted(&chars, index, '`', false);
            tokens.push(chars[index..end].iter().collect());
            index = end;
        } else if character.is_ascii_digit() || (character == '.' && next.is_some_and(|after| after.is_ascii_digit())) {
            let start = index;
            while index < chars.len() {
                let current = chars[index];
                let exponent_sign = (current == '+' || current == '-')
                    && matches!(chars[index - 1], 'e' | 'E')
                    && chars[start..index - 1].iter().all(|digit| digit.is_ascii_digit() || *digit == '.');
                if is_word(current) || current == '.' || exponent_sign {
                    index += 1;
                } else {
                    break;
                }
            }
            let token: String = chars[start..index].iter().collect();
            tokens.push(if is_number(&token) { "?".to_string() } else { token });
        } else if is_word(character) {
            let start = index;
            while index < chars.len() && is_word(chars[index]) {
                index += 1;
            }
            let word: String = chars[start..index].iter().collect();
            if chars.get(index) == Some(&'\'') && is_literal_prefix(&word) {
                index = skip_quoted(&chars, index, '\'', backslash_escapes);
                tokens.push("?".to_string());
            } else {
                tokens.push(word);
            }
        } else if matches!(character, '(' | ')' | ',' | '.' | ';') {
            tokens.push(character.to_string());
            index += 1;
        } else {
            let start = index;
            while index < chars.len() {
                let current = chars[index];
                if current.is_whitespace() || is_word(current) || matches!(current, '(' | ')' | ',' | '.' | ';' | '\'' | '"' | '`') {
                    break;
                }
                index += 1;
            }
            tokens.push(chars[start..index].iter().collect());
        }
    }
    tokens
}

/// Lists of values like `IN (1, 2, 3)` or the rows of an INSERT become one `(...)`, so their length doesn't matter.
fn collapse_lists(tokens: Vec<String>) -> Vec<String> {
    let mut collapsed: Vec<String> = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] == "(" {
            let mut end = index + 1;
            let mut values = 0;
            while end < tokens.len() && (tokens[end] == "?" || tokens[end] == ",") {
                values += usize::from(tokens[end] == "?");
                end += 1;
            }
            if values > 0 && tokens.get(end).is_some_and(|token| token == ")") {
                let repeated_row = collapsed.len() >= 2 && collapsed[collapsed.len() - 1] == "," && collapsed[collapsed.len() - 2] == "(...)";
                if repeated_row {
                    collapsed.pop();
                } else {
                    collapsed.push("(...)".to_string());
                }
                index = end + 1;
                continue;
            }
        }
        collapsed.push(tokens[index].clone());
        index += 1;
    }
    collapsed
}

/// The statement's shape, with literal values replaced by `?`, comments dropped and spacing made even.
pub fn normalize(sql: &str, backslash_escapes: bool) -> String {
    let mut text = String::with_capacity(sql.len());
    let mut previous: Option<&str> = None;
    let tokens = collapse_lists(tokens(sql, backslash_escapes));
    for token in &tokens {
        let tight = matches!(token.as_str(), ")" | "," | "." | ";") || matches!(previous, Some("(" | "."));
        if previous.is_some() && !tight {
            text.push(' ');
        }
        text.push_str(token);
        previous = Some(token);
    }
    text.trim_end_matches(';').trim_end().to_string()
}

pub async fn running_queries(conn: &mut Conn, dialect: Dialect, mariadb: bool) -> Result<RunningQueries, mysql_async::Error> {
    // MySQL's TIME is whole seconds, MariaDB also has milliseconds.
    let time = if mariadb { "TIME_MS" } else { "TIME * 1000" };
    let sql = format!(
        "SELECT ID, USER, HOST, DB, STATE, {time}, INFO, COMMAND FROM information_schema.PROCESSLIST \
         WHERE COMMAND NOT IN ('Sleep', 'Daemon', 'Binlog Dump', 'Binlog Dump GTID') AND ID <> CONNECTION_ID() \
         ORDER BY TIME DESC"
    );
    let rows: Vec<Row> = conn.query(sql).await?;
    let queries = rows
        .iter()
        .map(|row| RunningQuery {
            id: name(row, 0),
            user: non_empty(text(row, 1)),
            client: non_empty(text(row, 2)),
            database: non_empty(text(row, 3)),
            state: non_empty(text(row, 4)).or_else(|| non_empty(text(row, 7))),
            running_ms: text(row, 5).and_then(|value| value.parse().ok()),
            text: non_empty(text(row, 6)),
        })
        .collect();

    let account = account(conn, dialect).await?;
    let process: Vec<Row> = conn
        .exec(
            "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'PROCESS' AND GRANTEE = ?",
            (account.clone(),),
        )
        .await?;
    let notice = (process.first().and_then(|row| number(row, 0)) == Some(0)).then(|| {
        ActivityNotice::limited(
            "Other users' queries may be missing",
            "Without the PROCESS privilege the server only lists this login's own sessions. A PROCESS privilege that comes from a role isn't detected here.",
            vec![SetupStep::sql("Run as an admin", format!("GRANT PROCESS ON *.* TO {account};"))],
        )
    });

    Ok(RunningQueries {
        queries,
        whole_seconds: !mariadb,
        notice,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_that_differ_only_in_values_and_spacing_share_a_shape() {
        let a = normalize("SELECT * FROM users WHERE email='a@b.com' AND id IN (1,2,3)", true);
        let b = normalize("SELECT *  FROM users\n  WHERE email = 'x@y.org' AND id IN (42);", true);
        assert_eq!(a, "SELECT * FROM users WHERE email = ? AND id IN (...)");
        assert_eq!(a, b);
    }

    #[test]
    fn escaped_quotes_stay_inside_their_string() {
        assert_eq!(
            normalize(r"SELECT id FROM t WHERE name = 'it\'s' OR name = 'o''neil'", true),
            "SELECT id FROM t WHERE name = ? OR name = ?"
        );
        assert_eq!(
            normalize(r"SELECT id FROM t WHERE path = 'C:\' AND x = 1", false),
            "SELECT id FROM t WHERE path = ? AND x = ?"
        );
    }

    #[test]
    fn identifiers_keep_their_digits() {
        assert_eq!(
            normalize("SELECT `col 1`, t2.c3 FROM t2 WHERE x = 0x1F AND y = -1.5e-3 AND z = X'ab'", true),
            "SELECT `col 1`, t2.c3 FROM t2 WHERE x = ? AND y = - ? AND z = ?"
        );
    }

    #[test]
    fn inserts_with_any_number_of_rows_share_a_shape() {
        let many = normalize("INSERT INTO t (a, b) VALUES (1, 'x'), (2, 'y'), (3, 'z')", true);
        let one = normalize("INSERT INTO t (a, b) VALUES (7, 'q')", true);
        assert_eq!(many, "INSERT INTO t (a, b) VALUES (...)");
        assert_eq!(many, one);
    }

    #[test]
    fn comments_are_dropped_but_executable_ones_kept() {
        assert_eq!(normalize("/* app:checkout */ SELECT 1 -- trailing\n", true), "SELECT ?");
        assert_eq!(normalize("# note\nSELECT 2", true), "SELECT ?");
        assert_eq!(normalize("SELECT /*!40001 SQL_NO_CACHE */ 3", true), "SELECT /*!40001 SQL_NO_CACHE */ ?");
    }

    #[test]
    fn slow_log_groups_by_shape_and_database() {
        let entry = |sql: &str, database: Option<&str>, ms: f64, started: &str| SlowLogEntry {
            started: started.to_string(),
            user: Some("app".to_string()),
            query_ms: ms,
            rows_sent: 1,
            rows_examined: 10,
            database: database.map(str::to_string),
            sql: sql.to_string(),
        };
        let entries = [
            entry("SELECT * FROM orders WHERE id = 3", Some("shop"), 3000.0, "2026-11-08 10:00:03"),
            entry("SELECT * FROM orders WHERE id = 1", Some("shop"), 1000.0, "2026-11-08 10:00:01"),
            entry("SELECT * FROM orders WHERE id = 2", Some("staging"), 5000.0, "2026-11-08 10:00:02"),
        ];
        let (stats, limited) = group_slow_log(&entries, true, HistoryOrder::MeanMs);

        assert!(!limited);
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].database.as_deref(), Some("staging"));
        let (by_calls, _) = group_slow_log(&entries, true, HistoryOrder::Calls);
        assert_eq!(by_calls[0].database.as_deref(), Some("shop"));
        let shop = &stats[1];
        assert_eq!(shop.calls, 2);
        assert_eq!(shop.total_ms, 4000.0);
        assert_eq!(shop.mean_ms, 2000.0);
        assert_eq!(shop.max_ms, Some(3000.0));
        assert_eq!(shop.rows_examined, Some(20));
        assert_eq!(shop.sample.as_deref(), Some("SELECT * FROM orders WHERE id = 3"));
        assert_eq!(shop.last_seen.as_deref(), Some("2026-11-08 10:00:03"));
    }

    #[test]
    fn reads_slow_log_fields() {
        assert_eq!(time_ms("00:00:02.500000"), Some(2500.0));
        assert_eq!(time_ms("01:02:03"), Some(3_723_000.0));
        assert_eq!(slow_log_user("app[app] @ web-1 [10.0.0.5]"), "app");
        assert_eq!(trim_seconds("10.000000"), "10");
        assert_eq!(trim_seconds("0.500000"), "0.5");
    }

    #[test]
    fn grant_targets_the_current_account() {
        assert_eq!(account_literal(Dialect::default(), "app@10.0.%"), "'app'@'10.0.%'");
        assert_eq!(account_literal(Dialect::default(), "ops@corp@localhost"), "'ops@corp'@'localhost'");
    }
}
