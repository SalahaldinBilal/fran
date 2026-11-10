use super::client::{PgConnection, PgError};
use super::metadata::{flag, name, non_empty, text};
use super::sqlgen::quote_identifier;
use crate::db::activity::{
    ActivityNotice, HISTORY_LIMIT, HistoryOrder, QueryHistory, RunningQueries, RunningQuery, SetupStep, StatementStats,
};

const SOURCE: &str = "pg_stat_statements";
const EXTENSION: &str = "pg_stat_statements";
/// What pg_stat_statements raises when its library wasn't loaded at server start.
const NOT_LOADED: &str = "55000";
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// `1.10` is newer than `1.9`, so versions compare as numbers.
fn extension_version(version: &str) -> (u32, u32) {
    let mut parts = version.split('.').map(|part| part.parse().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
}

fn preload_names(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').map(|name| name.trim().trim_matches('"')).filter(|name| !name.is_empty())
}

/// Null when this login isn't allowed to see the setting.
async fn preload_list(conn: &mut PgConnection) -> Result<Option<String>, PgError> {
    let rows = conn
        .query_text("SELECT setting FROM pg_settings WHERE name = 'shared_preload_libraries'", &[])
        .await?;
    Ok(rows.first().map(|row| name(row, 0)))
}

fn preload_step(current: Option<&str>) -> SetupStep {
    let list = match current {
        Some(current) if preload_names(current).next().is_some() => {
            let mut names: Vec<&str> = preload_names(current).collect();
            names.push(EXTENSION);
            names.join(", ")
        }
        _ => EXTENSION.to_string(),
    };
    let label = match current {
        Some(_) => "Add this to postgresql.conf and restart the server. On a managed service, set it in its parameter settings instead.",
        None => "Add this to postgresql.conf and restart the server, keeping any libraries the list already has. On a managed service, set it in its parameter settings instead.",
    };
    SetupStep::config(label, format!("shared_preload_libraries = '{}'", list.replace('\'', "''")))
}

fn create_step(database: &str) -> SetupStep {
    SetupStep::sql(
        format!("Then create the extension once, as a superuser, in the database {database}"),
        format!("CREATE EXTENSION {EXTENSION};"),
    )
}

fn not_installed(database: &str, preloaded: Option<&str>) -> ActivityNotice {
    let loaded = preloaded.is_some_and(|list| preload_names(list).any(|name| name.eq_ignore_ascii_case(EXTENSION)));
    if loaded {
        return ActivityNotice::unavailable(
            "pg_stat_statements isn't installed in this database",
            format!(
                "The server loads it, but the extension has to be created in {database} before its numbers can be read. It counts statements from every database."
            ),
            vec![SetupStep::sql(
                format!("Run once, as a superuser, in the database {database}"),
                format!("CREATE EXTENSION {EXTENSION};"),
            )],
        );
    }
    ActivityNotice::unavailable(
        "The server isn't keeping a query history",
        "Postgres only keeps statement statistics with the pg_stat_statements extension, and its library has to be loaded when the server starts.",
        vec![preload_step(preloaded), create_step(database)],
    )
}

fn not_loaded(preloaded: Option<&str>) -> ActivityNotice {
    ActivityNotice::unavailable(
        "pg_stat_statements is installed but not loaded",
        "The extension exists in this database, but the server didn't load its library at start, so it has nothing to show.",
        vec![preload_step(preloaded)],
    )
}

async fn current_user(conn: &mut PgConnection) -> Result<String, PgError> {
    let rows = conn.query_text("SELECT current_user", &[]).await?;
    Ok(rows.first().map(|row| name(row, 0)).unwrap_or_default())
}

/// Superusers and members of pg_read_all_stats see every login's statements.
async fn reads_all_stats(conn: &mut PgConnection, major_version: u32) -> Result<bool, PgError> {
    let sql = if major_version >= 10 {
        "SELECT rolsuper OR pg_has_role(current_user, 'pg_read_all_stats', 'USAGE') FROM pg_roles WHERE rolname = current_user"
    } else {
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
    };
    let rows = conn.query_text(sql, &[]).await?;
    Ok(rows.first().is_some_and(|row| flag(row, 0)))
}

async fn hidden_notice(
    conn: &mut PgConnection,
    major_version: u32,
    title: &str,
    detail: &str,
) -> Result<Option<ActivityNotice>, PgError> {
    if reads_all_stats(conn, major_version).await? {
        return Ok(None);
    }
    let user = current_user(conn).await?;
    let steps = if major_version >= 10 {
        vec![SetupStep::sql("Run as a superuser", format!("GRANT pg_read_all_stats TO {};", quote_identifier(&user)))]
    } else {
        vec![SetupStep::text("Before Postgres 10, only a superuser sees other logins' statements.")]
    };
    Ok(Some(ActivityNotice::limited(title, detail, steps)))
}

pub async fn query_history(
    conn: &mut PgConnection,
    database: &str,
    major_version: u32,
    order: HistoryOrder,
) -> Result<QueryHistory, PgError> {
    let extension = conn
        .query_text(
            "SELECT n.nspname, e.extversion FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace \
             WHERE e.extname = 'pg_stat_statements'",
            &[],
        )
        .await?;
    let Some(row) = extension.first() else {
        let preloaded = preload_list(conn).await?;
        return Ok(QueryHistory::unavailable(SOURCE, not_installed(database, preloaded.as_deref())));
    };

    let view_schema = quote_identifier(&name(row, 0));
    let version = extension_version(&name(row, 1));
    // The times were renamed in 1.8, which came with Postgres 13. An upgraded server can still have an older extension.
    let (total, mean, max) = if version >= (1, 8) {
        ("total_exec_time", "mean_exec_time", "max_exec_time")
    } else {
        ("total_time", "mean_time", "max_time")
    };
    let order_by = match order {
        HistoryOrder::Calls => "calls",
        HistoryOrder::TotalMs => total,
        HistoryOrder::MeanMs => mean,
        HistoryOrder::MaxMs => max,
        HistoryOrder::Rows => "rows",
    };
    // One past the limit, to tell whether there were more.
    let sql = format!(
        "SELECT s.dbid::text, s.userid::text, s.queryid::text, d.datname, r.rolname, s.query, s.calls, \
         s.{total}, s.{mean}, s.{max}, s.rows \
         FROM {view_schema}.pg_stat_statements s \
         LEFT JOIN pg_database d ON d.oid = s.dbid \
         LEFT JOIN pg_roles r ON r.oid = s.userid \
         ORDER BY s.{order_by} DESC LIMIT {}",
        HISTORY_LIMIT + 1
    );
    let rows = match conn.query_text(&sql, &[]).await {
        Ok(rows) => rows,
        Err(PgError::Server(report)) if report.code == NOT_LOADED => {
            let preloaded = preload_list(conn).await?;
            return Ok(QueryHistory::unavailable(SOURCE, not_loaded(preloaded.as_deref())));
        }
        Err(PgError::Server(report)) if report.code == INSUFFICIENT_PRIVILEGE => {
            let user = current_user(conn).await?;
            return Ok(QueryHistory::unavailable(
                SOURCE,
                ActivityNotice::unavailable(
                    "This login can't read pg_stat_statements",
                    "The extension is there, but reading its view was refused.",
                    vec![SetupStep::sql(
                        "Run as a superuser",
                        format!("GRANT SELECT ON {view_schema}.pg_stat_statements TO {};", quote_identifier(&user)),
                    )],
                ),
            ));
        }
        Err(error) => return Err(error),
    };

    let since = if version >= (1, 9) {
        let info = conn
            .query_text(&format!("SELECT stats_reset::text FROM {view_schema}.pg_stat_statements_info"), &[])
            .await?;
        info.first().and_then(|row| text(row, 0))
    } else {
        None
    };

    let limited = rows.len() > HISTORY_LIMIT;
    let statements = rows
        .iter()
        .take(HISTORY_LIMIT)
        .enumerate()
        .map(|(index, row)| {
            let query_id = text(row, 2).unwrap_or_else(|| format!("row{index}"));
            StatementStats {
                id: format!("{}:{}:{query_id}", name(row, 0), name(row, 1)),
                text: name(row, 5),
                sample: None,
                database: non_empty(text(row, 3)),
                user: non_empty(text(row, 4)),
                calls: text(row, 6).and_then(|value| value.parse().ok()).unwrap_or(0),
                total_ms: text(row, 7).and_then(|value| value.parse().ok()).unwrap_or(0.0),
                mean_ms: text(row, 8).and_then(|value| value.parse().ok()).unwrap_or(0.0),
                max_ms: text(row, 9).and_then(|value| value.parse().ok()),
                rows: text(row, 10).and_then(|value| value.parse().ok()),
                rows_examined: None,
                last_seen: None,
            }
        })
        .collect();

    let notice = hidden_notice(
        conn,
        major_version,
        "Other logins' statements are hidden",
        "Statements run by other logins are counted, but their text shows as <insufficient privilege> without pg_read_all_stats.",
    )
    .await?;

    Ok(QueryHistory {
        source: SOURCE.to_string(),
        since,
        statements,
        limited,
        notice,
    })
}

fn describe_state(state: Option<String>, wait_type: Option<String>, wait_event: Option<String>) -> Option<String> {
    match (state, wait_type, wait_event) {
        (Some(state), Some(wait_type), Some(wait_event)) => Some(format!("{state}, waiting on {wait_type}: {wait_event}")),
        (state, _, _) => state,
    }
}

pub async fn running_queries(conn: &mut PgConnection, major_version: u32) -> Result<RunningQueries, PgError> {
    let (waits, client_backends) = if major_version >= 10 {
        ("wait_event_type, wait_event", "AND backend_type = 'client backend'")
    } else {
        ("NULL, NULL", "")
    };
    // An idle transaction has been idle since its state changed, not since its last query started.
    let sql = format!(
        "SELECT pid::text, usename, datname, COALESCE(host(client_addr), client_hostname), state, {waits}, \
         EXTRACT(EPOCH FROM clock_timestamp() - CASE WHEN state = 'active' THEN query_start ELSE state_change END) * 1000, \
         query \
         FROM pg_stat_activity \
         WHERE state <> 'idle' AND pid <> pg_backend_pid() {client_backends} \
         ORDER BY query_start"
    );
    let rows = conn.query_text(&sql, &[]).await?;
    let queries = rows
        .iter()
        .map(|row| RunningQuery {
            id: name(row, 0),
            user: non_empty(text(row, 1)),
            database: non_empty(text(row, 2)),
            client: non_empty(text(row, 3)),
            state: describe_state(non_empty(text(row, 4)), non_empty(text(row, 5)), non_empty(text(row, 6))),
            running_ms: text(row, 7).and_then(|value| value.parse().ok()),
            text: non_empty(text(row, 8)),
        })
        .collect();

    let notice = hidden_notice(
        conn,
        major_version,
        "Other logins' queries are hidden",
        "Without pg_read_all_stats, Postgres only shows what this login's own sessions are running.",
    )
    .await?;

    Ok(RunningQueries {
        queries,
        whole_seconds: false,
        notice,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_extension_versions_compare_as_numbers() {
        assert!(extension_version("1.10") >= (1, 9));
        assert!(extension_version("1.11") >= (1, 8));
        assert!(extension_version("1.7") < (1, 8));
    }

    #[test]
    fn keeps_libraries_already_preloaded() {
        let step = preload_step(Some("auto_explain, \"pg_cron\""));
        assert_eq!(
            step.code.as_deref(),
            Some("shared_preload_libraries = 'auto_explain, pg_cron, pg_stat_statements'")
        );
        assert!(step.restart);
    }

    #[test]
    fn only_asks_for_the_extension_when_the_library_is_loaded() {
        let loaded = not_installed("shop", Some("pg_stat_statements"));
        assert_eq!(loaded.steps.len(), 1);
        assert!(!loaded.steps[0].restart);

        let unknown = not_installed("shop", None);
        assert_eq!(unknown.steps.len(), 2);
        assert!(unknown.steps[0].restart);
    }
}
