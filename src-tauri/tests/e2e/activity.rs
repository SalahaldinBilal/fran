use std::time::Duration;

use fran_lib::db::activity::{HistoryOrder, NoticeKind};
use fran_lib::db::session::ContextAccess;

use crate::servers::Flavor;
use crate::support::{Case, Ctx, TestResult, cases};

pub fn all() -> Vec<Case> {
    [
        cases![None;
            history_counts_statements_from_other_connections,
            lists_queries_running_on_other_connections,
        ],
        cases![Some(Flavor::Postgres);
            history_says_how_to_create_the_extension,
        ],
    ]
    .concat()
}

/// The Postgres container preloads pg_stat_statements. The extension itself is the test's setup, not Fran's.
async fn ensure_statement_stats(ctx: &Ctx) -> TestResult {
    if ctx.flavor() == Flavor::Postgres {
        ctx.run_fresh("CREATE EXTENSION IF NOT EXISTS pg_stat_statements").await?;
    }
    Ok(())
}

async fn history_counts_statements_from_other_connections(ctx: &Ctx) -> TestResult {
    ensure_statement_stats(ctx).await?;
    let table = ctx.pick(format!("`{}`.items", ctx.ns), format!("\"{}\".items", ctx.ns));
    for price in [1, 2, 3] {
        ctx.run(&format!("SELECT COUNT(*) FROM {table} WHERE price > {price}")).await?;
    }

    // Ordered by calls, so the test's statement isn't crowded out by slower ones from other tests.
    let history = ctx.session.query_history(HistoryOrder::Calls).await?;
    assert!(history.notice.is_none(), "unexpected notice: {:?}", history.notice);
    let stats = history
        .statements
        .iter()
        .find(|stats| stats.text.contains(&ctx.ns) && stats.text.to_ascii_uppercase().contains("COUNT"))
        .ok_or("the test's statement isn't in the history")?;

    assert_eq!(stats.calls, 3, "the three runs weren't grouped into one statement: {}", stats.text);
    assert!(stats.total_ms > 0.0);
    assert!(stats.mean_ms <= stats.total_ms);
    let database = ctx.pick(ctx.ns.as_str(), "postgres");
    assert_eq!(stats.database.as_deref(), Some(database));
    Ok(())
}

async fn lists_queries_running_on_other_connections(ctx: &Ctx) -> TestResult {
    let sleeper = ctx.session.open_context(None, ContextAccess::ReadWrite).await?;
    let sleep = ctx.pick(
        format!("SELECT SLEEP(3) AS {}", ctx.ns),
        format!("SELECT pg_sleep(3) AS {}", ctx.ns),
    );

    // Past one second, since MySQL only counts whole seconds.
    let (slept, listed) = tokio::join!(ctx.session.execute(sleeper, &sleep, 10), async {
        tokio::time::sleep(Duration::from_millis(1300)).await;
        ctx.session.running_queries().await
    });
    ctx.session.close_context(sleeper).await;
    slept?;
    let listed = listed?;

    assert!(listed.notice.is_none(), "unexpected notice: {:?}", listed.notice);
    let query = listed
        .queries
        .iter()
        .find(|query| query.text.as_deref().is_some_and(|text| text.contains(&ctx.ns)))
        .ok_or("the sleeping query isn't listed")?;
    assert!(query.running_ms.is_some_and(|ms| ms >= 1000.0), "running for {:?}", query.running_ms);
    assert!(query.user.is_some());
    assert!(
        !listed.queries.iter().any(|query| query.text.as_deref().is_some_and(|text| text.contains("PROCESSLIST") || text.contains("pg_stat_activity"))),
        "Fran's own lookup is listed"
    );
    Ok(())
}

async fn history_says_how_to_create_the_extension(ctx: &Ctx) -> TestResult {
    let database = format!("{}_stats", ctx.ns);
    ctx.run_fresh(&format!("CREATE DATABASE \"{database}\"")).await?;

    let switched = ctx.session.switch_catalog(&database).await;
    let history = match &switched {
        Ok(()) => Some(ctx.session.query_history(HistoryOrder::MeanMs).await),
        Err(_) => None,
    };
    ctx.session.switch_catalog("postgres").await?;
    ctx.run_fresh(&format!("DROP DATABASE \"{database}\"")).await?;

    switched?;
    let history = history.ok_or("no history")??;
    let notice = history.notice.ok_or("no notice for a database without the extension")?;
    assert_eq!(notice.kind, NoticeKind::Unavailable);
    assert!(history.statements.is_empty());
    assert_eq!(notice.steps.len(), 1, "the library is already preloaded, so only CREATE EXTENSION is needed");
    assert_eq!(notice.steps[0].code.as_deref(), Some("CREATE EXTENSION pg_stat_statements;"));
    assert!(!notice.steps[0].restart);
    Ok(())
}
