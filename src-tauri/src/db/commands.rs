use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tauri::{State, ipc::Channel};

use super::{
    DatabaseKind,
    activity::{HistoryOrder, QueryHistory, RunningQueries},
    session::{ContextAccess, ContextId},
    sessions::{OpenSession, SessionInfo, SessionManager},
    split_statements,
    types::{
        BatchOutcome, CatalogColumn, ColumnChoices, ColumnMeta, DatabaseInfo, DatabaseSize, DesignOptions, ObjectInfo, ObjectKind,
        ObjectStructure, RowChange, ServerInfo, SqlTemplate, StatementOutcome, StatementRange, TableDesign,
    },
};
use crate::connections::{ConnectionProfile, ConnectionStore, prepare::prepare_connect};
use crate::error::AppResult;
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh_store::SshStore;
use crate::vault::Vault;

#[tauri::command]
pub async fn open_session(
    store: State<'_, Arc<ConnectionStore>>,
    vault: State<'_, Arc<Vault>>,
    known_hosts: State<'_, Arc<KnownHosts>>,
    ssh_store: State<'_, Arc<SshStore>>,
    sessions: State<'_, SessionManager>,
    connection_id: String,
    secrets: HashMap<String, String>,
) -> AppResult<SessionInfo> {
    let profile = store.find(&connection_id)?;
    let prepared = prepare_connect(&profile, secrets, &vault, &ssh_store)?;
    let access = prepared.access(&known_hosts);

    let session = prepared.profile.driver.connect(&prepared.secrets, &access).await.map_err(|error| prepared.scrub(error))?;
    sessions.insert(OpenSession {
        info: SessionInfo {
            id: uuid::Uuid::new_v4().to_string(),
            connection_id: profile.id.clone(),
            kind: profile.driver.kind(),
            server: session.server_info(),
            catalog: session.catalog(),
            activity: session.activity_support(),
        },
        session,
    })
}

#[tauri::command]
pub async fn list_catalogs(sessions: State<'_, SessionManager>, session_id: String) -> AppResult<Vec<String>> {
    sessions.get(&session_id)?.session.list_catalogs().await
}

#[tauri::command]
pub async fn switch_catalog(
    sessions: State<'_, SessionManager>,
    session_id: String,
    catalog: String,
) -> AppResult<SessionInfo> {
    let open = sessions.get(&session_id)?;
    open.session.switch_catalog(&catalog).await?;
    Ok(SessionInfo {
        catalog: open.session.catalog(),
        activity: open.session.activity_support(),
        ..open.info.clone()
    })
}

#[tauri::command]
pub async fn get_query_history(
    sessions: State<'_, SessionManager>,
    session_id: String,
    order: HistoryOrder,
) -> AppResult<QueryHistory> {
    sessions.get(&session_id)?.session.query_history(order).await
}

#[tauri::command]
pub async fn get_running_queries(sessions: State<'_, SessionManager>, session_id: String) -> AppResult<RunningQueries> {
    sessions.get(&session_id)?.session.running_queries().await
}

/// Works on unsaved profiles too. Stored secrets are used when the profile already has an id.
#[tauri::command]
pub async fn test_connection(
    vault: State<'_, Arc<Vault>>,
    known_hosts: State<'_, Arc<KnownHosts>>,
    ssh_store: State<'_, Arc<SshStore>>,
    profile: ConnectionProfile,
    secrets: HashMap<String, String>,
) -> AppResult<ServerInfo> {
    let prepared = prepare_connect(&profile, secrets, &vault, &ssh_store)?;
    let access = prepared.access(&known_hosts);

    let session = prepared.profile.driver.connect(&prepared.secrets, &access).await.map_err(|error| prepared.scrub(error))?;
    let info = session.server_info();
    session.close().await;
    Ok(info)
}

#[tauri::command]
pub async fn close_session(sessions: State<'_, SessionManager>, session_id: String) -> AppResult<()> {
    if let Some(open) = sessions.remove(&session_id) {
        open.session.close().await;
    }
    Ok(())
}

#[tauri::command]
pub async fn list_databases(
    sessions: State<'_, SessionManager>,
    session_id: String,
) -> AppResult<Vec<DatabaseInfo>> {
    sessions.get(&session_id)?.session.list_databases().await
}

#[tauri::command]
pub async fn get_database_sizes(
    sessions: State<'_, SessionManager>,
    session_id: String,
) -> AppResult<Vec<DatabaseSize>> {
    sessions.get(&session_id)?.session.database_sizes().await
}

#[tauri::command]
pub async fn list_objects(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
) -> AppResult<Vec<ObjectInfo>> {
    sessions.get(&session_id)?.session.list_objects(&database).await
}

#[tauri::command]
pub async fn get_object_structure(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    name: String,
    kind: ObjectKind,
    signature: Option<String>,
) -> AppResult<ObjectStructure> {
    sessions
        .get(&session_id)?
        .session
        .object_structure(&database, &name, kind, signature.as_deref())
        .await
}

#[tauri::command]
pub async fn get_column_choices(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    table: String,
    column: String,
) -> AppResult<Option<ColumnChoices>> {
    sessions
        .get(&session_id)?
        .session
        .column_choices(&database, &table, &column)
        .await
}

#[tauri::command]
pub async fn get_primary_key(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    table: String,
) -> AppResult<Vec<String>> {
    sessions.get(&session_id)?.session.primary_key(&database, &table).await
}

#[tauri::command]
pub async fn open_query_context(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: Option<String>,
) -> AppResult<ContextId> {
    sessions
        .get(&session_id)?
        .session
        .open_context(database, ContextAccess::ReadWrite)
        .await
}

#[tauri::command]
pub async fn close_query_context(
    sessions: State<'_, SessionManager>,
    session_id: String,
    context_id: ContextId,
) -> AppResult<()> {
    if let Ok(open) = sessions.get(&session_id) {
        open.session.close_context(context_id).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn execute_query(
    sessions: State<'_, SessionManager>,
    session_id: String,
    context_id: ContextId,
    sql: String,
    row_limit: usize,
    on_outcome: Channel<StatementOutcome>,
) -> AppResult<usize> {
    let sent = AtomicUsize::new(0);
    sessions
        .get(&session_id)?
        .session
        .execute_streaming(context_id, &sql, row_limit, &|outcome| {
            if on_outcome.send(outcome).is_ok() {
                sent.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await?;
    Ok(sent.into_inner())
}

#[tauri::command]
pub async fn cancel_query(
    sessions: State<'_, SessionManager>,
    session_id: String,
    context_id: ContextId,
) -> AppResult<()> {
    sessions.get(&session_id)?.session.cancel(context_id).await
}

#[tauri::command]
pub async fn split_sql(kind: DatabaseKind, sql: String) -> AppResult<Vec<StatementRange>> {
    Ok(split_statements(kind, &sql))
}

#[tauri::command]
pub async fn list_columns(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
) -> AppResult<Vec<CatalogColumn>> {
    sessions.get(&session_id)?.session.list_columns(&database).await
}

#[tauri::command]
pub async fn get_object_sql(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    name: String,
    kind: ObjectKind,
    signature: Option<String>,
    template: SqlTemplate,
) -> AppResult<String> {
    sessions
        .get(&session_id)?
        .session
        .object_sql(&database, &name, kind, signature.as_deref(), template)
        .await
}

#[tauri::command]
pub async fn get_database_sql(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    template: SqlTemplate,
) -> AppResult<String> {
    sessions.get(&session_id)?.session.database_sql(&database, template).await
}

#[tauri::command]
pub async fn preview_row_changes(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    table: String,
    columns: Vec<ColumnMeta>,
    changes: Vec<RowChange>,
) -> AppResult<Vec<String>> {
    sessions
        .get(&session_id)?
        .session
        .row_changes_sql(&database, &table, &columns, &changes)
}

#[tauri::command]
pub async fn get_insert_sql(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    table: String,
    columns: Vec<ColumnMeta>,
    rows: Vec<Vec<Option<String>>>,
) -> AppResult<Vec<String>> {
    sessions
        .get(&session_id)?
        .session
        .insert_rows_sql(&database, &table, &columns, &rows)
}

#[tauri::command]
pub async fn execute_batch(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: Option<String>,
    statements: Vec<String>,
    transactional: bool,
) -> AppResult<BatchOutcome> {
    sessions
        .get(&session_id)?
        .session
        .execute_batch(database.as_deref(), &statements, transactional)
        .await
}

#[tauri::command]
pub async fn get_table_design(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    table: String,
) -> AppResult<TableDesign> {
    sessions.get(&session_id)?.session.table_design(&database, &table).await
}

#[tauri::command]
pub async fn get_design_options(
    sessions: State<'_, SessionManager>,
    session_id: String,
) -> AppResult<DesignOptions> {
    sessions.get(&session_id)?.session.design_options().await
}

#[tauri::command]
pub async fn preview_table_design(
    sessions: State<'_, SessionManager>,
    session_id: String,
    database: String,
    original: Option<TableDesign>,
    design: TableDesign,
) -> AppResult<Vec<String>> {
    sessions
        .get(&session_id)?
        .session
        .table_design_sql(&database, original.as_ref(), &design)
}
