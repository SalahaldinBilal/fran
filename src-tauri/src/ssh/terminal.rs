use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty, client::Msg};
use serde::Serialize;
use tauri::{
    State,
    async_runtime::JoinHandle,
    ipc::{Channel, InvokeResponseBody},
};

use super::terminal_log::{FLUSH_EVERY, PaneLog, TerminalLogs};
use super::{HostKeyInfo, SshConnection, SshHandle, connect_saved_host, known_hosts::KnownHosts, policy::ChannelPolicy};
use crate::connections::{PASSWORD_SLOT, SecretOwner};
use crate::error::{AppError, AppResult};
use crate::ssh_store::{IdentityAuth, SshStore};
use crate::vault::Vault;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);
// The channel can end a moment before the handler hears why the connection went.
const REASON_WAIT: Duration = Duration::from_secs(1);
const TERM: &str = "xterm-256color";
const MAX_SIZE: u32 = 1000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalInfo {
    pub id: String,
    pub connection_id: String,
    pub host_id: String,
    /// The key the target host proved it holds on this connect.
    pub host_key: Option<HostKeyInfo>,
    pub agent_forwarding: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TerminalEvent {
    #[serde(rename_all = "camelCase")]
    Closed { reason: Option<String>, connection_lost: bool },
}

struct TermConnection {
    host_id: String,
    host_label: String,
    connection: SshConnection,
    host_key: Option<HostKeyInfo>,
}

/// A terminal's connection lent to SFTP so it doesn't log in again. The connection stays up while this is held.
pub struct BorrowedConnection {
    connection: Arc<TermConnection>,
}

impl BorrowedConnection {
    pub fn host_id(&self) -> &str {
        &self.connection.host_id
    }

    pub fn host_key(&self) -> Option<HostKeyInfo> {
        self.connection.host_key.clone()
    }

    pub fn target(&self) -> Arc<SshHandle> {
        self.connection.connection.target()
    }

    pub fn is_closed(&self) -> bool {
        self.connection.connection.is_closed()
    }

    pub fn policy(&self) -> Arc<ChannelPolicy> {
        self.connection.connection.policy().clone()
    }
}

struct Pane {
    connection_id: String,
    writer: Arc<ChannelWriteHalf<Msg>>,
    task: Option<JoinHandle<()>>,
}

/// Open terminal connections and their panes. Split panes are extra session channels on one connection.
#[derive(Default)]
pub struct TerminalManager {
    connections: Mutex<HashMap<String, Arc<TermConnection>>>,
    panes: Mutex<HashMap<String, Pane>>,
}

fn lock_error() -> AppError {
    AppError::general("Terminal lock poisoned")
}

fn channel_error(error: russh::Error) -> AppError {
    AppError::ssh(format!("The terminal channel failed: {error}"))
}

async fn expect_success(read: &mut ChannelReadHalf, early: &mut Vec<Vec<u8>>, what: &str) -> AppResult<()> {
    let wait = async {
        loop {
            match read.wait().await {
                Some(ChannelMsg::Success) => return Ok(()),
                Some(ChannelMsg::Failure) => return Err(AppError::ssh(format!("The server refused {what}"))),
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => early.push(data.to_vec()),
                Some(ChannelMsg::Close) | None => {
                    return Err(AppError::ssh(format!("The server closed the channel instead of starting {what}")));
                }
                Some(_) => {}
            }
        }
    };
    tokio::time::timeout(REPLY_TIMEOUT, wait)
        .await
        .map_err(|_| AppError::ssh(format!("The server didn't answer the request for {what}")))?
}

impl TerminalManager {
    fn connection(&self, id: &str) -> AppResult<Arc<TermConnection>> {
        self.connections
            .lock()
            .map_err(|_| lock_error())?
            .get(id)
            .filter(|connection| !connection.connection.is_closed())
            .cloned()
            .ok_or_else(|| AppError::not_found("This connection was closed"))
    }

    pub fn borrow(&self, connection_id: &str) -> AppResult<BorrowedConnection> {
        self.connection(connection_id).map(|connection| BorrowedConnection { connection })
    }

    fn writer(&self, id: &str) -> AppResult<Arc<ChannelWriteHalf<Msg>>> {
        self.panes
            .lock()
            .map_err(|_| lock_error())?
            .get(id)
            .map(|pane| pane.writer.clone())
            .ok_or_else(|| AppError::not_found("This terminal is closed"))
    }

    fn remove_connection_if_unused(&self, connection_id: &str) {
        let used = self
            .panes
            .lock()
            .map(|panes| panes.values().any(|pane| pane.connection_id == connection_id))
            .unwrap_or(false);
        if !used {
            if let Ok(mut connections) = self.connections.lock() {
                connections.remove(connection_id);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_pane(
        self: &Arc<Self>,
        connection_id: &str,
        connection: Arc<TermConnection>,
        cols: u32,
        rows: u32,
        logs: Option<Arc<TerminalLogs>>,
        output: Channel,
        events: Channel<TerminalEvent>,
    ) -> AppResult<TerminalInfo> {
        let policy = connection.connection.policy().clone();
        let channel = connection.connection.target().channel_open_session().await.map_err(channel_error)?;
        let (mut read, write) = channel.split();

        if policy.forwards_agent() {
            write.agent_forward(false).await.map_err(channel_error)?;
        }
        let mut early = Vec::new();
        write
            .request_pty(true, TERM, cols.clamp(1, MAX_SIZE), rows.clamp(1, MAX_SIZE), 0, 0, &[(Pty::IUTF8, 1)])
            .await
            .map_err(channel_error)?;
        expect_success(&mut read, &mut early, "a terminal").await?;
        write.request_shell(true).await.map_err(channel_error)?;
        expect_success(&mut read, &mut early, "a shell").await?;

        let id = uuid::Uuid::new_v4().to_string();
        let mut log = logs.map(|logs| PaneLog::start(logs, id.clone(), connection.host_id.clone(), connection.host_label.clone()));
        for chunk in early {
            if let Some(log) = log.as_mut() {
                log.output(&chunk);
            }
            let _ = output.send(InvokeResponseBody::Raw(chunk));
        }

        self.panes.lock().map_err(|_| lock_error())?.insert(
            id.clone(),
            Pane {
                connection_id: connection_id.to_string(),
                writer: Arc::new(write),
                task: None,
            },
        );
        let task = tauri::async_runtime::spawn(self.clone().pump(id.clone(), read, policy.clone(), log, output, events));
        if let Ok(mut panes) = self.panes.lock() {
            match panes.get_mut(&id) {
                Some(pane) => pane.task = Some(task),
                None => drop(task),
            }
        }

        Ok(TerminalInfo {
            id,
            connection_id: connection_id.to_string(),
            host_id: connection.host_id.clone(),
            host_key: connection.host_key.clone(),
            agent_forwarding: policy.forwards_agent(),
        })
    }

    async fn pump(
        self: Arc<Self>,
        id: String,
        mut read: ChannelReadHalf,
        policy: Arc<ChannelPolicy>,
        mut log: Option<PaneLog>,
        output: Channel,
        events: Channel<TerminalEvent>,
    ) {
        let mut exit = None;
        let mut closed_by_server = false;
        let mut flush = tokio::time::interval(FLUSH_EVERY);
        loop {
            let message = tokio::select! {
                message = read.wait() => message,
                _ = flush.tick(), if log.is_some() => {
                    if let Some(log) = log.as_mut() {
                        log.flush();
                    }
                    continue;
                }
            };
            match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if let Some(log) = log.as_mut() {
                        log.output(&data);
                    }
                    if output.send(InvokeResponseBody::Raw(data.to_vec())).is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) if exit_status != 0 => {
                    exit = Some(format!("The shell exited with status {exit_status}"));
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    exit = Some(format!("The shell was stopped by signal {signal_name:?}"));
                }
                Some(ChannelMsg::Close) => {
                    closed_by_server = true;
                    break;
                }
                None => break,
                Some(_) => {}
            }
        }

        let Some(pane) = self.panes.lock().ok().and_then(|mut panes| panes.remove(&id)) else {
            if let Some(log) = log {
                log.close(None);
            }
            return;
        };
        let connection_lost = !closed_by_server;
        let reason = if connection_lost {
            let _ = tokio::time::timeout(REASON_WAIT, policy.wait_closed()).await;
            Some(policy.close_reason().unwrap_or_else(|| "The connection dropped".to_string()))
        } else {
            exit
        };
        if let Some(log) = log {
            log.close(reason.as_deref());
        }
        self.remove_connection_if_unused(&pane.connection_id);
        let _ = events.send(TerminalEvent::Closed { reason, connection_lost });
    }

    fn close(&self, id: &str) {
        let Some(pane) = self.panes.lock().ok().and_then(|mut panes| panes.remove(id)) else {
            return;
        };
        if let Some(task) = pane.task {
            task.abort();
        }
        let writer = pane.writer;
        tauri::async_runtime::spawn(async move {
            let _ = writer.close().await;
        });
        self.remove_connection_if_unused(&pane.connection_id);
    }

    pub fn close_all(&self) {
        let panes: Vec<Pane> = self.panes.lock().map(|mut panes| panes.drain().map(|(_, pane)| pane).collect()).unwrap_or_default();
        for pane in panes {
            if let Some(task) = pane.task {
                task.abort();
            }
        }
        if let Ok(mut connections) = self.connections.lock() {
            connections.clear();
        }
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn open_terminal(
    vault: State<'_, Arc<Vault>>,
    known_hosts: State<'_, Arc<KnownHosts>>,
    ssh_store: State<'_, Arc<SshStore>>,
    terminals: State<'_, Arc<TerminalManager>>,
    terminal_logs: State<'_, Arc<TerminalLogs>>,
    host_id: String,
    cols: u32,
    rows: u32,
    log: bool,
    secrets: HashMap<String, String>,
    on_output: Channel,
    on_event: Channel<TerminalEvent>,
) -> AppResult<TerminalInfo> {
    let logs = pane_logs(log, &terminal_logs, &vault)?;
    let file = ssh_store.snapshot()?;
    let host = file.host(&host_id).cloned().ok_or_else(|| AppError::not_found("That SSH host was deleted"))?;
    let agent = host.agent_forwarding.then(|| {
        match host.identity_id.as_deref().and_then(|id| file.identity(id)).map(|identity| &identity.auth) {
            Some(IdentityAuth::Agent { socket }) => socket.clone(),
            _ => String::new(),
        }
    });

    let policy = Arc::new(ChannelPolicy::with_agent(agent));
    let connection = connect_saved_host(&host_id, secrets, &vault, &ssh_store, &known_hosts, policy, CONNECT_TIMEOUT).await?;
    let connection_id = uuid::Uuid::new_v4().to_string();
    let term = Arc::new(TermConnection {
        host_id: host_id.clone(),
        host_label: host.label.clone(),
        connection,
        host_key: known_hosts.find(&host.host, host.port)?,
    });
    terminals
        .connections
        .lock()
        .map_err(|_| lock_error())?
        .insert(connection_id.clone(), term.clone());

    let opened = terminals.open_pane(&connection_id, term, cols, rows, logs, on_output, on_event).await;
    if opened.is_err() {
        terminals.remove_connection_if_unused(&connection_id);
    }
    opened
}

/// A new shell on a connection that's already open, so no second login.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn open_terminal_pane(
    vault: State<'_, Arc<Vault>>,
    terminals: State<'_, Arc<TerminalManager>>,
    terminal_logs: State<'_, Arc<TerminalLogs>>,
    connection_id: String,
    cols: u32,
    rows: u32,
    log: bool,
    on_output: Channel,
    on_event: Channel<TerminalEvent>,
) -> AppResult<TerminalInfo> {
    let logs = pane_logs(log, &terminal_logs, &vault)?;
    let connection = terminals.connection(&connection_id)?;
    terminals.open_pane(&connection_id, connection, cols, rows, logs, on_output, on_event).await
}

fn pane_logs(log: bool, logs: &Arc<TerminalLogs>, vault: &Vault) -> AppResult<Option<Arc<TerminalLogs>>> {
    if !log {
        return Ok(None);
    }
    if !logs.is_unlocked() {
        logs.unlock(vault)?;
    }
    Ok(Some(logs.clone()))
}

#[tauri::command]
pub async fn terminal_input(terminals: State<'_, Arc<TerminalManager>>, id: String, data: Vec<u8>) -> AppResult<()> {
    terminals
        .writer(&id)?
        .data_bytes(data)
        .await
        .map_err(|_| AppError::ssh("This terminal is closed"))
}

#[tauri::command]
pub async fn terminal_resize(terminals: State<'_, Arc<TerminalManager>>, id: String, cols: u32, rows: u32) -> AppResult<()> {
    terminals
        .writer(&id)?
        .window_change(cols.clamp(1, MAX_SIZE), rows.clamp(1, MAX_SIZE), 0, 0)
        .await
        .map_err(|_| AppError::ssh("This terminal is closed"))
}

/// Types the host login's saved password at the prompt, for sudo. It goes from the vault to the server and never
/// through the window. Enter isn't sent, so at a prompt that isn't asking for it nothing runs.
#[tauri::command]
pub async fn terminal_type_password(
    vault: State<'_, Arc<Vault>>,
    ssh_store: State<'_, Arc<SshStore>>,
    terminals: State<'_, Arc<TerminalManager>>,
    id: String,
) -> AppResult<()> {
    let (connection_id, writer) = {
        let panes = terminals.panes.lock().map_err(|_| lock_error())?;
        let pane = panes.get(&id).ok_or_else(|| AppError::not_found("This terminal is closed"))?;
        (pane.connection_id.clone(), pane.writer.clone())
    };
    let host_id = terminals.connection(&connection_id)?.host_id.clone();

    let file = ssh_store.snapshot()?;
    let host = file.host(&host_id).ok_or_else(|| AppError::not_found("That SSH host was deleted"))?;
    let identity = host
        .identity_id
        .as_deref()
        .and_then(|identity_id| file.identity(identity_id))
        .ok_or_else(|| AppError::not_found("This host has no login"))?;
    let password = vault
        .get(&SecretOwner::Identity(identity.id.clone()).secret_id(PASSWORD_SLOT))?
        .ok_or_else(|| AppError::not_found(format!("{} has no saved password. Save one in the Keychain, under Identities.", identity.label)))?;

    writer
        .data_bytes(password.as_bytes().to_vec())
        .await
        .map_err(|_| AppError::ssh("This terminal is closed"))
}

#[tauri::command]
pub fn close_terminal(terminals: State<'_, Arc<TerminalManager>>, id: String) {
    terminals.close(&id);
}

/// Opens links from terminal output. Only web links, so a server can't make the app open files or other schemes.
#[tauri::command]
pub fn open_link(app: tauri::AppHandle, url: String) -> AppResult<()> {
    use tauri_plugin_opener::OpenerExt;

    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) || url.chars().any(char::is_control) {
        return Err(AppError::general("Only http and https links can be opened"));
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|error| AppError::general(format!("Couldn't open the link: {error}")))
}
