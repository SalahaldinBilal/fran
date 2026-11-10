pub mod local;
pub mod paths;
pub mod transfer;

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh_sftp::{
    client::{SftpSession, error::Error as SftpError},
    protocol::{FileAttributes, FileType},
};
use serde::Serialize;
use tauri::{State, ipc::Channel};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{
    HostKeyInfo, SshConnection, SshHandle, connect_saved_host,
    known_hosts::KnownHosts,
    policy::ChannelPolicy,
    route::SshRoute,
    terminal::{BorrowedConnection, TerminalManager},
};
use crate::error::{AppError, AppResult};
use crate::ssh_store::SshStore;
use crate::vault::Vault;
use paths::{remote_crumbs, remote_join, remote_name_problem, remote_parent};
use transfer::{ConflictChoice, Control, Direction, TransferEvent};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT_SECS: u64 = 30;
pub const MAX_TRANSFERS: usize = 3;
const PREVIEW_LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    /// Unix milliseconds.
    pub modified: Option<i64>,
    pub mode: Option<u32>,
    pub hidden: bool,
    /// A link whose target is a folder, so it opens like one.
    pub link_dir: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    pub path: String,
    pub crumbs: Vec<paths::Crumb>,
    pub parent: Option<String>,
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeCount {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpInfo {
    pub id: String,
    pub host_id: String,
    pub home: String,
    pub host_key: Option<HostKeyInfo>,
    /// Runs on a terminal's connection instead of its own login.
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SftpEvent {
    /// The SSH connection under it went away.
    Closed { reason: Option<String> },
}

enum Link {
    Own(SshConnection),
    Terminal(BorrowedConnection),
    /// No SSH connection under the session, for tests against an in-process server.
    #[cfg(test)]
    Detached(Arc<ChannelPolicy>),
}

impl Link {
    fn is_closed(&self) -> bool {
        match self {
            Link::Own(connection) => connection.is_closed(),
            Link::Terminal(borrowed) => borrowed.is_closed(),
            #[cfg(test)]
            Link::Detached(_) => false,
        }
    }

    fn policy(&self) -> Arc<ChannelPolicy> {
        match self {
            Link::Own(connection) => connection.policy().clone(),
            Link::Terminal(borrowed) => borrowed.policy(),
            #[cfg(test)]
            Link::Detached(policy) => policy.clone(),
        }
    }
}

/// One SFTP session and what it runs on.
pub struct SftpConn {
    sftp: SftpSession,
    link: Link,
    slots: Arc<Semaphore>,
    closed: CancellationToken,
}

pub(crate) fn sftp_failed(what: impl Display, error: SftpError) -> AppError {
    AppError::ssh(format!("{what}: {error}"))
}

fn kind_of(file_type: FileType) -> EntryKind {
    match file_type {
        FileType::Dir => EntryKind::Dir,
        FileType::File => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Other => EntryKind::Other,
    }
}

fn remote_entry(path: String, name: String, kind: EntryKind, attributes: &FileAttributes) -> FileEntry {
    FileEntry {
        hidden: name.starts_with('.'),
        size: (kind == EntryKind::File).then_some(attributes.size).flatten(),
        modified: attributes.mtime.map(|seconds| i64::from(seconds) * 1000),
        mode: attributes.permissions,
        link_dir: false,
        path,
        name,
        kind,
    }
}

fn checked_remote_name(name: &str) -> AppResult<&str> {
    let name = name.trim();
    match remote_name_problem(name) {
        Some(problem) => Err(AppError::general(problem)),
        None => Ok(name),
    }
}

async fn session_over<S>(stream: S) -> AppResult<SftpSession>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session = SftpSession::new(stream)
        .await
        .map_err(|error| AppError::ssh(format!("The server didn't start SFTP: {error}")))?;
    session.set_timeout(REQUEST_TIMEOUT_SECS);
    Ok(session)
}

async fn start_sftp(handle: &SshHandle) -> AppResult<SftpSession> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|error| AppError::ssh(format!("Couldn't open an SFTP channel: {error}")))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| AppError::ssh(format!("The server refused SFTP: {error}")))?;
    session_over(channel.into_stream()).await
}

impl SftpConn {
    fn new(sftp: SftpSession, link: Link) -> Arc<Self> {
        Arc::new(Self {
            sftp,
            link,
            slots: Arc::new(Semaphore::new(MAX_TRANSFERS)),
            closed: CancellationToken::new(),
        })
    }

    async fn over(link: Link) -> AppResult<Arc<Self>> {
        let handle = match &link {
            Link::Own(connection) => connection.target(),
            Link::Terminal(borrowed) => borrowed.target(),
            #[cfg(test)]
            Link::Detached(_) => return Err(AppError::general("A detached link has no SSH connection")),
        };
        let sftp = start_sftp(&handle).await?;
        Ok(Self::new(sftp, link))
    }

    /// Logs in along `route` and starts SFTP on its last hop.
    pub async fn connect(route: &SshRoute, known_hosts: &KnownHosts, timeout: Duration) -> AppResult<Arc<Self>> {
        let connection = SshConnection::open(route, known_hosts, timeout).await?;
        Self::over(Link::Own(connection)).await
    }

    #[cfg(test)]
    async fn detached<S>(stream: S) -> AppResult<Arc<Self>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Ok(Self::new(session_over(stream).await?, Link::Detached(Arc::new(ChannelPolicy::default()))))
    }

    pub async fn home(&self) -> AppResult<String> {
        self.sftp.canonicalize(".").await.map_err(|error| sftp_failed("Couldn't find the home folder", error))
    }

    pub async fn list(self: &Arc<Self>, path: &str) -> AppResult<Listing> {
        let path = self
            .sftp
            .canonicalize(path)
            .await
            .map_err(|error| sftp_failed(format!("Couldn't open {path}"), error))?;
        let listing = self.sftp.read_dir(path.as_str()).await.map_err(|error| sftp_failed(format!("Couldn't open {path}"), error))?;

        let mut entries = Vec::new();
        let mut links = tokio::task::JoinSet::new();
        for entry in listing {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let item = remote_entry(remote_join(&path, &name), name, kind_of(entry.file_type()), &entry.metadata());
            // Following each link is one more request, so they all go out at once.
            if item.kind == EntryKind::Symlink {
                let (conn, index, target) = (self.clone(), entries.len(), item.path.clone());
                links.spawn(async move { (index, conn.sftp.metadata(target).await.is_ok_and(|meta| meta.is_dir())) });
            }
            entries.push(item);
        }
        while let Some(result) = links.join_next().await {
            if let Ok((index, is_dir)) = result {
                entries[index].link_dir = is_dir;
            }
        }
        Ok(Listing {
            crumbs: remote_crumbs(&path),
            parent: remote_parent(&path),
            path,
            entries,
        })
    }

    pub async fn stat(&self, path: &str) -> AppResult<FileEntry> {
        let attributes = self
            .sftp
            .symlink_metadata(path)
            .await
            .map_err(|error| sftp_failed(format!("Couldn't read {path}"), error))?;
        Ok(remote_entry(path.to_string(), paths::remote_name(path).to_string(), kind_of(attributes.file_type()), &attributes))
    }

    pub async fn mkdir(&self, dir: &str, name: &str) -> AppResult<String> {
        let path = remote_join(dir, checked_remote_name(name)?);
        self.sftp
            .create_dir(path.as_str())
            .await
            .map_err(|error| sftp_failed(format!("Couldn't create {path}"), error))?;
        Ok(path)
    }

    pub async fn rename(&self, path: &str, name: &str) -> AppResult<String> {
        let parent = remote_parent(path).ok_or_else(|| AppError::general("This can't be renamed"))?;
        let target = remote_join(&parent, checked_remote_name(name)?);
        if target != path && self.sftp.symlink_metadata(target.as_str()).await.is_ok() {
            return Err(AppError::general(format!("{target} already exists")));
        }
        self.sftp
            .rename(path, target.as_str())
            .await
            .map_err(|error| sftp_failed(format!("Couldn't rename {path}"), error))?;
        Ok(target)
    }

    /// Folders with something in them are only removed with `recursive`. Links inside are removed, never followed.
    pub async fn remove(&self, path: &str, recursive: bool) -> AppResult<()> {
        if remote_parent(path).is_none() {
            return Err(AppError::general("The root folder can't be deleted"));
        }
        let attributes = self
            .sftp
            .symlink_metadata(path)
            .await
            .map_err(|error| sftp_failed(format!("Couldn't read {path}"), error))?;
        if !attributes.is_dir() {
            return self.sftp.remove_file(path).await.map_err(|error| sftp_failed(format!("Couldn't delete {path}"), error));
        }
        if !recursive {
            return self.sftp.remove_dir(path).await.map_err(|error| sftp_failed(format!("Couldn't delete {path}"), error));
        }

        let mut dirs = vec![path.to_string()];
        let mut emptied = Vec::new();
        while let Some(dir) = dirs.pop() {
            let listing = self.sftp.read_dir(dir.as_str()).await.map_err(|error| sftp_failed(format!("Couldn't read {dir}"), error))?;
            for entry in listing {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let child = remote_join(&dir, &name);
                if entry.file_type().is_dir() {
                    dirs.push(child);
                } else {
                    self.sftp.remove_file(child.as_str()).await.map_err(|error| sftp_failed(format!("Couldn't delete {child}"), error))?;
                }
            }
            emptied.push(dir);
        }
        for dir in emptied.into_iter().rev() {
            self.sftp.remove_dir(dir.as_str()).await.map_err(|error| sftp_failed(format!("Couldn't delete {dir}"), error))?;
        }
        Ok(())
    }

    /// What a recursive delete would remove, the folder itself included.
    pub async fn count(&self, root: &str) -> AppResult<TreeCount> {
        let mut count = TreeCount::default();
        let mut dirs = vec![root.to_string()];
        while let Some(dir) = dirs.pop() {
            count.folders += 1;
            let listing = self.sftp.read_dir(dir.as_str()).await.map_err(|error| sftp_failed(format!("Couldn't read {dir}"), error))?;
            for entry in listing {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                if entry.file_type().is_dir() {
                    dirs.push(remote_join(&dir, &name));
                } else {
                    count.files += 1;
                    count.bytes += entry.metadata().size.unwrap_or(0);
                }
            }
        }
        Ok(count)
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> AppResult<()> {
        let mut attributes = FileAttributes::empty();
        attributes.permissions = Some(mode & 0o7777);
        self.sftp
            .set_metadata(path, attributes)
            .await
            .map_err(|error| sftp_failed(format!("Couldn't change the permissions of {path}"), error))
    }

    /// Read-only text of a small file.
    pub async fn preview(&self, path: &str) -> AppResult<String> {
        let attributes = self.sftp.metadata(path).await.map_err(|error| sftp_failed(format!("Couldn't read {path}"), error))?;
        if !attributes.is_regular() {
            return Err(AppError::general("Only files can be previewed"));
        }
        if attributes.len() > PREVIEW_LIMIT {
            return Err(AppError::general("This file is bigger than 1 MiB. Download it to open it."));
        }

        let file = self.sftp.open(path).await.map_err(|error| sftp_failed(format!("Couldn't open {path}"), error))?;
        let mut data = Vec::new();
        file.take(PREVIEW_LIMIT + 1)
            .read_to_end(&mut data)
            .await
            .map_err(|error| AppError::ssh(format!("Couldn't read {path}: {error}")))?;
        if data.len() as u64 > PREVIEW_LIMIT {
            return Err(AppError::general("This file is bigger than 1 MiB. Download it to open it."));
        }
        if data.contains(&0) {
            return Err(AppError::general("This looks like a binary file, so it can't be shown as text"));
        }
        String::from_utf8(data).map_err(|_| AppError::general("This file isn't UTF-8 text"))
    }

    pub async fn close(&self) {
        self.closed.cancel();
        let _ = self.sftp.close().await;
    }
}

/// Open SFTP sessions and their running transfers.
#[derive(Default)]
pub struct SftpManager {
    conns: Mutex<HashMap<String, Arc<SftpConn>>>,
    transfers: Mutex<HashMap<String, Arc<Control>>>,
}

fn lock_error() -> AppError {
    AppError::general("SFTP lock poisoned")
}

impl SftpManager {
    fn conn(&self, id: &str) -> AppResult<Arc<SftpConn>> {
        let mut conns = self.conns.lock().map_err(|_| lock_error())?;
        match conns.get(id) {
            Some(conn) if !conn.link.is_closed() => Ok(conn.clone()),
            Some(_) => {
                conns.remove(id);
                Err(AppError::not_found("The SFTP connection dropped"))
            }
            None => Err(AppError::not_found("This SFTP connection was closed")),
        }
    }

    fn cancel_transfers(&self, sftp_id: Option<&str>) {
        if let Ok(transfers) = self.transfers.lock() {
            for control in transfers.values().filter(|control| sftp_id.is_none_or(|id| control.sftp_id == id)) {
                control.cancel.cancel();
            }
        }
    }

    fn close(&self, id: &str) -> Option<Arc<SftpConn>> {
        self.cancel_transfers(Some(id));
        let conn = self.conns.lock().ok().and_then(|mut conns| conns.remove(id));
        if let Some(conn) = &conn {
            conn.closed.cancel();
        }
        conn
    }

    pub fn close_all(&self) {
        self.cancel_transfers(None);
        if let Ok(mut conns) = self.conns.lock() {
            for conn in conns.values() {
                conn.closed.cancel();
            }
            conns.clear();
        }
    }

    /// Tells the tab as soon as the SSH connection drops, instead of on its next click.
    fn watch(self: Arc<Self>, id: String, conn: Arc<SftpConn>, events: Channel<SftpEvent>) {
        let policy = conn.link.policy();
        let closed = conn.closed.clone();
        drop(conn);
        tauri::async_runtime::spawn(async move {
            tokio::select! {
                () = policy.wait_closed() => {
                    self.close(&id);
                    let _ = events.send(SftpEvent::Closed { reason: policy.close_reason() });
                }
                () = closed.cancelled() => {}
            }
        });
    }

    fn control(&self, transfer_id: &str) -> AppResult<Arc<Control>> {
        self.transfers
            .lock()
            .map_err(|_| lock_error())?
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| AppError::not_found("This transfer already ended"))
    }
}

/// Uses the terminal's connection when one is given and still up, otherwise logs in along the host's route.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn sftp_open(
    vault: State<'_, Arc<Vault>>,
    known_hosts: State<'_, Arc<KnownHosts>>,
    ssh_store: State<'_, Arc<SshStore>>,
    terminals: State<'_, Arc<TerminalManager>>,
    sftp: State<'_, Arc<SftpManager>>,
    host_id: String,
    connection_id: Option<String>,
    secrets: HashMap<String, String>,
    on_event: Channel<SftpEvent>,
) -> AppResult<SftpInfo> {
    let borrowed = connection_id
        .as_deref()
        .and_then(|id| terminals.borrow(id).ok())
        .filter(|borrowed| borrowed.host_id() == host_id && !borrowed.is_closed());

    let (link, host_key) = match borrowed {
        Some(borrowed) => {
            let key = borrowed.host_key();
            (Link::Terminal(borrowed), key)
        }
        None => {
            let file = ssh_store.snapshot()?;
            let host = file.host(&host_id).cloned().ok_or_else(|| AppError::not_found("That SSH host was deleted"))?;
            let policy = Arc::new(ChannelPolicy::default());
            let connection = connect_saved_host(&host_id, secrets, &vault, &ssh_store, &known_hosts, policy, CONNECT_TIMEOUT).await?;
            (Link::Own(connection), known_hosts.find(&host.host, host.port)?)
        }
    };

    let shared = matches!(link, Link::Terminal(_));
    let conn = SftpConn::over(link).await?;
    let home = conn.home().await?;

    let id = uuid::Uuid::new_v4().to_string();
    sftp.conns.lock().map_err(|_| lock_error())?.insert(id.clone(), conn.clone());
    sftp.inner().clone().watch(id.clone(), conn, on_event);
    Ok(SftpInfo { id, host_id, home, host_key, shared })
}

#[tauri::command]
pub async fn sftp_close(sftp: State<'_, Arc<SftpManager>>, id: String) -> AppResult<()> {
    if let Some(conn) = sftp.close(&id) {
        conn.close().await;
    }
    Ok(())
}

#[tauri::command]
pub async fn sftp_list(sftp: State<'_, Arc<SftpManager>>, id: String, path: String) -> AppResult<Listing> {
    sftp.conn(&id)?.list(&path).await
}

#[tauri::command]
pub async fn sftp_stat(sftp: State<'_, Arc<SftpManager>>, id: String, path: String) -> AppResult<FileEntry> {
    sftp.conn(&id)?.stat(&path).await
}

#[tauri::command]
pub async fn sftp_mkdir(sftp: State<'_, Arc<SftpManager>>, id: String, dir: String, name: String) -> AppResult<String> {
    sftp.conn(&id)?.mkdir(&dir, &name).await
}

#[tauri::command]
pub async fn sftp_rename(sftp: State<'_, Arc<SftpManager>>, id: String, path: String, name: String) -> AppResult<String> {
    sftp.conn(&id)?.rename(&path, &name).await
}

#[tauri::command]
pub async fn sftp_remove(sftp: State<'_, Arc<SftpManager>>, id: String, path: String, recursive: bool) -> AppResult<()> {
    sftp.conn(&id)?.remove(&path, recursive).await
}

#[tauri::command]
pub async fn sftp_count(sftp: State<'_, Arc<SftpManager>>, id: String, path: String) -> AppResult<TreeCount> {
    sftp.conn(&id)?.count(&path).await
}

#[tauri::command]
pub async fn sftp_chmod(sftp: State<'_, Arc<SftpManager>>, id: String, path: String, mode: u32) -> AppResult<()> {
    sftp.conn(&id)?.chmod(&path, mode).await
}

#[tauri::command]
pub async fn sftp_preview(sftp: State<'_, Arc<SftpManager>>, id: String, path: String) -> AppResult<String> {
    sftp.conn(&id)?.preview(&path).await
}

/// Starts a copy in the background and returns its id. Progress, name clashes and the end arrive on `on_event`.
#[tauri::command]
pub fn sftp_transfer(
    sftp: State<'_, Arc<SftpManager>>,
    id: String,
    direction: Direction,
    source: String,
    target_dir: String,
    on_event: Channel<TransferEvent>,
) -> AppResult<String> {
    let conn = sftp.conn(&id)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let control = Arc::new(Control::new(id));
    sftp.transfers.lock().map_err(|_| lock_error())?.insert(transfer_id.clone(), control.clone());

    let manager = sftp.inner().clone();
    let key = transfer_id.clone();
    tauri::async_runtime::spawn(async move {
        transfer::run(conn, control, direction, source, target_dir, on_event).await;
        if let Ok(mut transfers) = manager.transfers.lock() {
            transfers.remove(&key);
        }
    });
    Ok(transfer_id)
}

#[tauri::command]
pub fn sftp_answer_conflict(sftp: State<'_, Arc<SftpManager>>, transfer_id: String, choice: ConflictChoice, for_all: bool) -> AppResult<()> {
    if sftp.control(&transfer_id)?.answer(choice, for_all) {
        Ok(())
    } else {
        Err(AppError::general("This transfer isn't waiting for an answer"))
    }
}

/// The file being written is deleted. Files already finished stay.
#[tauri::command]
pub fn cancel_transfer(sftp: State<'_, Arc<SftpManager>>, transfer_id: String) -> AppResult<()> {
    sftp.control(&transfer_id)?.cancel.cancel();
    Ok(())
}
