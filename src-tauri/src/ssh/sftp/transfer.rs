use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use russh_sftp::protocol::{FileAttributes, OpenFlags};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::paths::{local_name_problem, numbered_name, remote_join, remote_name};
use super::{SftpConn, sftp_failed};
use crate::error::AppError;

const CHUNK: usize = 256 * 1024;
const PROGRESS_EVERY: Duration = Duration::from_millis(100);
const MAX_NUMBERED: u32 = 999;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConflictChoice {
    Overwrite,
    Skip,
    KeepBoth,
}

struct Answer {
    choice: ConflictChoice,
    for_all: bool,
}

pub struct Control {
    pub sftp_id: String,
    pub cancel: CancellationToken,
    answer: Mutex<Option<oneshot::Sender<Answer>>>,
}

impl Control {
    pub fn new(sftp_id: String) -> Self {
        Self {
            sftp_id,
            cancel: CancellationToken::new(),
            answer: Mutex::new(None),
        }
    }

    /// False when the transfer wasn't waiting on a conflict.
    pub fn answer(&self, choice: ConflictChoice, for_all: bool) -> bool {
        let Some(sender) = self.answer.lock().ok().and_then(|mut slot| slot.take()) else {
            return false;
        };
        sender.send(Answer { choice, for_all }).is_ok()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TransferEvent {
    /// Waiting for one of the connection's transfer slots.
    Waiting,
    /// Counting what's in a folder before copying it.
    #[serde(rename_all = "camelCase")]
    Scanning { files: u64, bytes: u64 },
    #[serde(rename_all = "camelCase")]
    Started { total_bytes: u64, total_files: u64 },
    #[serde(rename_all = "camelCase")]
    Progress { bytes: u64, files: u64, current: String },
    #[serde(rename_all = "camelCase")]
    Conflict { path: String, is_dir: bool },
    #[serde(rename_all = "camelCase")]
    Skipped { path: String, reason: String },
    #[serde(rename_all = "camelCase")]
    Finished { bytes: u64, files: u64, skipped: u64 },
    #[serde(rename_all = "camelCase")]
    Failed { message: String },
    Cancelled,
}

enum Stop {
    Cancelled,
    Failed(AppError),
}

impl From<AppError> for Stop {
    fn from(error: AppError) -> Self {
        Self::Failed(error)
    }
}

enum StepKind {
    Folder,
    File { size: u64, mode: Option<u32> },
}

/// One thing to copy, named by its path below the transfer's root so a renamed folder carries its contents along.
struct Step {
    rel: Vec<String>,
    source: String,
    kind: StepKind,
}

struct Job {
    conn: Arc<SftpConn>,
    control: Arc<Control>,
    events: Channel<TransferEvent>,
    direction: Direction,
    for_all: Option<ConflictChoice>,
    bytes: u64,
    files: u64,
    skipped: u64,
    last_sent: Instant,
    buf: Vec<u8>,
}

pub async fn run(
    conn: Arc<SftpConn>,
    control: Arc<Control>,
    direction: Direction,
    source: String,
    target_dir: String,
    events: Channel<TransferEvent>,
) {
    let _ = events.send(TransferEvent::Waiting);
    let permit = tokio::select! {
        permit = conn.slots.clone().acquire_owned() => permit,
        _ = control.cancel.cancelled() => {
            let _ = events.send(TransferEvent::Cancelled);
            return;
        }
    };
    let Ok(_permit) = permit else {
        let _ = events.send(TransferEvent::Failed { message: "This SFTP connection was closed".to_string() });
        return;
    };

    let mut job = Job {
        conn,
        control,
        events: events.clone(),
        direction,
        for_all: None,
        bytes: 0,
        files: 0,
        skipped: 0,
        last_sent: Instant::now(),
        buf: vec![0; CHUNK],
    };
    let event = match job.execute(&source, &target_dir).await {
        Ok(()) => TransferEvent::Finished { bytes: job.bytes, files: job.files, skipped: job.skipped },
        Err(Stop::Cancelled) => TransferEvent::Cancelled,
        Err(Stop::Failed(error)) => TransferEvent::Failed { message: error.message },
    };
    let _ = events.send(event);
}

/// A hidden name next to the file being replaced, for the copy until it's complete.
fn part_name(name: &str) -> String {
    let tag = uuid::Uuid::new_v4().simple().to_string();
    format!(".{name}.{}.part", &tag[..8])
}

fn io_failed(what: impl std::fmt::Display, error: std::io::Error) -> Stop {
    Stop::Failed(AppError::general(format!("{what}: {error}")))
}

impl Job {
    fn check_cancel(&self) -> Result<(), Stop> {
        if self.control.cancel.is_cancelled() { Err(Stop::Cancelled) } else { Ok(()) }
    }

    fn skip(&mut self, path: &str, reason: &str) {
        self.skipped += 1;
        let _ = self.events.send(TransferEvent::Skipped { path: path.to_string(), reason: reason.to_string() });
    }

    fn found(&mut self, size: u64) {
        self.files += 1;
        self.bytes += size;
        if self.last_sent.elapsed() >= PROGRESS_EVERY {
            self.last_sent = Instant::now();
            let _ = self.events.send(TransferEvent::Scanning { files: self.files, bytes: self.bytes });
        }
    }

    fn progress(&mut self, current: &str) {
        if self.last_sent.elapsed() >= PROGRESS_EVERY {
            self.last_sent = Instant::now();
            let _ = self.events.send(TransferEvent::Progress { bytes: self.bytes, files: self.files, current: current.to_string() });
        }
    }

    async fn execute(&mut self, source: &str, target_dir: &str) -> Result<(), Stop> {
        let _ = self.events.send(TransferEvent::Scanning { files: 0, bytes: 0 });
        let steps = match self.direction {
            Direction::Download => {
                let target = tokio::fs::metadata(target_dir).await.map_err(|error| io_failed(format!("Couldn't open {target_dir}"), error))?;
                if !target.is_dir() {
                    return Err(AppError::general(format!("{target_dir} isn't a folder")).into());
                }
                self.scan_download(source).await?
            }
            Direction::Upload => self.scan_upload(source).await?,
        };

        let (total_bytes, total_files) = steps.iter().fold((0, 0), |(bytes, files), step| match step.kind {
            StepKind::File { size, .. } => (bytes + size, files + 1),
            StepKind::Folder => (bytes, files),
        });
        // The scan borrowed the counters.
        self.files = 0;
        self.bytes = 0;
        let _ = self.events.send(TransferEvent::Started { total_bytes, total_files });

        let mut targets: HashMap<Vec<String>, String> = HashMap::from([(Vec::new(), target_dir.to_string())]);
        for step in steps {
            self.check_cancel()?;
            let (parent_rel, name) = step.rel.split_at(step.rel.len() - 1);
            // The folder it belongs in was skipped, and that skip was already reported.
            let Some(parent) = targets.get(parent_rel).cloned() else {
                if matches!(step.kind, StepKind::File { .. }) {
                    self.skipped += 1;
                }
                continue;
            };
            match step.kind {
                StepKind::Folder => {
                    if let Some(actual) = self.make_folder(&step.source, &parent, &name[0]).await? {
                        targets.insert(step.rel, actual);
                    }
                }
                StepKind::File { mode, .. } => self.copy_file(&step.source, &parent, &name[0], mode).await?,
            }
        }
        Ok(())
    }

    async fn scan_download(&mut self, source: &str) -> Result<Vec<Step>, Stop> {
        let sftp = &self.conn.sftp;
        let root = remote_name(source).to_string();
        if let Some(problem) = local_name_problem(&root) {
            return Err(AppError::general(format!("{source} can't be saved here. {problem}.")).into());
        }
        let meta = sftp.symlink_metadata(source).await.map_err(|error| sftp_failed(format!("Couldn't read {source}"), error))?;

        if meta.is_symlink() {
            let target = sftp.metadata(source).await.map_err(|error| sftp_failed(format!("Couldn't follow the link {source}"), error))?;
            if !target.is_regular() {
                return Err(AppError::general(format!("{source} is a link to a folder. Links to folders aren't followed.")).into());
            }
            return Ok(vec![Step { rel: vec![root], source: source.to_string(), kind: StepKind::File { size: target.len(), mode: None } }]);
        }
        if meta.is_regular() {
            return Ok(vec![Step { rel: vec![root], source: source.to_string(), kind: StepKind::File { size: meta.len(), mode: None } }]);
        }
        if !meta.is_dir() {
            return Err(AppError::general(format!("{source} isn't a file or a folder")).into());
        }

        let mut steps = vec![Step { rel: vec![root.clone()], source: source.to_string(), kind: StepKind::Folder }];
        let mut dirs = vec![(source.to_string(), vec![root])];
        while let Some((dir, rel)) = dirs.pop() {
            self.check_cancel()?;
            let listing = self.conn.sftp.read_dir(dir.as_str()).await.map_err(|error| sftp_failed(format!("Couldn't read {dir}"), error))?;
            for entry in listing {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let path = remote_join(&dir, &name);
                if let Some(problem) = local_name_problem(&name) {
                    self.skip(&path, problem);
                    continue;
                }
                let file_type = entry.file_type();
                let mut child = rel.clone();
                child.push(name);
                if file_type.is_dir() {
                    steps.push(Step { rel: child.clone(), source: path.clone(), kind: StepKind::Folder });
                    dirs.push((path, child));
                } else if file_type.is_file() {
                    let size = entry.metadata().len();
                    self.found(size);
                    steps.push(Step { rel: child, source: path, kind: StepKind::File { size, mode: None } });
                } else if file_type.is_symlink() {
                    self.skip(&path, "Links inside folders aren't followed");
                } else {
                    self.skip(&path, "Not a regular file");
                }
            }
        }
        Ok(steps)
    }

    async fn scan_upload(&mut self, source: &str) -> Result<Vec<Step>, Stop> {
        let source_path = Path::new(source);
        let root = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
            .ok_or_else(|| AppError::general(format!("{source} has no usable name")))?;
        let meta = tokio::fs::symlink_metadata(source_path).await.map_err(|error| io_failed(format!("Couldn't read {source}"), error))?;

        if meta.file_type().is_symlink() {
            let target = tokio::fs::metadata(source_path).await.map_err(|error| io_failed(format!("Couldn't follow the link {source}"), error))?;
            if !target.is_file() {
                return Err(AppError::general(format!("{source} is a link to a folder. Links to folders aren't followed.")).into());
            }
            let mode = super::local::mode(&target);
            return Ok(vec![Step { rel: vec![root], source: source.to_string(), kind: StepKind::File { size: target.len(), mode } }]);
        }
        if meta.is_file() {
            let mode = super::local::mode(&meta);
            return Ok(vec![Step { rel: vec![root], source: source.to_string(), kind: StepKind::File { size: meta.len(), mode } }]);
        }
        if !meta.is_dir() {
            return Err(AppError::general(format!("{source} isn't a file or a folder")).into());
        }

        let mut steps = vec![Step { rel: vec![root.clone()], source: source.to_string(), kind: StepKind::Folder }];
        let mut dirs = vec![(source_path.to_path_buf(), vec![root])];
        while let Some((dir, rel)) = dirs.pop() {
            self.check_cancel()?;
            let mut reader = tokio::fs::read_dir(&dir).await.map_err(|error| io_failed(format!("Couldn't read {}", dir.display()), error))?;
            while let Some(item) = reader.next_entry().await.map_err(|error| io_failed(format!("Couldn't read {}", dir.display()), error))? {
                let path = item.path();
                let shown = path.to_string_lossy().into_owned();
                let Ok(name) = item.file_name().into_string() else {
                    self.skip(&shown, "The name isn't valid UTF-8");
                    continue;
                };
                let Ok(metadata) = tokio::fs::symlink_metadata(&path).await else {
                    self.skip(&shown, "Couldn't be read");
                    continue;
                };
                let file_type = metadata.file_type();
                let mut child = rel.clone();
                child.push(name);
                if file_type.is_symlink() {
                    self.skip(&shown, "Links inside folders aren't followed");
                } else if file_type.is_dir() {
                    steps.push(Step { rel: child.clone(), source: shown, kind: StepKind::Folder });
                    dirs.push((path, child));
                } else if file_type.is_file() {
                    let mode = super::local::mode(&metadata);
                    self.found(metadata.len());
                    steps.push(Step { rel: child, source: shown, kind: StepKind::File { size: metadata.len(), mode } });
                } else {
                    self.skip(&shown, "Not a regular file");
                }
            }
        }
        Ok(steps)
    }

    fn join(&self, dir: &str, name: &str) -> String {
        match self.direction {
            Direction::Download => PathBuf::from(dir).join(name).to_string_lossy().into_owned(),
            Direction::Upload => remote_join(dir, name),
        }
    }

    /// Whether something is at `path` in the target, and if so whether it's a folder.
    async fn existing(&self, path: &str) -> Option<bool> {
        match self.direction {
            Direction::Download => tokio::fs::symlink_metadata(path).await.ok().map(|meta| meta.is_dir()),
            Direction::Upload => self.conn.sftp.symlink_metadata(path).await.ok().map(|meta| meta.is_dir()),
        }
    }

    async fn ask(&mut self, path: &str, is_dir: bool) -> Result<ConflictChoice, Stop> {
        if let Some(choice) = self.for_all {
            return Ok(choice);
        }
        let (sender, receiver) = oneshot::channel();
        if let Ok(mut slot) = self.control.answer.lock() {
            *slot = Some(sender);
        }
        let _ = self.events.send(TransferEvent::Conflict { path: path.to_string(), is_dir });
        let answer = tokio::select! {
            answer = receiver => answer.map_err(|_| Stop::Cancelled)?,
            _ = self.control.cancel.cancelled() => return Err(Stop::Cancelled),
        };
        if answer.for_all {
            self.for_all = Some(answer.choice);
        }
        Ok(answer.choice)
    }

    /// Where the item goes once a name clash is settled, or None when it's skipped. True means it replaces a file.
    async fn settle(&mut self, dir: &str, name: &str, is_dir: bool) -> Result<Option<(String, bool)>, Stop> {
        let wanted = self.join(dir, name);
        let Some(existing_dir) = self.existing(&wanted).await else {
            return Ok(Some((wanted, false)));
        };
        // Folders merge, and the files inside ask on their own.
        if is_dir && existing_dir {
            return Ok(Some((wanted, false)));
        }

        match self.ask(&wanted, is_dir).await? {
            ConflictChoice::Skip => {
                self.skip(&wanted, "Already there");
                Ok(None)
            }
            ConflictChoice::KeepBoth => {
                for number in 1..=MAX_NUMBERED {
                    let candidate = self.join(dir, &numbered_name(name, number));
                    if self.existing(&candidate).await.is_none() {
                        return Ok(Some((candidate, false)));
                    }
                }
                Err(AppError::general(format!("Couldn't find a free name next to {wanted}")).into())
            }
            ConflictChoice::Overwrite if is_dir || existing_dir => {
                let reason = if is_dir { "A file with this name is in the way" } else { "A folder with this name is in the way" };
                self.skip(&wanted, reason);
                Ok(None)
            }
            ConflictChoice::Overwrite => Ok(Some((wanted, true))),
        }
    }

    /// Swaps a finished copy in for the file it replaces. The old one stays until the new one is complete.
    async fn put_in_place(&self, part: &str, target: &str) -> Result<(), Stop> {
        match self.direction {
            // Rename replaces the target, and a link there is replaced rather than written through.
            Direction::Download => tokio::fs::rename(part, target).await.map_err(|error| {
                io_failed(format!("The new copy is saved as {part}, but it couldn't replace {target}"), error)
            }),
            // SFTP rename won't replace, so the old file goes first. Only a failed rename leaves the copy under its temporary name.
            Direction::Upload => {
                let sftp = &self.conn.sftp;
                sftp.remove_file(target)
                    .await
                    .map_err(|error| sftp_failed(format!("Couldn't replace {target}, the new copy is saved as {part}"), error))?;
                sftp.rename(part, target)
                    .await
                    .map_err(|error| sftp_failed(format!("The new copy is saved as {part}, but it couldn't be renamed to {target}"), error).into())
            }
        }
    }

    async fn make_folder(&mut self, source: &str, dir: &str, name: &str) -> Result<Option<String>, Stop> {
        let Some((target, _)) = self.settle(dir, name, true).await? else {
            return Ok(None);
        };
        if self.existing(&target).await.is_none() {
            match self.direction {
                Direction::Download => tokio::fs::create_dir(&target).await.map_err(|error| io_failed(format!("Couldn't create {target}"), error))?,
                Direction::Upload => self
                    .conn
                    .sftp
                    .create_dir(target.as_str())
                    .await
                    .map_err(|error| sftp_failed(format!("Couldn't create {target}"), error))?,
            }
        }
        self.progress(source);
        Ok(Some(target))
    }

    async fn copy_file(&mut self, source: &str, dir: &str, name: &str, mode: Option<u32>) -> Result<(), Stop> {
        let Some((target, replaces)) = self.settle(dir, name, false).await? else {
            return Ok(());
        };
        let write_to = if replaces { self.join(dir, &part_name(name)) } else { target.clone() };
        match self.direction {
            Direction::Download => self.download(source, &write_to).await?,
            Direction::Upload => self.upload(source, &write_to, mode).await?,
        }
        if replaces {
            self.put_in_place(&write_to, &target).await?;
        }
        self.files += 1;
        Ok(())
    }

    // New local files get the default mode, so a download never keeps setuid, setgid or the executable bit.
    async fn download(&mut self, source: &str, target: &str) -> Result<(), Stop> {
        let mut reader = self.conn.sftp.open(source).await.map_err(|error| sftp_failed(format!("Couldn't open {source}"), error))?;
        let mut writer = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .await
            .map_err(|error| io_failed(format!("Couldn't create {target}"), error))?;

        let mut result = self.pump(&mut reader, &mut writer, source).await;
        if result.is_ok() {
            result = writer.flush().await.map_err(|error| io_failed(format!("Couldn't write {target}"), error));
        }
        drop(writer);
        if result.is_err() {
            let _ = tokio::fs::remove_file(target).await;
        }
        result
    }

    async fn upload(&mut self, source: &str, target: &str, mode: Option<u32>) -> Result<(), Stop> {
        let mut reader = tokio::fs::File::open(source).await.map_err(|error| io_failed(format!("Couldn't open {source}"), error))?;
        let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE | OpenFlags::TRUNCATE;
        let mut writer = self
            .conn
            .sftp
            .open_with_flags(target, flags)
            .await
            .map_err(|error| sftp_failed(format!("Couldn't create {target}"), error))?;

        let mut result = self.pump(&mut reader, &mut writer, source).await;
        if result.is_ok() {
            result = writer.shutdown().await.map_err(|error| io_failed(format!("Couldn't finish writing {target}"), error));
        }
        drop(writer);
        if result.is_err() {
            let _ = self.conn.sftp.remove_file(target).await;
            return result;
        }

        if let Some(mode) = mode {
            let mut attributes = FileAttributes::empty();
            attributes.permissions = Some(mode & 0o777);
            self.conn
                .sftp
                .set_metadata(target, attributes)
                .await
                .map_err(|error| sftp_failed(format!("Couldn't set the permissions of {target}"), error))?;
        }
        Ok(())
    }

    async fn pump<R, W>(&mut self, reader: &mut R, writer: &mut W, current: &str) -> Result<(), Stop>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            self.check_cancel()?;
            let read = tokio::select! {
                read = reader.read(&mut self.buf) => read,
                _ = self.control.cancel.cancelled() => return Err(Stop::Cancelled),
            };
            let count = read.map_err(|error| io_failed(format!("Reading {current} failed"), error))?;
            if count == 0 {
                return Ok(());
            }
            writer
                .write_all(&self.buf[..count])
                .await
                .map_err(|error| io_failed(format!("Writing {current} failed"), error))?;
            self.bytes += count as u64;
            self.progress(current);
        }
    }
}
