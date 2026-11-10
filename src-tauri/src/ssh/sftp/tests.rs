use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode};
use tauri::ipc::{Channel, InvokeResponseBody};

use super::SftpConn;
use super::transfer::{self, Control, Direction};

const DIR_MODE: u32 = 0o040_755;
const FILE_MODE: u32 = 0o100_644;

/// A server whose listing holds names a real OpenSSH server can't, to check they never escape the target folder.
#[derive(Default)]
struct FakeServer {
    listed: HashSet<String>,
}

fn attrs(mode: u32, size: u64) -> FileAttributes {
    FileAttributes { size: Some(size), permissions: Some(mode), ..Default::default() }
}

fn children() -> Vec<(&'static str, &'static [u8])> {
    vec![("ok.txt", b"hello"), ("../evil", b"pwned"), ("a/b", b"pwned")]
}

fn content(path: &str) -> Option<&'static [u8]> {
    let name = path.strip_prefix("/data/")?;
    children().into_iter().find(|(child, _)| *child == name).map(|(_, data)| data)
}

fn lookup(path: &str) -> Option<FileAttributes> {
    match path {
        "/" | "/data" => Some(attrs(DIR_MODE, 0)),
        _ => content(path).map(|data| attrs(FILE_MODE, data.len() as u64)),
    }
}

impl russh_sftp::server::Handler for FakeServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = if path == "." { "/".to_string() } else { path };
        Ok(Name { id, files: vec![File::dummy(path)] })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        lookup(&path).map(|attrs| Attrs { id, attrs }).ok_or(StatusCode::NoSuchFile)
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if path != "/data" {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(Handle { id, handle: format!("dir:{path}") })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        if !self.listed.insert(handle) {
            return Err(StatusCode::Eof);
        }
        let files = children().into_iter().map(|(name, data)| File::new(name, attrs(FILE_MODE, data.len() as u64))).collect();
        Ok(Name { id, files })
    }

    async fn open(&mut self, id: u32, filename: String, _pflags: OpenFlags, _attrs: FileAttributes) -> Result<Handle, Self::Error> {
        content(&filename).ok_or(StatusCode::NoSuchFile)?;
        Ok(Handle { id, handle: format!("file:{filename}") })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let data = handle.strip_prefix("file:").and_then(content).ok_or(StatusCode::Failure)?;
        let start = offset as usize;
        if start >= data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(data.len());
        Ok(Data { id, data: data[start..end].to_vec() })
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        Ok(Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() })
    }
}

async fn fake_conn() -> Arc<SftpConn> {
    let (client, server) = tokio::io::duplex(256 * 1024);
    tokio::spawn(russh_sftp::server::run(server, FakeServer::default()));
    SftpConn::detached(client).await.expect("the fake server starts")
}

fn collecting_channel() -> (Channel<transfer::TransferEvent>, Arc<Mutex<Vec<serde_json::Value>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let channel = Channel::new(move |body| {
        if let InvokeResponseBody::Json(json) = body
            && let Ok(value) = serde_json::from_str(&json)
        {
            sink.lock().unwrap().push(value);
        }
        Ok(())
    });
    (channel, events)
}

#[tokio::test]
async fn names_from_the_server_never_leave_the_target_folder() {
    let conn = fake_conn().await;
    let root = std::env::temp_dir().join(format!("fran-sftp-{}", uuid::Uuid::new_v4()));
    let target = root.join("downloads");
    std::fs::create_dir_all(&target).unwrap();

    let (channel, events) = collecting_channel();
    let control = Arc::new(Control::new("fake".to_string()));
    transfer::run(conn, control, Direction::Download, "/data".to_string(), target.to_string_lossy().into_owned(), channel).await;

    let events = events.lock().unwrap().clone();
    let last = events.last().expect("the transfer reports how it ended");
    assert_eq!(last["kind"], "finished", "{events:?}");
    assert_eq!(last["files"], 1);

    let skipped: Vec<&str> = events.iter().filter(|event| event["kind"] == "skipped").filter_map(|event| event["path"].as_str()).collect();
    assert!(skipped.iter().any(|path| path.ends_with("../evil")), "{skipped:?}");
    assert!(skipped.iter().any(|path| path.ends_with("a/b")), "{skipped:?}");

    assert_eq!(std::fs::read(target.join("data").join("ok.txt")).unwrap(), b"hello");
    assert!(!root.join("evil").exists());
    assert!(!target.join("evil").exists());
    assert!(!target.join("data").join("a").exists());
    let written: HashMap<String, ()> = walk(&root).into_iter().map(|path| (path, ())).collect();
    assert_eq!(written.len(), 1, "{written:?}");

    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn previews_refuse_folders_and_list_reports_entries() {
    let conn = fake_conn().await;
    assert!(conn.preview("/data").await.is_err());
    assert_eq!(conn.preview("/data/ok.txt").await.unwrap(), "hello");
    let listing = conn.list("/data").await.unwrap();
    assert_eq!(listing.entries.len(), 3);
    assert_eq!(listing.parent.as_deref(), Some("/"));
}

fn walk(root: &std::path::Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for item in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = item.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path.to_string_lossy().into_owned());
            }
        }
    }
    files
}
