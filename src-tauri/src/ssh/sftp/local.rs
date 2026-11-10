use std::{
    fs,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use tauri::{AppHandle, Manager};

use super::paths::{Crumb, local_crumbs, local_name_problem, simplify_local};
use super::{EntryKind, FileEntry, Listing, TreeCount};
use crate::error::{AppError, AppResult};

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|error| AppError::general(format!("The file task stopped: {error}")))?
}

fn io_failed(what: impl std::fmt::Display, error: std::io::Error) -> AppError {
    AppError::general(format!("{what}: {error}"))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(windows)]
fn hidden_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
}

#[cfg(not(windows))]
fn hidden_attribute(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
pub fn mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
pub fn mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

fn kind(file_type: fs::FileType) -> EntryKind {
    if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Dir
    } else if file_type.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

fn entry(path: PathBuf, name: String, metadata: &fs::Metadata) -> FileEntry {
    let kind = kind(metadata.file_type());
    FileEntry {
        hidden: name.starts_with('.') || hidden_attribute(metadata),
        link_dir: kind == EntryKind::Symlink && fs::metadata(&path).map(|target| target.is_dir()).unwrap_or(false),
        size: (kind == EntryKind::File).then(|| metadata.len()),
        modified: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|elapsed| elapsed.as_millis() as i64),
        mode: mode(metadata),
        path: text(&path),
        name,
        kind,
    }
}

fn list(path: &Path) -> AppResult<Listing> {
    let path = simplify_local(fs::canonicalize(path).map_err(|error| io_failed(format!("Couldn't open {}", path.display()), error))?);
    let reader = fs::read_dir(&path).map_err(|error| io_failed(format!("Couldn't open {}", path.display()), error))?;
    let entries = reader
        .flatten()
        .filter_map(|item| {
            let metadata = item.metadata().ok()?;
            Some(entry(item.path(), item.file_name().to_string_lossy().into_owned(), &metadata))
        })
        .collect();
    Ok(Listing {
        crumbs: local_crumbs(&path),
        parent: path.parent().map(text),
        path: text(&path),
        entries,
    })
}

fn start_path(app: &AppHandle, path: Option<String>) -> AppResult<PathBuf> {
    let home = || app.path().home_dir().map_err(|error| AppError::general(format!("Couldn't find the home folder: {error}")));
    match path.as_deref().map(str::trim) {
        None | Some("") | Some("~") => home(),
        Some(typed) => match typed.strip_prefix("~/").or_else(|| typed.strip_prefix("~\\")) {
            Some(rest) => Ok(home()?.join(rest)),
            None => Ok(PathBuf::from(typed)),
        },
    }
}

fn checked_name(name: &str) -> AppResult<&str> {
    let name = name.trim();
    match local_name_problem(name) {
        Some(problem) => Err(AppError::general(problem)),
        None => Ok(name),
    }
}

pub fn count_tree(root: &Path) -> AppResult<TreeCount> {
    let mut count = TreeCount::default();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        count.folders += 1;
        let reader = fs::read_dir(&dir).map_err(|error| io_failed(format!("Couldn't read {}", dir.display()), error))?;
        for item in reader.flatten() {
            let Ok(file_type) = item.file_type() else { continue };
            if file_type.is_dir() {
                dirs.push(item.path());
            } else {
                count.files += 1;
                count.bytes += item.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            }
        }
    }
    Ok(count)
}

#[tauri::command]
pub async fn local_list(app: AppHandle, path: Option<String>) -> AppResult<Listing> {
    let start = start_path(&app, path)?;
    blocking(move || list(&start)).await
}

/// Places the local pane can start from: every drive on Windows, `/` elsewhere.
#[tauri::command]
pub async fn local_roots() -> AppResult<Vec<Crumb>> {
    blocking(|| {
        if cfg!(windows) {
            Ok((b'A'..=b'Z')
                .map(|letter| format!("{}:\\", letter as char))
                .filter(|root| Path::new(root).exists())
                .map(|root| Crumb { label: root.trim_end_matches('\\').to_string(), path: root })
                .collect())
        } else {
            Ok(vec![Crumb { label: "/".to_string(), path: "/".to_string() }])
        }
    })
    .await
}

#[tauri::command]
pub async fn local_mkdir(dir: String, name: String) -> AppResult<String> {
    blocking(move || {
        let path = Path::new(&dir).join(checked_name(&name)?);
        fs::create_dir(&path).map_err(|error| io_failed(format!("Couldn't create {}", path.display()), error))?;
        Ok(text(&path))
    })
    .await
}

#[tauri::command]
pub async fn local_rename(path: String, name: String) -> AppResult<String> {
    blocking(move || {
        let from = PathBuf::from(&path);
        let parent = from.parent().ok_or_else(|| AppError::general("This can't be renamed"))?;
        let to = parent.join(checked_name(&name)?);
        // fs::rename replaces an existing file, so a taken name is refused first.
        if to != from && fs::symlink_metadata(&to).is_ok() {
            return Err(AppError::general(format!("{} already exists", to.display())));
        }
        fs::rename(&from, &to).map_err(|error| io_failed(format!("Couldn't rename {}", from.display()), error))?;
        Ok(text(&to))
    })
    .await
}

#[tauri::command]
pub async fn local_remove(path: String, recursive: bool) -> AppResult<()> {
    blocking(move || {
        let path = PathBuf::from(&path);
        if path.parent().is_none() {
            return Err(AppError::general("A drive or the root folder can't be deleted"));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| io_failed(format!("Couldn't read {}", path.display()), error))?;
        let file_type = metadata.file_type();
        let result = if file_type.is_symlink() {
            // A link to a folder on Windows is removed as a folder. Neither call touches what it points at.
            fs::remove_file(&path).or_else(|_| fs::remove_dir(&path))
        } else if file_type.is_dir() {
            if recursive { fs::remove_dir_all(&path) } else { fs::remove_dir(&path) }
        } else {
            fs::remove_file(&path)
        };
        result.map_err(|error| io_failed(format!("Couldn't delete {}", path.display()), error))
    })
    .await
}

#[tauri::command]
pub async fn local_count(path: String) -> AppResult<TreeCount> {
    blocking(move || count_tree(Path::new(&path))).await
}
