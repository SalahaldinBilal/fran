use std::path::{Component, Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Crumb {
    pub label: String,
    pub path: String,
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

/// Why a name from the server can't be used as a file name on this computer.
pub fn local_name_problem(name: &str) -> Option<&'static str> {
    name_problem(name, cfg!(windows))
}

fn name_problem(name: &str, windows: bool) -> Option<&'static str> {
    if name.is_empty() {
        return Some("The name is empty");
    }
    if name == "." || name == ".." {
        return Some("The name points at a folder above it");
    }
    if name.contains('/') || name.contains('\\') {
        return Some("The name contains a path separator");
    }
    if name.contains('\0') {
        return Some("The name contains a NUL character");
    }
    if name.chars().any(char::is_control) {
        return Some("The name contains control characters");
    }
    if !windows {
        return None;
    }
    if name.contains(':') {
        return Some("The name contains a colon, which Windows reads as a drive or a stream");
    }
    if name.chars().any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*')) {
        return Some("The name contains a character Windows doesn't allow");
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("Windows doesn't allow names that end in a dot or a space");
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    if WINDOWS_RESERVED.iter().any(|reserved| reserved.eq_ignore_ascii_case(stem)) {
        return Some("The name is reserved on Windows");
    }
    None
}

/// Why a typed name can't be used for a file on the server.
pub fn remote_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("The name is empty");
    }
    if name == "." || name == ".." {
        return Some("The name points at a folder above it");
    }
    if name.contains('/') {
        return Some("The name contains a slash");
    }
    if name.contains('\0') {
        return Some("The name contains a NUL character");
    }
    None
}

pub fn remote_join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

pub fn remote_name(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("")
}

pub fn remote_parent(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let index = trimmed.rfind('/')?;
    Some(if index == 0 { "/".to_string() } else { trimmed[..index].to_string() })
}

pub fn remote_crumbs(path: &str) -> Vec<Crumb> {
    if !path.starts_with('/') {
        return vec![Crumb { label: path.to_string(), path: path.to_string() }];
    }
    let mut crumbs = vec![Crumb { label: "/".to_string(), path: "/".to_string() }];
    let mut current = String::new();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        current.push('/');
        current.push_str(segment);
        crumbs.push(Crumb { label: segment.to_string(), path: current.clone() });
    }
    crumbs
}

pub fn local_crumbs(path: &Path) -> Vec<Crumb> {
    let mut crumbs: Vec<Crumb> = Vec::new();
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let text = current.to_string_lossy().into_owned();
        match component {
            Component::Prefix(prefix) => crumbs.push(Crumb {
                label: prefix.as_os_str().to_string_lossy().into_owned(),
                path: text,
            }),
            // After a drive prefix the root belongs to it, so `C:` opens `C:\`.
            Component::RootDir => match crumbs.last_mut() {
                Some(last) => last.path = text,
                None => crumbs.push(Crumb { label: "/".to_string(), path: text }),
            },
            Component::Normal(name) => crumbs.push(Crumb {
                label: name.to_string_lossy().into_owned(),
                path: text,
            }),
            Component::CurDir | Component::ParentDir => {}
        }
    }
    crumbs
}

/// Drops the `\\?\` prefix that canonicalize adds on Windows.
pub fn simplify_local(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(text) = path.to_str() {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            if rest.as_bytes().get(1) == Some(&b':') {
                return PathBuf::from(rest);
            }
        }
    }
    path
}

/// `report.txt` becomes `report (2).txt`. A leading dot isn't an extension.
pub fn numbered_name(name: &str, number: u32) -> String {
    match name.rfind('.') {
        Some(index) if index > 0 => format!("{} ({number}){}", &name[..index], &name[index..]),
        _ => format!("{name} ({number})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_names_that_escape_the_folder_are_refused() {
        for name in ["", ".", "..", "../evil", "a/b", "a\\b", "a\0b", "line\nbreak"] {
            assert!(name_problem(name, false).is_some(), "{name:?}");
            assert!(name_problem(name, true).is_some(), "{name:?}");
        }
        assert_eq!(name_problem("notes.txt", false), None);
        assert_eq!(name_problem(".bashrc", false), None);
        assert_eq!(name_problem("..hidden", false), None);
    }

    #[test]
    fn windows_only_rules() {
        for name in ["C:", "C:evil", "file.txt:stream", "CON", "con.txt", "Nul", "COM1.log", "lpt9", "COM¹", "a?b", "a|b", "trailing.", "trailing "] {
            assert!(name_problem(name, true).is_some(), "{name:?}");
            assert_eq!(name_problem(name, false), None, "{name:?}");
        }
        assert_eq!(name_problem("console.txt", true), None);
        assert_eq!(name_problem("COM10", true), None);
    }

    #[test]
    fn remote_names() {
        assert!(remote_name_problem("a/b").is_some());
        assert!(remote_name_problem("..").is_some());
        assert_eq!(remote_name_problem("a\\b"), None);
    }

    #[test]
    fn remote_paths() {
        assert_eq!(remote_join("/home/me", "a"), "/home/me/a");
        assert_eq!(remote_join("/", "a"), "/a");
        assert_eq!(remote_name("/home/me/a.txt"), "a.txt");
        assert_eq!(remote_name("/home/me/"), "me");
        assert_eq!(remote_parent("/home/me"), Some("/home".to_string()));
        assert_eq!(remote_parent("/home"), Some("/".to_string()));
        assert_eq!(remote_parent("/"), None);
        let crumbs = remote_crumbs("/home/me");
        assert_eq!(crumbs.iter().map(|crumb| crumb.path.as_str()).collect::<Vec<_>>(), ["/", "/home", "/home/me"]);
    }

    #[test]
    fn numbered_names() {
        assert_eq!(numbered_name("report.txt", 1), "report (1).txt");
        assert_eq!(numbered_name("archive.tar.gz", 2), "archive.tar (2).gz");
        assert_eq!(numbered_name(".env", 1), ".env (1)");
        assert_eq!(numbered_name("folder", 3), "folder (3)");
    }

    #[cfg(unix)]
    #[test]
    fn local_crumbs_unix() {
        let crumbs = local_crumbs(Path::new("/home/me"));
        assert_eq!(crumbs.iter().map(|crumb| crumb.path.as_str()).collect::<Vec<_>>(), ["/", "/home", "/home/me"]);
    }

    #[cfg(windows)]
    #[test]
    fn local_crumbs_windows() {
        let crumbs = local_crumbs(Path::new(r"C:\Users\me"));
        assert_eq!(crumbs[0], Crumb { label: "C:".to_string(), path: r"C:\".to_string() });
        assert_eq!(crumbs.last().map(|crumb| crumb.path.as_str()), Some(r"C:\Users\me"));
        assert_eq!(simplify_local(PathBuf::from(r"\\?\C:\Users")), PathBuf::from(r"C:\Users"));
        assert_eq!(simplify_local(PathBuf::from(r"\\?\UNC\server\share")), PathBuf::from(r"\\server\share"));
    }
}
