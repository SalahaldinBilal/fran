use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

pub fn home_dir() -> Option<PathBuf> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(variable).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// `~/` and OpenSSH's `%d` become the home folder. Other tokens stay as they are.
pub fn expand_home(path: &str) -> String {
    let Some(home) = home_dir() else {
        return path.to_string();
    };
    let home = home.to_string_lossy();
    let path = path.trim();
    let expanded = match path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        Some(rest) => format!("{home}/{rest}"),
        None if path == "~" => home.to_string(),
        None => path.to_string(),
    };
    expanded.replace("%d", &home)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigEntry {
    pub alias: String,
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Vec<JumpSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedConfig {
    pub entries: Vec<ConfigEntry>,
    /// Patterns like `*.internal` or `!bastion`, listed but not imported.
    pub skipped_patterns: Vec<String>,
}

impl ParsedConfig {
    pub fn entry(&self, alias: &str) -> Option<&ConfigEntry> {
        self.entries.iter().find(|entry| entry.alias == alias)
    }
}

fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let split = line.find(|character: char| character.is_whitespace() || character == '=')?;
    let key = line[..split].to_ascii_lowercase();
    let value = line[split..].trim_start_matches(|character: char| character.is_whitespace() || character == '=').trim();
    let value = value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(value);
    Some((key, value.to_string()))
}

fn parse_jump(spec: &str) -> Option<JumpSpec> {
    let spec = spec.trim().trim_start_matches("ssh://");
    if spec.is_empty() {
        return None;
    }
    let (user, rest) = match spec.rsplit_once('@') {
        Some((user, rest)) => (Some(user.to_string()), rest),
        None => (None, spec),
    };
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, after) = inner.split_once(']')?;
        (host.to_string(), after.strip_prefix(':').and_then(|port| port.parse().ok()))
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host.to_string(), port.parse().ok()),
            _ => (rest.to_string(), None),
        }
    };
    Some(JumpSpec { user, host, port })
}

fn is_pattern(alias: &str) -> bool {
    alias.contains(['*', '?']) || alias.starts_with('!')
}

/// Reads `Host` blocks. `Match` blocks are skipped. `Include` is followed one level, relative to `base`.
pub fn parse(text: &str, base: &Path) -> ParsedConfig {
    parse_level(text, base, true)
}

fn parse_level(text: &str, base: &Path, follow_includes: bool) -> ParsedConfig {
    let mut parsed = ParsedConfig::default();
    let mut current: Vec<usize> = Vec::new();
    let mut in_match = false;

    for line in text.lines() {
        let Some((key, value)) = split_line(line) else {
            continue;
        };
        match key.as_str() {
            "host" => {
                in_match = false;
                current.clear();
                for alias in value.split_whitespace() {
                    if is_pattern(alias) {
                        if !parsed.skipped_patterns.iter().any(|seen| seen == alias) {
                            parsed.skipped_patterns.push(alias.to_string());
                        }
                    } else if parsed.entry(alias).is_none() {
                        parsed.entries.push(ConfigEntry {
                            alias: alias.to_string(),
                            ..Default::default()
                        });
                        current.push(parsed.entries.len() - 1);
                    }
                }
            }
            "match" => {
                in_match = true;
                current.clear();
            }
            "include" if follow_includes && !in_match => {
                for pattern in value.split_whitespace() {
                    for path in include_paths(pattern, base) {
                        if let Ok(included) = fs::read_to_string(&path) {
                            let nested = parse_level(&included, base, false);
                            for entry in nested.entries {
                                if parsed.entry(&entry.alias).is_none() {
                                    parsed.entries.push(entry);
                                }
                            }
                            for pattern in nested.skipped_patterns {
                                if !parsed.skipped_patterns.contains(&pattern) {
                                    parsed.skipped_patterns.push(pattern);
                                }
                            }
                        }
                    }
                }
            }
            _ if in_match => {}
            _ => {
                // OpenSSH keeps the first value it sees for each setting.
                for &index in &current {
                    let entry = &mut parsed.entries[index];
                    match key.as_str() {
                        "hostname" if entry.host_name.is_none() => entry.host_name = Some(value.clone()),
                        "user" if entry.user.is_none() => entry.user = Some(value.clone()),
                        "port" if entry.port.is_none() => entry.port = value.parse().ok(),
                        "identityfile" if entry.identity_file.is_none() => entry.identity_file = Some(value.clone()),
                        "proxyjump" if entry.proxy_jump.is_empty() && !value.eq_ignore_ascii_case("none") => {
                            entry.proxy_jump = value.split(',').filter_map(parse_jump).collect();
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    parsed
}

/// A relative include is under `~/.ssh`. A trailing `*` file name is matched in its folder.
fn include_paths(pattern: &str, base: &Path) -> Vec<PathBuf> {
    let expanded = expand_home(pattern);
    let path = Path::new(&expanded);
    let path = if path.is_absolute() { path.to_path_buf() } else { base.join(path) };

    let name = path.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
    if !name.contains('*') {
        return vec![path];
    }
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    let (prefix, suffix) = name.split_once('*').unwrap_or((&name, ""));
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|candidate| {
                    let file = candidate.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
                    candidate.is_file() && file.starts_with(prefix) && file.ends_with(suffix)
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCandidate {
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<String>,
    pub jumps: Vec<String>,
    /// Why it can't be imported, or None when it can.
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub path: String,
    pub found: bool,
    pub candidates: Vec<ImportCandidate>,
    pub skipped_patterns: Vec<String>,
}

pub fn local_user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_text(text: &str) -> ParsedConfig {
        parse(text, Path::new("/nonexistent"))
    }

    #[test]
    fn reads_host_blocks() {
        let parsed = parse_text(
            "# comment\nHost prod-bastion\n  HostName bastion.acme.io\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519\n\nHost pi\n  HostName=192.168.1.20\n  User = pi\n  Port 2222\n",
        );
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].host_name.as_deref(), Some("bastion.acme.io"));
        assert_eq!(parsed.entries[0].user.as_deref(), Some("deploy"));
        assert_eq!(parsed.entries[0].identity_file.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(parsed.entries[1].port, Some(2222));
        assert_eq!(parsed.entries[1].user.as_deref(), Some("pi"));
    }

    #[test]
    fn keywords_are_case_insensitive_and_first_value_wins() {
        let parsed = parse_text("host a\n USER one\n user two\n hostname \"a.example\"\n");
        assert_eq!(parsed.entries[0].user.as_deref(), Some("one"));
        assert_eq!(parsed.entries[0].host_name.as_deref(), Some("a.example"));
    }

    #[test]
    fn patterns_are_listed_not_imported() {
        let parsed = parse_text("Host web *.internal !old\n User x\nHost *\n User y\n");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].alias, "web");
        assert_eq!(parsed.entries[0].user.as_deref(), Some("x"));
        assert_eq!(parsed.skipped_patterns, ["*.internal", "!old", "*"]);
    }

    #[test]
    fn match_blocks_are_skipped() {
        let parsed = parse_text("Host a\n User one\nMatch host a exec true\n User other\n Port 99\n");
        assert_eq!(parsed.entries[0].user.as_deref(), Some("one"));
        assert_eq!(parsed.entries[0].port, None);
    }

    #[test]
    fn proxy_jump_lists() {
        let parsed = parse_text("Host api\n ProxyJump bastion,ops@edge.acme.io:2200,[fe80::1]:22\nHost direct\n ProxyJump none\n");
        let jumps = &parsed.entries[0].proxy_jump;
        assert_eq!(jumps.len(), 3);
        assert_eq!(jumps[0], JumpSpec { user: None, host: "bastion".to_string(), port: None });
        assert_eq!(jumps[1], JumpSpec { user: Some("ops".to_string()), host: "edge.acme.io".to_string(), port: Some(2200) });
        assert_eq!(jumps[2].host, "fe80::1");
        assert!(parsed.entries[1].proxy_jump.is_empty());
    }

    #[test]
    fn includes_are_followed_one_level() {
        let dir = std::env::temp_dir().join(format!("fran-ssh-config-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(dir.join("conf.d")).unwrap();
        fs::write(dir.join("conf.d").join("work.conf"), "Host work\n HostName work.example\nInclude deeper\n").unwrap();
        fs::write(dir.join("deeper"), "Host deeper\n").unwrap();

        let parsed = parse("Include conf.d/*.conf\nHost home\n", &dir);
        let aliases: Vec<_> = parsed.entries.iter().map(|entry| entry.alias.as_str()).collect();
        assert_eq!(aliases, ["work", "home"]);
        fs::remove_dir_all(dir).unwrap();
    }
}
