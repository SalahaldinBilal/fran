use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::json_store::JsonStore;
use crate::ssh_store::SshStore;

pub const SNIPPET_FILE_VERSION: u32 = 1;

/// Plain text on disk, so the UI tells people not to put secrets in them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    #[serde(default)]
    pub id: String,
    pub label: String,
    pub command: String,
    /// Ask before running it.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnippetFile {
    pub version: u32,
    pub snippets: Vec<Snippet>,
}

impl Default for SnippetFile {
    fn default() -> Self {
        Self {
            version: SNIPPET_FILE_VERSION,
            snippets: Vec::new(),
        }
    }
}

pub type SnippetStore = JsonStore<SnippetFile>;

impl SnippetStore {
    pub fn exists(&self, id: &str) -> AppResult<bool> {
        self.read(|file| file.snippets.iter().any(|snippet| snippet.id == id))
    }
}

#[tauri::command]
pub async fn list_snippets(store: State<'_, Arc<SnippetStore>>) -> AppResult<Vec<Snippet>> {
    store.read(|file| file.snippets.clone())
}

#[tauri::command]
pub async fn save_snippet(store: State<'_, Arc<SnippetStore>>, mut snippet: Snippet) -> AppResult<Snippet> {
    snippet.label = snippet.label.trim().to_string();
    snippet.command = snippet.command.trim_end().to_string();
    if snippet.command.trim().is_empty() {
        return Err(AppError::general("A snippet needs a command"));
    }
    if snippet.label.is_empty() {
        snippet.label = snippet.command.lines().next().unwrap_or_default().trim().chars().take(40).collect();
    }
    if snippet.id.is_empty() {
        snippet.id = uuid::Uuid::new_v4().to_string();
    }

    let saved = snippet.clone();
    store.update(move |file| {
        match file.snippets.iter_mut().find(|existing| existing.id == snippet.id) {
            Some(existing) => *existing = snippet,
            None => file.snippets.push(snippet),
        }
        Ok(())
    })?;
    Ok(saved)
}

#[tauri::command]
pub async fn delete_snippet(
    store: State<'_, Arc<SnippetStore>>,
    ssh_store: State<'_, Arc<SshStore>>,
    id: String,
) -> AppResult<()> {
    let users = ssh_store.read(|file| {
        file.hosts
            .iter()
            .filter(|host| host.startup_snippet_id.as_deref() == Some(id.as_str()))
            .map(|host| host.label.clone())
            .collect::<Vec<_>>()
    })?;
    if !users.is_empty() {
        return Err(AppError::general(format!(
            "This snippet runs on connect for {}. Pick something else there first.",
            users.join(", ")
        )));
    }
    store.update(move |file| {
        file.snippets.retain(|snippet| snippet.id != id);
        Ok(())
    })
}
