pub mod client;
pub mod commands;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use self::client::{Client, Place, Refused, Remote};
use super::{Incoming, Outgoing, ProblemReason, Provider, Pulled, Pushed, vault_prefix};
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::secrets::SecretsStore;
use crate::ssh_store::now_millis;
use crate::sync::items::{Item, secret_value_key};
use crate::sync::state::{Category, Cloud};
use crate::vault::Vault;

const TOKEN_SLOT: &str = "token";
const SEEN_SLOT: &str = "seen";
/// Doppler's limit for one value.
const MAX_VALUE_BYTES: usize = 50 * 1024;

/// What `sync.json` keeps about a Doppler cloud. The token is in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub project: String,
    pub config: String,
}

impl Config {
    pub fn of(cloud: &Cloud) -> AppResult<Self> {
        serde_json::from_value(cloud.config.clone()).map_err(|_| AppError::general("This cloud's saved details are damaged. Remove it and add it again."))
    }

    /// The same on every computer that added this project and config.
    pub fn identity(&self) -> String {
        format!("doppler:{}:{}", self.project, self.config)
    }

    pub fn place(&self) -> Place {
        Place { project: self.project.clone(), config: self.config.clone() }
    }
}

fn no_token() -> AppError {
    AppError::new("This computer has no token for that Doppler config. Enter one.", ErrorDetail::SyncSignedOut)
}

pub fn token_id(cloud_id: &str) -> String {
    format!("{}{TOKEN_SLOT}", vault_prefix(cloud_id))
}

pub fn token(cloud_id: &str, vault: &Vault) -> AppResult<Zeroizing<String>> {
    vault.get(&token_id(cloud_id))?.ok_or_else(no_token)
}

/// The value Doppler held the last time this computer looked, and how many times it has changed since the link was made.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Seen {
    name: String,
    revision: u64,
    value: String,
    #[serde(default)]
    computed: bool,
}

impl Drop for Seen {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

struct Linked {
    key: String,
    secret_id: String,
    name: String,
}

pub struct Doppler {
    cloud_id: String,
    identity: String,
    place: Place,
    client: Client,
    vault: Arc<Vault>,
    secrets: Arc<SecretsStore>,
    /// The revision the engine has for each item, for when the vault's own note is gone.
    known: BTreeMap<String, u64>,
}

pub fn open(cloud: &Cloud, vault: Arc<Vault>, secrets: Arc<SecretsStore>) -> AppResult<Arc<dyn Provider>> {
    let client = Client::new(&token(&cloud.id, &vault)?)?;
    Ok(Arc::new(Doppler::with(cloud, client, vault, secrets)?))
}

impl Doppler {
    pub(super) fn with(cloud: &Cloud, client: Client, vault: Arc<Vault>, secrets: Arc<SecretsStore>) -> AppResult<Self> {
        let config = Config::of(cloud)?;
        Ok(Self {
            cloud_id: cloud.id.clone(),
            identity: cloud.identity.clone(),
            place: config.place(),
            client,
            vault,
            secrets,
            known: cloud.records.iter().map(|(key, record)| (key.clone(), record.revision)).collect(),
        })
    }

    fn links(&self) -> AppResult<Vec<Linked>> {
        self.secrets.read(|file| {
            let linked = file.secrets.iter().filter_map(|secret| Some((secret, secret.link.as_ref().filter(|link| link.cloud == self.identity)?)));
            linked.map(|(secret, link)| Linked { key: secret_value_key(&secret.id), secret_id: secret.id.clone(), name: link.name.clone() }).collect()
        })
    }

    fn link_of(&self, key: &str) -> AppResult<Option<Linked>> {
        Ok(self.links()?.into_iter().find(|linked| linked.key == key))
    }

    fn seen_id(&self, secret_id: &str) -> String {
        format!("{}{SEEN_SLOT}:{secret_id}", vault_prefix(&self.cloud_id))
    }

    /// None when nothing was seen yet, or when the secret has since been linked to another name.
    fn seen(&self, linked: &Linked) -> AppResult<Option<Seen>> {
        let stored = self.vault.get(&self.seen_id(&linked.secret_id))?;
        Ok(stored.and_then(|stored| serde_json::from_str::<Seen>(&stored).ok()).filter(|seen| seen.name == linked.name))
    }

    fn save_seen(&self, linked: &Linked, revision: u64, remote: &Remote) -> AppResult<()> {
        let seen = Seen { name: linked.name.clone(), revision, value: remote.value.clone(), computed: remote.computed };
        let stored = Zeroizing::new(serde_json::to_string(&seen)?);
        self.vault.set(&self.seen_id(&linked.secret_id), &stored)
    }

    fn known(&self, key: &str) -> u64 {
        self.known.get(key).copied().unwrap_or(0)
    }

    /// Doppler has no revisions. One is counted here: it goes up each time the value read differs from the last one seen.
    fn revision_for(&self, linked: &Linked, remote: &Remote) -> AppResult<u64> {
        let seen = self.seen(linked)?;
        if let Some(seen) = &seen
            && seen.value == remote.value
            && seen.computed == remote.computed
        {
            return Ok(seen.revision);
        }
        let revision = seen.map(|seen| seen.revision).unwrap_or(0).max(self.known(&linked.key)) + 1;
        self.save_seen(linked, revision, remote)?;
        Ok(revision)
    }

    async fn current(&self, name: &str) -> AppResult<Option<Remote>> {
        Ok(self.client.secrets(&self.place, &[name.to_string()]).await?.remove(name))
    }

    /// Makes the next pull hand Doppler's value back as a newer revision, so an edit that can't go up is undone and kept in "Replaced by sync".
    fn doppler_wins(&self, linked: &Linked, remote: &Remote, base: u64) -> AppResult<()> {
        let seen = self.seen(linked)?.map(|seen| seen.revision).unwrap_or(0);
        self.save_seen(linked, seen.max(base).max(self.known(&linked.key)) + 1, remote)
    }

    async fn push_one(&self, change: &Outgoing) -> AppResult<Pushed> {
        let accepted = Pushed::Accepted { revision: change.base_revision + 1 };
        let Some(linked) = self.link_of(&change.key)? else {
            // Unlinked or deleted here. The secret in Doppler is left alone.
            return Ok(accepted);
        };
        if change.deleted {
            self.vault.remove(&self.seen_id(&linked.secret_id))?;
            return Ok(accepted);
        }
        let value = change.content.get("value").and_then(Value::as_str).unwrap_or_default();
        if value.len() > MAX_VALUE_BYTES {
            return Ok(Pushed::TooLarge);
        }
        let seen = self.seen(&linked)?;
        if let Some(seen) = seen.as_ref().filter(|seen| seen.computed) {
            let remote = Remote { value: seen.value.clone(), computed: true };
            self.doppler_wins(&linked, &remote, change.base_revision)?;
            return Ok(Pushed::Conflict);
        }
        // Never seen here, so there's no original value to guard with. A name Doppler already has keeps its value.
        if seen.is_none()
            && let Some(remote) = self.current(&linked.name).await?
        {
            if remote.value == value && !remote.computed {
                self.save_seen(&linked, change.base_revision + 1, &remote)?;
                return Ok(accepted);
            }
            self.doppler_wins(&linked, &remote, change.base_revision)?;
            return Ok(Pushed::Conflict);
        }
        let original = seen.as_ref().map(|seen| seen.value.as_str());
        match self.client.set(&self.place, &linked.name, value, original).await? {
            Ok(()) => {
                self.save_seen(&linked, change.base_revision + 1, &Remote { value: value.to_string(), computed: false })?;
                return Ok(accepted);
            }
            Err(Refused::ReadOnly) => return Ok(Pushed::ReadOnly),
            Err(Refused::Other(_)) => {}
        }
        // Doppler doesn't say why in a way that can be relied on. Reading the secret again does: someone changed it there, or Doppler won't take this one.
        match self.current(&linked.name).await? {
            Some(remote) if original != Some(remote.value.as_str()) => Ok(Pushed::Conflict),
            _ => Ok(Pushed::Refused),
        }
    }

    pub async fn names(&self) -> AppResult<Vec<String>> {
        self.client.names(&self.place).await
    }

    pub async fn delete(&self, name: &str) -> AppResult<()> {
        match self.client.delete(&self.place, name).await? {
            Ok(()) => Ok(()),
            Err(Refused::ReadOnly) => Err(AppError::general("This Doppler token can only read. Delete the secret in Doppler.")),
            Err(Refused::Other(said)) => Err(AppError::general(format!("Doppler didn't delete {name}: {said}"))),
        }
    }
}

#[async_trait]
impl Provider for Doppler {
    // Nothing is routed to Doppler by category. Only secrets linked to it live there.
    fn accepts(&self, _category: Category) -> bool {
        false
    }

    fn takes(&self, item: &Item) -> bool {
        item.pinned.as_deref() == Some(self.identity.as_str())
    }

    async fn pull(&self, cursor: u64) -> AppResult<Pulled> {
        let links = self.links()?;
        let mut names: Vec<String> = links.iter().map(|linked| linked.name.clone()).collect();
        names.sort();
        names.dedup();
        let remote = if names.is_empty() { BTreeMap::new() } else { self.client.secrets(&self.place, &names).await? };

        let mut changes = Vec::new();
        let mut problems = Vec::new();
        let now = now_millis();
        for linked in &links {
            let Some(found) = remote.get(&linked.name) else {
                problems.push((linked.key.clone(), ProblemReason::Missing));
                continue;
            };
            if found.computed {
                problems.push((linked.key.clone(), ProblemReason::Computed));
            }
            changes.push(Incoming {
                key: linked.key.clone(),
                revision: self.revision_for(linked, found)?,
                deleted: false,
                moved_to: None,
                // Doppler is the source of truth, so its value is always the newer one.
                modified_at: now,
                refs: BTreeMap::new(),
                content: json!({ "value": found.value }),
            });
        }
        Ok(Pulled { changes, cursor, more: false, problems })
    }

    async fn push(&self, changes: Vec<Outgoing>) -> AppResult<Vec<(String, Pushed)>> {
        let mut answers = Vec::with_capacity(changes.len());
        let mut read_only = false;
        for change in changes {
            let pushed = if read_only && !change.deleted { Pushed::ReadOnly } else { self.push_one(&change).await? };
            read_only |= pushed == Pushed::ReadOnly;
            answers.push((change.key, pushed));
        }
        Ok(answers)
    }
}

/// A token that was checked against a project and config, ready to be added as a cloud.
pub struct Checked {
    pub config: Config,
    pub token: Zeroizing<String>,
}

/// Proves the token can list that config's secret names. Nothing is read beyond the names.
pub async fn check(client: &Client, token: &str, project: &str, config: &str) -> AppResult<Checked> {
    let (project, config) = (project.trim(), config.trim());
    if project.is_empty() || config.is_empty() {
        return Err(AppError::general("Pick a project and a config"));
    }
    let config = Config { project: project.to_string(), config: config.to_string() };
    client.names(&config.place()).await?;
    Ok(Checked { config, token: Zeroizing::new(token.trim().to_string()) })
}

impl Checked {
    pub fn save(&self, cloud_id: &str, vault: &Vault) -> AppResult<()> {
        vault.set(&token_id(cloud_id), &self.token)
    }
}
