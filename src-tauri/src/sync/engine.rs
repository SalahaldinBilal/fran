use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::hmac;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Notify, mpsc};
use zeroize::Zeroizing;

use super::items::{Item, SETTING, Stores, VAULT, category_of, is_order, label_of, references, split_key};
pub use super::providers::ProblemReason;
use super::providers::{CloudKind, Incoming, Opener, Outgoing, Provider, Pulled, Pushed, vault_prefix};
use super::duplicates::{self, Duplicate};
use super::routes::{Homes, kept_local};
use super::shared_routes;
use super::state::{Category, Cloud, REPLACED_KEPT_MS, RecordState, Replaced, ReplacedReason, Routes, SyncFile, SyncStore, Target, replaced_vault_id};
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::ssh_store::now_millis;

const HASH_KEY_ID: &str = "sync:local:hashKey";
const PUSH_DELAY: Duration = Duration::from_secs(2);
const PULL_EVERY: Duration = Duration::from_secs(5 * 60);
const FIRST_RETRY: Duration = Duration::from_secs(5);
const MAX_ROUNDS: usize = 5;
const MAX_MOVE_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncPhase {
    /// Added, nothing has run yet.
    Waiting,
    Syncing,
    UpToDate,
    Error,
}

/// An item the cloud wouldn't take or can't keep in step. It stays on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub key: String,
    pub label: String,
    pub reason: ProblemReason,
}

/// What a pass is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SyncStep {
    Checking,
    /// Items changed here so far by what came in.
    Receiving { count: usize },
    Sending { count: usize },
}

/// What the last finished pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassSummary {
    pub received: usize,
    pub sent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudStatus {
    pub phase: SyncPhase,
    pub step: Option<SyncStep>,
    pub last_pass: Option<PassSummary>,
    pub message: Option<String>,
    pub signed_out: bool,
    pub problems: Vec<Problem>,
}

impl Default for CloudStatus {
    fn default() -> Self {
        Self { phase: SyncPhase::Waiting, step: None, last_pass: None, message: None, signed_out: false, problems: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudView {
    pub id: String,
    pub kind: CloudKind,
    pub name: String,
    pub identity: String,
    pub config: Value,
    pub last_sync: Option<i64>,
    pub items: usize,
    pub status: CloudStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacedView {
    pub id: String,
    pub key: String,
    pub label: String,
    pub cloud: String,
    pub at: i64,
    pub reason: ReplacedReason,
}

/// Something an item points at that this computer doesn't have.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingRef {
    pub item: String,
    pub label: String,
    pub target: String,
    /// The local id of the cloud the target lives in, when this computer is signed into it.
    pub cloud: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncView {
    pub clouds: Vec<CloudView>,
    pub routes: Routes,
    /// Item key to the cloud it syncs to, for every item that has one.
    pub homes: BTreeMap<String, String>,
    pub replaced: Vec<ReplacedView>,
    pub moved: BTreeMap<String, String>,
    pub missing: Vec<MissingRef>,
    /// Categories another computer sends to a cloud this one isn't signed into, with that cloud's identity.
    pub waiting_routes: BTreeMap<Category, String>,
    pub duplicates: Vec<Duplicate>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveCandidate {
    pub key: String,
    pub label: String,
    pub home: Option<String>,
}

/// How the engine reaches the window. Tests pass one that does nothing.
pub trait Events: Send + Sync {
    /// Clouds, routes or a status changed.
    fn changed(&self);
    /// A pull wrote items of these kinds, so the lists showing them are stale.
    fn applied(&self, kinds: &[String]);
}

struct Worker {
    wake: Arc<Notify>,
    task: tauri::async_runtime::JoinHandle<()>,
}

pub struct Engine {
    stores: Stores,
    state: Arc<SyncStore>,
    opener: Opener,
    events: Arc<dyn Events>,
    /// Held for every read-then-write of `sync.json` and the stores, never across a network call.
    local: tokio::sync::Mutex<()>,
    statuses: Mutex<HashMap<String, CloudStatus>>,
    /// Per cloud, the hash of each item it refused, so the same content isn't sent again.
    refused: Mutex<HashMap<String, HashMap<String, String>>>,
    workers: Mutex<HashMap<String, Worker>>,
}

fn canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(fields) => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            out.push(b'{');
            for name in names {
                let _ = serde_json::to_writer(&mut *out, name);
                out.push(b':');
                canonical(&fields[name], out);
                out.push(b',');
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for value in values {
                canonical(value, out);
                out.push(b',');
            }
            out.push(b']');
        }
        other => {
            let _ = serde_json::to_writer(&mut *out, other);
        }
    }
}

struct Hasher(hmac::Key);

impl Hasher {
    fn of(&self, content: &Value) -> String {
        let mut bytes = Zeroizing::new(Vec::new());
        canonical(content, &mut bytes);
        hex::encode(hmac::sign(&self.0, &bytes))
    }
}

fn follows(record: &RecordState) -> bool {
    !record.deleted && !record.hash.is_empty()
}

fn is_vault(key: &str) -> bool {
    key.split_once(':').is_some_and(|(kind, _)| kind == VAULT)
}

fn kind_of(key: &str) -> String {
    key.split_once(':').map(|(kind, _)| kind.to_string()).unwrap_or_default()
}

/// Kept for settings only. They hold no passwords, so keeping their content in sync.json is fine.
fn merge_base(key: &str, content: &Value) -> Option<Value> {
    (kind_of(key) == SETTING && content.is_object()).then(|| content.clone())
}

/// A three-way merge of one setting's parts. None when the setting isn't an object on every side.
fn merged_setting(base: &Value, local: &Value, remote: &Value, remote_wins: bool) -> Option<Value> {
    let (base, local, remote) = (base.as_object()?, local.as_object()?, remote.as_object()?);
    let names: BTreeSet<&String> = base.keys().chain(local.keys()).chain(remote.keys()).collect();
    let mut merged = serde_json::Map::new();
    for name in names {
        let (was, here, there) = (base.get(name), local.get(name), remote.get(name));
        let kept = if here == was {
            there
        } else if there == was || !remote_wins {
            here
        } else {
            there
        };
        if let Some(value) = kept {
            merged.insert(name.clone(), value.clone());
        }
    }
    Some(Value::Object(merged))
}

fn unknown_cloud() -> AppError {
    AppError::not_found("That cloud was removed from this computer")
}

async fn next_event(watch: &mut Option<mpsc::Receiver<()>>) -> bool {
    match watch {
        Some(receiver) => receiver.recv().await.is_some(),
        None => std::future::pending().await,
    }
}

/// What applying one pull changes, gathered so the stores are read again only once.
struct Applying<'a> {
    cloud_id: &'a str,
    file: SyncFile,
    items: BTreeMap<String, Item>,
    hasher: &'a Hasher,
    /// Written from the cloud. Their hash is taken from what the store holds afterwards.
    written: Vec<String>,
    kinds: BTreeSet<String>,
    /// Items written or removed here, not the ones that only confirmed what this computer already had.
    changed: usize,
}

impl Applying<'_> {
    fn cloud(&mut self) -> AppResult<&mut Cloud> {
        self.file.cloud_mut(self.cloud_id).ok_or_else(unknown_cloud)
    }

    fn set_record(&mut self, key: &str, record: RecordState) -> AppResult<()> {
        self.cloud()?.records.insert(key.to_string(), record);
        Ok(())
    }

    /// An item that arrives from a cloud syncs to that cloud here too, whatever this computer's defaults say.
    fn pin_home(&mut self, key: &str) {
        let home = Homes::new(&self.file, &self.items).of_key(key).map(str::to_string);
        if home.as_deref() != Some(self.cloud_id) {
            self.file.routes.items.insert(key.to_string(), Target::Cloud(self.cloud_id.to_string()));
        }
    }
}

impl Engine {
    pub fn new(stores: Stores, state: Arc<SyncStore>, opener: Opener, events: Arc<dyn Events>) -> Arc<Self> {
        Arc::new(Self {
            stores,
            state,
            opener,
            events,
            local: tokio::sync::Mutex::new(()),
            statuses: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            workers: Mutex::new(HashMap::new()),
        })
    }

    pub fn stores(&self) -> &Stores {
        &self.stores
    }

    /// Every item, the shared category defaults from `file` included.
    fn collect(&self, file: &SyncFile) -> AppResult<BTreeMap<String, Item>> {
        let mut items = self.stores.collect()?;
        let routes = shared_routes::item(file);
        items.insert(routes.key.clone(), routes);
        Ok(items)
    }

    pub fn cloud(&self, cloud_id: &str) -> AppResult<Cloud> {
        self.state.read(|file| file.cloud(cloud_id).cloned())?.ok_or_else(unknown_cloud)
    }

    // Kept in the vault: a plain SHA-256 of a password in sync.json could be guessed offline.
    fn hasher(&self) -> AppResult<Hasher> {
        let vault = &self.stores.vault;
        let stored = match vault.get(HASH_KEY_ID)? {
            Some(stored) => stored,
            None => {
                let mut bytes = Zeroizing::new([0u8; 32]);
                getrandom::fill(bytes.as_mut()).map_err(|error| AppError::general(format!("No secure random source: {error}")))?;
                let fresh = Zeroizing::new(hex::encode(bytes.as_slice()));
                vault.set(HASH_KEY_ID, &fresh)?;
                fresh
            }
        };
        let bytes = Zeroizing::new(hex::decode(stored.as_str()).map_err(|_| AppError::vault("The sync hash key in the vault is damaged"))?);
        Ok(Hasher(hmac::Key::new(hmac::HMAC_SHA256, &bytes)))
    }

    /// Tells the window only when something it shows really changed.
    fn set_status(&self, cloud_id: &str, change: impl FnOnce(&mut CloudStatus)) {
        let changed = match self.statuses.lock() {
            Ok(mut statuses) => {
                let status = statuses.entry(cloud_id.to_string()).or_default();
                let before = status.clone();
                change(status);
                *status != before
            }
            Err(_) => false,
        };
        if changed {
            self.events.changed();
        }
    }

    fn status(&self, cloud_id: &str) -> CloudStatus {
        self.statuses.lock().ok().and_then(|statuses| statuses.get(cloud_id).cloned()).unwrap_or_default()
    }

    fn keep_replaced(&self, applying: &mut Applying, key: &str, content: &Value, reason: ReplacedReason) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let owner_label = || {
            let owner = key.strip_prefix("vault:").and_then(|vault_id| vault_id.rsplit_once(':')).map(|(owner, _)| owner.to_string());
            owner.and_then(|owner| applying.items.get(&owner).map(|item| item.label.clone()))
        };
        let (label, kept) = if is_vault(key) {
            let value = content.get("value").and_then(Value::as_str).unwrap_or_default();
            self.stores.vault.set(&replaced_vault_id(&id), value)?;
            (owner_label().unwrap_or_default(), Value::Null)
        } else {
            (label_of(key, content), content.clone())
        };
        let cloud = applying.cloud_id.to_string();
        applying.file.replaced.push(Replaced { id, key: key.to_string(), label, content: kept, cloud, at: now_millis(), reason });
        Ok(())
    }

    fn apply_one(&self, applying: &mut Applying, change: &Incoming) -> AppResult<()> {
        let key = change.key.as_str();
        let known = applying.cloud()?.records.get(key).cloned();
        if known.as_ref().is_some_and(|known| known.revision >= change.revision) {
            return Ok(());
        }
        let unfollowed = RecordState { revision: change.revision, hash: String::new(), deleted: change.deleted, modified_at: change.modified_at, base: None };
        if category_of(key).is_none() || kept_local(&applying.file, key) {
            return applying.set_record(key, unfollowed);
        }

        let hasher = applying.hasher;
        let local = applying.items.get(key).cloned();
        let local_hash = local.as_ref().map(|item| hasher.of(&item.content));
        let remote_hash = hasher.of(&change.content);
        let agreed = known.as_ref().filter(|known| follows(known));
        let dirty = match (agreed, &local_hash) {
            (Some(agreed), Some(hash)) => *hash != agreed.hash,
            (Some(_), None) => true,
            (None, Some(hash)) => change.deleted || *hash != remote_hash,
            (None, None) => false,
        };
        let edited_at = applying.cloud()?.dirty_since.get(key).copied().unwrap_or(0);
        // A computer that joins always has an order and defaults of its own. The ones everyone else has win over them.
        let shared_setup = is_order(key) || shared_routes::is_routes(key);
        let remote_wins = !dirty || change.modified_at >= edited_at || (shared_setup && agreed.is_none());
        let keeps_loser = !shared_setup;

        if change.deleted {
            if let Some(identity) = &change.moved_to {
                match applying.file.cloud_by_identity(identity).map(|cloud| cloud.id.clone()) {
                    Some(target) => {
                        applying.file.routes.items.insert(key.to_string(), Target::Cloud(target));
                        applying.file.moved.remove(key);
                    }
                    None if local.is_some() => {
                        applying.file.routes.items.insert(key.to_string(), Target::Local);
                        applying.file.moved.insert(key.to_string(), identity.clone());
                    }
                    None => {}
                }
                applying.cloud()?.dirty_since.remove(key);
                applying.cloud()?.refs.remove(key);
                return applying.set_record(key, unfollowed);
            }
            if local.is_some() && !remote_wins {
                // The edit made here is newer than the delete, so it goes back up on the next push.
                return applying.set_record(key, unfollowed);
            }
            if let Some(local) = &local {
                self.keep_replaced(applying, key, &local.content, ReplacedReason::Deleted)?;
                self.stores.remove(key)?;
                applying.items.remove(key);
                applying.kinds.insert(kind_of(key));
                applying.changed += 1;
            }
            applying.file.routes.items.remove(key);
            applying.cloud()?.dirty_since.remove(key);
            applying.cloud()?.refs.remove(key);
            return applying.set_record(key, unfollowed);
        }

        let followed = RecordState { revision: change.revision, hash: remote_hash.clone(), deleted: false, modified_at: change.modified_at, base: merge_base(key, &change.content) };

        // Both sides changed one setting. Each part goes to whichever side changed it, the newer edit only where both did.
        if dirty
            && let (Some(local), Some(base)) = (&local, agreed.and_then(|agreed| agreed.base.as_ref()))
            && let Some(merged) = merged_setting(base, &local.content, &change.content, remote_wins)
        {
            if merged != local.content {
                self.stores.write(key, &merged)?;
                applying.items.insert(key.to_string(), Item { content: merged, ..local.clone() });
                applying.kinds.insert(kind_of(key));
                applying.changed += 1;
            }
            applying.cloud()?.refs.insert(key.to_string(), change.refs.clone());
            applying.set_record(key, followed)?;
            applying.pin_home(key);
            return Ok(());
        }

        // The same item is live in another cloud too: two computers moved it differently. The newer record keeps it.
        let elsewhere = applying.file.holder(key, applying.cloud_id).map(|cloud| (cloud.id.clone(), cloud.records[key].modified_at));
        if let Some((_, other_modified)) = elsewhere
            && change.modified_at <= other_modified
        {
            return applying.set_record(key, followed);
        }

        if local_hash.as_deref() == Some(remote_hash.as_str()) {
            applying.cloud()?.dirty_since.remove(key);
            applying.cloud()?.refs.insert(key.to_string(), change.refs.clone());
            applying.set_record(key, followed)?;
            applying.pin_home(key);
            return Ok(());
        }

        if !remote_wins {
            if keeps_loser {
                self.keep_replaced(applying, key, &change.content, ReplacedReason::Overwritten)?;
            }
            applying.set_record(key, followed)?;
            applying.pin_home(key);
            return Ok(());
        }

        if dirty && keeps_loser && let Some(local) = &local {
            self.keep_replaced(applying, key, &local.content, ReplacedReason::Replaced)?;
        }
        let written = if shared_routes::is_routes(key) {
            shared_routes::apply(&mut applying.file, &change.content);
            Ok(())
        } else {
            self.stores.write(key, &change.content)
        };
        if written.is_err() {
            // Written by a newer Fran in a shape this one can't store. Left alone until this one is updated.
            return applying.set_record(key, unfollowed);
        }
        let category = category_of(key).unwrap_or(Category::Connections);
        let stand_in = Item { key: key.to_string(), category, group: None, owner: None, pinned: None, label: label_of(key, &change.content), content: change.content.clone() };
        applying.items.insert(key.to_string(), local.map(|local| Item { content: change.content.clone(), ..local }).unwrap_or(stand_in));
        applying.written.push(key.to_string());
        applying.kinds.insert(kind_of(key));
        applying.changed += 1;
        applying.cloud()?.dirty_since.remove(key);
        applying.cloud()?.refs.insert(key.to_string(), change.refs.clone());
        applying.set_record(key, followed)?;
        applying.pin_home(key);
        Ok(())
    }

    fn prune_replaced(&self, file: &mut SyncFile) {
        let oldest = now_millis() - REPLACED_KEPT_MS;
        let (kept, expired): (Vec<Replaced>, Vec<Replaced>) = std::mem::take(&mut file.replaced).into_iter().partition(|entry| entry.at >= oldest);
        file.replaced = kept;
        for entry in expired.iter().filter(|entry| is_vault(&entry.key)) {
            let _ = self.stores.vault.remove(&replaced_vault_id(&entry.id));
        }
    }

    /// How many items it changed on this computer.
    fn apply(&self, cloud_id: &str, pulled: &Pulled) -> AppResult<usize> {
        let hasher = self.hasher()?;
        let file = self.state.read(Clone::clone)?;
        let items = self.collect(&file)?;
        let mut applying = Applying {
            cloud_id,
            file,
            items,
            hasher: &hasher,
            written: Vec::new(),
            kinds: BTreeSet::new(),
            changed: 0,
        };
        let before = applying.file.replaced.len();
        // Orders last, so items that arrive in the same pull are already there to be sorted.
        let (orders, items): (Vec<&Incoming>, Vec<&Incoming>) = pulled.changes.iter().partition(|change| is_order(&change.key));
        for change in items.into_iter().chain(orders) {
            self.apply_one(&mut applying, change)?;
        }

        // A store can keep an item in a slightly different shape than it arrived in. The hash has to be of what's stored.
        if !applying.written.is_empty() {
            let stored = self.collect(&applying.file)?;
            for key in std::mem::take(&mut applying.written) {
                let hash = stored.get(&key).map(|item| hasher.of(&item.content)).unwrap_or_default();
                if let Some(record) = applying.cloud()?.records.get_mut(&key) {
                    record.hash = hash;
                }
            }
        }

        applying.cloud()?.cursor = pulled.cursor;
        self.prune_replaced(&mut applying.file);
        let view_changed = applying.file.replaced.len() != before || applying.kinds.contains("routes");
        let Applying { file, kinds, changed, .. } = applying;
        self.state.update(move |current| {
            *current = file;
            Ok(())
        })?;
        if !kinds.is_empty() {
            self.events.applied(&kinds.into_iter().collect::<Vec<_>>());
        }
        if view_changed {
            self.events.changed();
        }
        Ok(changed)
    }

    /// What this cloud is missing. The routes are read here, right before the push, so nothing leaves through an old queue.
    fn outgoing(&self, cloud_id: &str, takes: &dyn Fn(&Item) -> bool) -> AppResult<(Vec<Outgoing>, bool)> {
        let hasher = self.hasher()?;
        let file = self.state.read(Clone::clone)?;
        let items = self.collect(&file)?;
        let homes = Homes::new(&file, &items);
        let cloud = file.cloud(cloud_id).ok_or_else(unknown_cloud)?;
        let refused = self.refused.lock().ok().and_then(|refused| refused.get(cloud_id).cloned()).unwrap_or_default();
        let now = now_millis();
        let edited_at = |key: &str| cloud.dirty_since.get(key).copied().unwrap_or(now);
        let mut changes = Vec::new();
        let mut waiting_on_another_cloud = false;

        for item in items.values() {
            let held_back = file.held_back(cloud_id, &item.key) || item.owner.as_deref().is_some_and(|owner| file.held_back(cloud_id, owner));
            if homes.of(item) != Some(cloud_id) || !takes(item) || held_back {
                continue;
            }
            let hash = hasher.of(&item.content);
            let record = cloud.records.get(&item.key);
            if record.is_some_and(|record| follows(record) && record.hash == hash) || refused.get(&item.key) == Some(&hash) {
                continue;
            }
            let refs = references(item)
                .into_iter()
                .filter_map(|target| {
                    let identity = homes.of_key(&target).and_then(|home| file.cloud(home)).map(|home| home.identity.clone())?;
                    Some((target, identity))
                })
                .collect();
            changes.push(Outgoing {
                key: item.key.clone(),
                base_revision: record.map(|record| record.revision).unwrap_or(0),
                deleted: false,
                moved_to: None,
                modified_at: edited_at(&item.key),
                refs,
                content: item.content.clone(),
            });
        }

        for (key, record) in cloud.records.iter().filter(|(_, record)| follows(record)) {
            let tombstone = |moved_to: Option<String>| Outgoing {
                key: key.clone(),
                base_revision: record.revision,
                deleted: true,
                moved_to,
                modified_at: edited_at(key),
                refs: BTreeMap::new(),
                content: Value::Null,
            };
            let Some(item) = items.get(key) else {
                changes.push(tombstone(None));
                continue;
            };
            let Some(home) = homes.of(item).filter(|home| *home != cloud_id).and_then(|home| file.cloud(home)) else {
                continue;
            };
            // Moved to another cloud. This copy only goes once the other cloud has confirmed its own.
            let hash = hasher.of(&item.content);
            if home.records.get(key).is_some_and(|theirs| follows(theirs) && theirs.hash == hash) {
                changes.push(tombstone(Some(home.identity.clone())));
            } else {
                waiting_on_another_cloud = true;
            }
        }

        let unmarked: Vec<String> = changes.iter().filter(|change| !cloud.dirty_since.contains_key(&change.key)).map(|change| change.key.clone()).collect();
        if !unmarked.is_empty() {
            self.state.update(|file| {
                let cloud = file.cloud_mut(cloud_id).ok_or_else(unknown_cloud)?;
                for key in unmarked {
                    cloud.dirty_since.insert(key, now);
                }
                Ok(())
            })?;
        }
        Ok((changes, waiting_on_another_cloud))
    }

    /// Notes when each unsynced edit was first seen. Runs right after a save, with no network, so an edit made offline keeps its real time.
    pub async fn mark_dirty(&self) -> AppResult<()> {
        let _local = self.local.lock().await;
        let ids: Vec<String> = self.state.read(|file| file.clouds.iter().map(|cloud| cloud.id.clone()).collect())?;
        for id in ids {
            self.outgoing(&id, &|_| true)?;
        }
        Ok(())
    }

    /// Records what the cloud said about a push. True when something has to be pulled and tried again.
    fn record(&self, cloud_id: &str, sent: &[Outgoing], answers: &[(String, Pushed)]) -> AppResult<bool> {
        let hasher = self.hasher()?;
        let mut conflicts = false;
        let mut problems = Vec::new();
        let mut refused = HashMap::new();
        self.state.update(|file| {
            for (key, pushed) in answers {
                let Some(change) = sent.iter().find(|change| change.key == *key) else {
                    continue;
                };
                match pushed {
                    Pushed::Accepted { revision } => {
                        let hash = if change.deleted { String::new() } else { hasher.of(&change.content) };
                        let cloud = file.cloud_mut(cloud_id).ok_or_else(unknown_cloud)?;
                        let base = if change.deleted { None } else { merge_base(key, &change.content) };
                        cloud.records.insert(key.clone(), RecordState { revision: *revision, hash, deleted: change.deleted, modified_at: change.modified_at, base });
                        cloud.dirty_since.remove(key);
                        if change.deleted {
                            cloud.refs.remove(key);
                        } else {
                            cloud.refs.insert(key.clone(), change.refs.clone());
                        }
                        let route_is_here = file.routes.items.get(key) == Some(&Target::Cloud(cloud_id.to_string()));
                        if change.deleted && change.moved_to.is_none() && route_is_here {
                            file.routes.items.remove(key);
                        }
                    }
                    Pushed::Conflict => conflicts = true,
                    Pushed::TooLarge | Pushed::QuotaExceeded | Pushed::ReadOnly | Pushed::Refused => {
                        let reason = match pushed {
                            Pushed::TooLarge => ProblemReason::TooLarge,
                            Pushed::QuotaExceeded => ProblemReason::QuotaExceeded,
                            Pushed::ReadOnly => ProblemReason::ReadOnly,
                            _ => ProblemReason::Refused,
                        };
                        let label = if is_vault(key) { String::new() } else { label_of(key, &change.content) };
                        problems.push(Problem { key: key.clone(), label, reason });
                        refused.insert(key.clone(), hasher.of(&change.content));
                    }
                }
            }
            Ok(())
        })?;
        if let Ok(mut all) = self.refused.lock() {
            all.entry(cloud_id.to_string()).or_default().extend(refused);
        }
        if let Ok(mut statuses) = self.statuses.lock() {
            let status = statuses.entry(cloud_id.to_string()).or_default();
            let answered: BTreeSet<&String> = answers.iter().map(|(key, _)| key).collect();
            status.problems.retain(|problem| problem.reason.from_pull() || !answered.contains(&problem.key));
            status.problems.extend(problems);
        }
        Ok(conflicts)
    }

    /// What the last pull said about items it had no change for. Each pull replaces the list.
    fn note_pulled(&self, cloud_id: &str, found: Vec<(String, ProblemReason)>) {
        let Ok(mut statuses) = self.statuses.lock() else {
            return;
        };
        let status = statuses.entry(cloud_id.to_string()).or_default();
        let before = status.problems.iter().filter(|problem| problem.reason.from_pull()).count();
        if before == 0 && found.is_empty() {
            return;
        }
        status.problems.retain(|problem| !problem.reason.from_pull());
        status.problems.extend(found.into_iter().map(|(key, reason)| Problem { key, label: String::new(), reason }));
        drop(statuses);
        self.events.changed();
    }

    fn note_duplicates(&self, cloud_id: &str) -> AppResult<()> {
        let file = self.state.read(Clone::clone)?;
        let items = self.collect(&file)?;
        let found = duplicates::find(&file, file.cloud(cloud_id).ok_or_else(unknown_cloud)?, &items);
        if found.is_empty() {
            return Ok(());
        }
        self.state.update(|file| {
            file.duplicates.extend(found);
            Ok(())
        })?;
        self.events.changed();
        Ok(())
    }

    /// None settles every one listed. `merge` keeps the cloud's copy, else both stay and the local one is sent too.
    pub async fn settle_duplicates(&self, ids: Option<Vec<String>>, merge: bool) -> AppResult<()> {
        let kinds = {
            let _local = self.local.lock().await;
            let chosen: Vec<Duplicate> = self.state.read(|file| {
                file.duplicates.iter().filter(|duplicate| ids.as_ref().is_none_or(|ids| ids.contains(&duplicate.id))).cloned().collect()
            })?;
            let mut kinds = BTreeSet::new();
            if merge {
                for duplicate in &chosen {
                    kinds.extend(duplicates::merge(&self.stores, &duplicate.local, &duplicate.remote)?);
                }
            }
            self.state.update(|file| {
                file.duplicates.retain(|duplicate| !chosen.contains(duplicate));
                if merge {
                    for duplicate in &chosen {
                        file.routes.items.remove(&duplicate.local);
                    }
                }
                Ok(())
            })?;
            kinds
        };
        if !kinds.is_empty() {
            self.events.applied(&kinds.into_iter().collect::<Vec<_>>());
        }
        let _ = self.mark_dirty().await;
        self.events.changed();
        self.wake(None);
        Ok(())
    }

    fn set_step(&self, cloud_id: &str, step: SyncStep) {
        self.set_status(cloud_id, |status| status.step = Some(step));
    }

    async fn sync_with(&self, cloud_id: &str, provider: &dyn Provider) -> AppResult<PassSummary> {
        let mut summary = PassSummary::default();
        self.set_step(cloud_id, SyncStep::Checking);
        let mut first_pull = self.cloud(cloud_id)?.cursor == 0;
        for _ in 0..MAX_ROUNDS {
            let mut found = Vec::new();
            loop {
                let cursor = self.cloud(cloud_id)?.cursor;
                let mut pulled = provider.pull(cursor).await?;
                let more = pulled.more;
                found.append(&mut pulled.problems);
                let changed = {
                    let _local = self.local.lock().await;
                    self.apply(cloud_id, &pulled)?
                };
                if changed > 0 {
                    summary.received += changed;
                    self.set_step(cloud_id, SyncStep::Receiving { count: summary.received });
                }
                if !more {
                    break;
                }
            }
            self.note_pulled(cloud_id, found);
            if std::mem::take(&mut first_pull) {
                let _local = self.local.lock().await;
                self.note_duplicates(cloud_id)?;
            }

            let (changes, waiting) = {
                let _local = self.local.lock().await;
                self.outgoing(cloud_id, &|item| provider.takes(item))?
            };
            if waiting {
                self.wake_others(cloud_id);
            }
            if changes.is_empty() {
                let _local = self.local.lock().await;
                self.state.update(|file| {
                    file.cloud_mut(cloud_id).ok_or_else(unknown_cloud)?.last_sync = Some(now_millis());
                    Ok(())
                })?;
                return Ok(summary);
            }
            self.set_step(cloud_id, SyncStep::Sending { count: changes.len() });
            let answers = provider.push(changes.clone()).await?;
            summary.sent += answers.iter().filter(|(_, pushed)| matches!(pushed, Pushed::Accepted { .. })).count();
            {
                let _local = self.local.lock().await;
                self.record(cloud_id, &changes, &answers)?;
            }
            // A move only finishes once the old cloud drops its copy, and it's waiting for this push.
            self.wake_others(cloud_id);
        }
        Err(AppError::general("This cloud kept changing while syncing. It will be tried again."))
    }

    /// One full pass for one cloud: pull, apply, push, and again while the cloud reports conflicts.
    pub async fn sync_cloud(&self, cloud_id: &str) -> AppResult<()> {
        let provider = (self.opener)(&self.cloud(cloud_id)?)?;
        let result = self.sync_with(cloud_id, provider.as_ref()).await;
        self.set_status(cloud_id, |status| status.step = None);
        result.map(|_| ())
    }

    /// Every cloud, twice, so a move between two of them finishes in one call. Workers do the same through wake-ups.
    pub async fn sync_all(&self) -> AppResult<()> {
        let ids: Vec<String> = self.state.read(|file| file.clouds.iter().map(|cloud| cloud.id.clone()).collect())?;
        for _ in 0..2 {
            for id in &ids {
                self.sync_cloud(id).await?;
            }
        }
        Ok(())
    }

    /// Pulls every cloud that holds a linked value, right now. True when one of those values changed here, so a failed connect is worth one more try.
    pub async fn refresh_linked(&self) -> AppResult<bool> {
        if self.state.read(|file| file.clouds.is_empty())? {
            return Ok(false);
        }
        let hasher = self.hasher()?;
        let linked = |engine: &Self| -> AppResult<(BTreeSet<String>, BTreeMap<String, String>)> {
            let items = engine.stores.collect()?;
            let file = engine.state.read(Clone::clone)?;
            let pinned = items.values().filter_map(|item| Some((item, file.cloud_by_identity(item.pinned.as_ref()?)?)));
            Ok(pinned.map(|(item, cloud)| (cloud.id.clone(), (item.key.clone(), hasher.of(&item.content)))).unzip())
        };
        let (clouds, before) = linked(self)?;
        for cloud_id in &clouds {
            self.sync_cloud(cloud_id).await?;
        }
        Ok(!clouds.is_empty() && linked(self)?.1 != before)
    }

    fn wake_others(&self, cloud_id: &str) {
        if let Ok(workers) = self.workers.lock() {
            workers.iter().filter(|(id, _)| id.as_str() != cloud_id).for_each(|(_, worker)| worker.wake.notify_one());
        }
    }

    pub fn wake(&self, cloud_id: Option<&str>) {
        if let Ok(workers) = self.workers.lock() {
            workers.iter().filter(|(id, _)| cloud_id.is_none_or(|wanted| wanted == id.as_str())).for_each(|(_, worker)| worker.wake.notify_one());
        }
    }

    async fn run_worker(self: Arc<Self>, cloud_id: String, wake: Arc<Notify>) {
        let mut retry = FIRST_RETRY;
        let mut watch: Option<mpsc::Receiver<()>> = None;
        loop {
            self.set_status(&cloud_id, |status| {
                status.phase = SyncPhase::Syncing;
                status.step = Some(SyncStep::Checking);
            });
            let provider = self.cloud(&cloud_id).and_then(|cloud| (self.opener)(&cloud));
            let result = match &provider {
                Ok(provider) => {
                    // A task of its own, so a panic in a pass shows as a failed sync instead of a worker stuck on "syncing".
                    let (engine, id, provider) = (self.clone(), cloud_id.clone(), provider.clone());
                    let pass = tauri::async_runtime::spawn(async move { engine.sync_with(&id, provider.as_ref()).await });
                    pass.await.unwrap_or_else(|_| Err(AppError::general("Sync stopped on an internal error. It will be tried again.")))
                }
                Err(error) => Err(error.clone()),
            };
            let wait = match result {
                Ok(summary) => {
                    self.set_status(&cloud_id, |status| {
                        status.phase = SyncPhase::UpToDate;
                        status.step = None;
                        status.last_pass = Some(summary);
                        status.message = None;
                        status.signed_out = false;
                    });
                    retry = FIRST_RETRY;
                    if watch.is_none()
                        && let Ok(provider) = &provider
                    {
                        watch = provider.watch().await;
                    }
                    PULL_EVERY
                }
                Err(error) => {
                    let signed_out = matches!(error.detail, ErrorDetail::SyncSignedOut);
                    self.set_status(&cloud_id, |status| {
                        status.phase = SyncPhase::Error;
                        status.step = None;
                        status.message = Some(error.message.clone());
                        status.signed_out = signed_out;
                    });
                    let wait = if signed_out || matches!(error.detail, ErrorDetail::AppLocked | ErrorDetail::NotFound) { PULL_EVERY } else { retry };
                    retry = (retry * 2).min(PULL_EVERY);
                    wait
                }
            };
            tokio::select! {
                _ = wake.notified() => {}
                _ = tokio::time::sleep(wait) => {}
                open = next_event(&mut watch) => {
                    if !open {
                        watch = None;
                    }
                }
            }
        }
    }

    fn spawn_worker(self: &Arc<Self>, cloud_id: &str) {
        let wake = Arc::new(Notify::new());
        let task = tauri::async_runtime::spawn(self.clone().run_worker(cloud_id.to_string(), wake.clone()));
        if let Ok(mut workers) = self.workers.lock()
            && let Some(old) = workers.insert(cloud_id.to_string(), Worker { wake, task })
        {
            old.task.abort();
        }
    }

    fn stop_worker(&self, cloud_id: &str) {
        if let Ok(mut workers) = self.workers.lock()
            && let Some(worker) = workers.remove(cloud_id)
        {
            worker.task.abort();
        }
    }

    /// Starts one worker per cloud, and the task that wakes them a moment after anything is saved.
    pub fn start(self: &Arc<Self>) {
        let ids = self.state.read(|file| file.clouds.iter().map(|cloud| cloud.id.clone()).collect::<Vec<_>>()).unwrap_or_default();
        for id in ids {
            self.spawn_worker(&id);
        }
        let engine = self.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                super::notify::wait().await;
                let _ = engine.mark_dirty().await;
                tokio::time::sleep(PUSH_DELAY).await;
                engine.wake(None);
            }
        });
    }

    /// Adds a cloud, or signs back into one this computer already has. `save` puts its session in the vault under the id it's given.
    pub async fn add_cloud(self: &Arc<Self>, kind: CloudKind, name: &str, identity: String, config: Value, save: impl FnOnce(&str) -> AppResult<()>) -> AppResult<String> {
        let id = self.register_cloud(kind, name, identity, config, save).await?;
        self.set_status(&id, |status| *status = CloudStatus::default());
        self.spawn_worker(&id);
        Ok(id)
    }

    /// `add_cloud` without the background worker.
    pub async fn register_cloud(&self, kind: CloudKind, name: &str, identity: String, config: Value, save: impl FnOnce(&str) -> AppResult<()>) -> AppResult<String> {
        let id = {
            let _local = self.local.lock().await;
            let existing = self.state.read(|file| file.cloud_by_identity(&identity).map(|cloud| cloud.id.clone()))?;
            let id = existing.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            save(&id)?;
            let name = name.trim().to_string();
            let cloud_id = id.clone();
            self.state.update(move |file| {
                match file.cloud_mut(&cloud_id) {
                    Some(cloud) => cloud.config = config,
                    None => file.clouds.push(Cloud {
                        id: cloud_id,
                        kind,
                        name,
                        identity,
                        config,
                        cursor: 0,
                        records: BTreeMap::new(),
                        dirty_since: BTreeMap::new(),
                        refs: BTreeMap::new(),
                        last_sync: None,
                    }),
                }
                // Items another computer moved here were waiting for this sign-in, and so were its defaults.
                let identities: Vec<String> = file.clouds.iter().map(|cloud| cloud.identity.clone()).collect();
                file.moved.retain(|_, identity| !identities.contains(identity));
                shared_routes::resolve_waiting(file);
                Ok(())
            })?;
            id
        };
        self.events.changed();
        Ok(id)
    }

    /// Forgets a cloud on this computer. Everything it synced stays here as local only.
    pub async fn remove_cloud(&self, cloud_id: &str) -> AppResult<()> {
        self.stop_worker(cloud_id);
        let _local = self.local.lock().await;
        self.stores.vault.remove_prefix(&vault_prefix(cloud_id))?;
        let target = Target::Cloud(cloud_id.to_string());
        self.state.update(|file| {
            shared_routes::keep_waiting(file, cloud_id);
            file.duplicates.retain(|duplicate| duplicate.cloud != cloud_id);
            file.clouds.retain(|cloud| cloud.id != cloud_id);
            file.routes.categories.retain(|_, route| *route != target);
            file.routes.groups.retain(|_, route| *route != target);
            file.routes.items.retain(|_, route| *route != target);
            Ok(())
        })?;
        if let Ok(mut statuses) = self.statuses.lock() {
            statuses.remove(cloud_id);
        }
        self.events.changed();
        Ok(())
    }

    pub async fn rename_cloud(&self, cloud_id: &str, name: &str) -> AppResult<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::general("A cloud needs a name"));
        }
        let _local = self.local.lock().await;
        self.state.update(|file| {
            file.cloud_mut(cloud_id).ok_or_else(unknown_cloud)?.name = name.to_string();
            Ok(())
        })?;
        self.events.changed();
        Ok(())
    }

    fn checked_target(&self, file: &SyncFile, target: &Option<Target>, category: Option<Category>) -> AppResult<()> {
        match target {
            Some(Target::Cloud(id)) => {
                let cloud = file.cloud(id).ok_or_else(unknown_cloud)?;
                let provider = (self.opener)(cloud);
                // A signed-out cloud can still be picked. What it accepts is checked again at push time.
                if let (Ok(provider), Some(category)) = (provider, category)
                    && !provider.accepts(category)
                {
                    return Err(AppError::general(format!("{} can't hold that", cloud.name)));
                }
                Ok(())
            }
            Some(Target::WithItem) if !category.is_some_and(Category::is_secret) => Err(AppError::general("Only passwords and keys can follow the item they belong to")),
            _ => Ok(()),
        }
    }

    async fn change_routes(&self, change: impl FnOnce(&mut SyncFile) -> AppResult<()>) -> AppResult<()> {
        {
            let _local = self.local.lock().await;
            self.state.update(change)?;
        }
        // The shared defaults are an item too, and their edit time decides a conflict. A locked vault marks them at push time instead.
        let _ = self.mark_dirty().await;
        self.events.changed();
        self.wake(None);
        Ok(())
    }

    /// None on a category means "Don't sync".
    pub async fn set_category_route(&self, category: Category, target: Option<Target>) -> AppResult<()> {
        self.checked_target(&self.state.read(Clone::clone)?, &target, Some(category))?;
        self.change_routes(|file| {
            file.waiting_routes.remove(&category);
            match target {
                Some(target) if target != Target::Local => file.routes.categories.insert(category, target),
                _ => file.routes.categories.remove(&category),
            };
            Ok(())
        })
        .await
    }

    /// Everything but passwords and keys goes to one cloud.
    pub async fn use_for_everything(&self, cloud_id: &str) -> AppResult<()> {
        let cloud = self.cloud(cloud_id)?;
        let accepts = (self.opener)(&cloud).ok();
        self.change_routes(|file| {
            for category in Category::ALL.into_iter().filter(|category| !category.is_secret()) {
                if accepts.as_ref().is_none_or(|provider| provider.accepts(category)) {
                    file.waiting_routes.remove(&category);
                    file.routes.categories.insert(category, Target::Cloud(cloud.id.clone()));
                }
            }
            Ok(())
        })
        .await
    }

    /// None means the group follows its category again.
    pub async fn set_group_route(&self, group: String, target: Option<Target>) -> AppResult<()> {
        let category = category_of(&group);
        if category.is_none() {
            return Err(AppError::general("That group can't be synced"));
        }
        self.checked_target(&self.state.read(Clone::clone)?, &target, category)?;
        self.change_routes(|file| {
            match target {
                Some(target) => file.routes.groups.insert(group, target),
                None => file.routes.groups.remove(&group),
            };
            Ok(())
        })
        .await
    }

    /// None means the items follow their group or category again.
    pub async fn set_item_routes(&self, keys: Vec<String>, target: Option<Target>) -> AppResult<()> {
        let file = self.state.read(Clone::clone)?;
        for key in &keys {
            split_key(key)?;
            let category = category_of(key).ok_or_else(|| AppError::general("That item can't be synced"))?;
            self.checked_target(&file, &target, Some(category))?;
        }
        self.change_routes(|file| {
            for key in keys {
                file.moved.remove(&key);
                match &target {
                    Some(target) => file.routes.items.insert(key, target.clone()),
                    None => file.routes.items.remove(&key),
                };
            }
            Ok(())
        })
        .await
    }

    /// What `key` points at, all the way down, that wouldn't end up in `target` with it.
    pub fn move_candidates(&self, key: &str, target: &str) -> AppResult<Vec<MoveCandidate>> {
        let items = self.stores.collect()?;
        let file = self.state.read(Clone::clone)?;
        let homes = Homes::new(&file, &items);
        let mut seen = BTreeSet::from([key.to_string()]);
        let mut level = vec![key.to_string()];
        let mut found = Vec::new();
        for _ in 0..MAX_MOVE_DEPTH {
            let mut next = Vec::new();
            for item in level.iter().filter_map(|key| items.get(key)) {
                for reference in references(item) {
                    let Some(pointed) = items.get(&reference) else {
                        continue;
                    };
                    if !seen.insert(reference.clone()) {
                        continue;
                    }
                    next.push(reference.clone());
                    let home = homes.of(pointed).map(str::to_string);
                    if home.as_deref() != Some(target) {
                        found.push(MoveCandidate { key: reference, label: pointed.label.clone(), home });
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            level = next;
        }
        Ok(found)
    }

    pub fn view(&self) -> AppResult<SyncView> {
        let file = self.state.read(Clone::clone)?;
        // A locked vault hides passwords from the list, but the clouds and their status still have to show.
        let items = self.collect(&file).unwrap_or_default();
        let homes = Homes::new(&file, &items);
        let clouds = file
            .clouds
            .iter()
            .map(|cloud| CloudView {
                id: cloud.id.clone(),
                kind: cloud.kind,
                name: cloud.name.clone(),
                identity: cloud.identity.clone(),
                config: cloud.config.clone(),
                last_sync: cloud.last_sync,
                items: cloud.records.values().filter(|record| follows(record)).count(),
                status: self.status(&cloud.id),
            })
            .collect();
        let mut missing = Vec::new();
        for cloud in &file.clouds {
            for (key, refs) in &cloud.refs {
                let Some(item) = items.get(key) else {
                    continue;
                };
                for (target, identity) in refs.iter().filter(|(target, _)| !items.contains_key(*target)) {
                    let known = file.cloud_by_identity(identity).map(|cloud| cloud.id.clone());
                    missing.push(MissingRef { item: key.clone(), label: item.label.clone(), target: target.clone(), cloud: known });
                }
            }
        }
        Ok(SyncView {
            clouds,
            homes: items.values().filter_map(|item| Some((item.key.clone(), homes.of(item)?.to_string()))).collect(),
            routes: file.routes.clone(),
            replaced: file
                .replaced
                .iter()
                .map(|entry| ReplacedView {
                    id: entry.id.clone(),
                    key: entry.key.clone(),
                    label: entry.label.clone(),
                    cloud: entry.cloud.clone(),
                    at: entry.at,
                    reason: entry.reason,
                })
                .collect(),
            moved: file.moved.clone(),
            missing,
            waiting_routes: file.waiting_routes.clone(),
            duplicates: file.duplicates.clone(),
        })
    }

    /// Puts a version sync replaced back. It counts as a new edit, so it goes to the cloud on the next push.
    pub async fn restore_replaced(&self, entry_id: &str) -> AppResult<()> {
        let kind = {
            let _local = self.local.lock().await;
            let entry = self.state.read(|file| file.replaced.iter().find(|entry| entry.id == entry_id).cloned())?;
            let entry = entry.ok_or_else(|| AppError::not_found("That version is gone"))?;
            if is_vault(&entry.key) {
                let vault_id = replaced_vault_id(&entry.id);
                let value = self.stores.vault.get(&vault_id)?.ok_or_else(|| AppError::not_found("That version is gone"))?;
                self.stores.write(&entry.key, &serde_json::json!({ "value": value.as_str() }))?;
                self.stores.vault.remove(&vault_id)?;
            } else {
                self.stores.write(&entry.key, &entry.content)?;
            }
            self.state.update(|file| {
                file.replaced.retain(|kept| kept.id != entry_id);
                // The delete took the item's route with it. Undoing it has to reach the cloud the delete came from.
                let unrouted = !file.routes.items.contains_key(&entry.key);
                if entry.reason == ReplacedReason::Deleted && unrouted && file.cloud(&entry.cloud).is_some() {
                    file.routes.items.insert(entry.key.clone(), Target::Cloud(entry.cloud.clone()));
                }
                Ok(())
            })?;
            kind_of(&entry.key)
        };
        self.events.applied(&[kind]);
        self.events.changed();
        Ok(())
    }

    pub async fn discard_replaced(&self, entry_id: Option<&str>) -> AppResult<()> {
        let _local = self.local.lock().await;
        let dropped = self.state.update(|file| {
            let (dropped, kept) = std::mem::take(&mut file.replaced).into_iter().partition(|entry| entry_id.is_none_or(|id| id == entry.id));
            file.replaced = kept;
            Ok::<Vec<Replaced>, AppError>(dropped)
        })?;
        for entry in dropped.iter().filter(|entry| is_vault(&entry.key)) {
            self.stores.vault.remove(&replaced_vault_id(&entry.id))?;
        }
        self.events.changed();
        Ok(())
    }
}
