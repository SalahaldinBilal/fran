use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::duplicates::Duplicate;
use super::providers::CloudKind;
use crate::json_store::JsonStore;

pub const SYNC_FILE_VERSION: u32 = 1;
pub const REPLACED_KEPT_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Category {
    Connections,
    SshHosts,
    Identities,
    Proxies,
    VpnProfiles,
    SavedQueries,
    Snippets,
    Forwards,
    KnownHosts,
    Settings,
    Secrets,
    Passwords,
    PrivateKeys,
}

impl Category {
    pub const ALL: [Category; 13] = [
        Self::Connections,
        Self::SshHosts,
        Self::Identities,
        Self::Proxies,
        Self::VpnProfiles,
        Self::SavedQueries,
        Self::Snippets,
        Self::Forwards,
        Self::KnownHosts,
        Self::Settings,
        Self::Secrets,
        Self::Passwords,
        Self::PrivateKeys,
    ];

    /// Never switched on by "Use for everything", and the only ones that can follow their item.
    pub fn is_secret(self) -> bool {
        matches!(self, Self::Passwords | Self::PrivateKeys)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "cloud", rename_all = "camelCase")]
pub enum Target {
    /// "Don't sync" on a category, "Keep on this computer" on an item or group.
    Local,
    Cloud(String),
    /// Passwords and keys only: the cloud of the item they belong to.
    WithItem,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Routes {
    pub categories: BTreeMap<Category, Target>,
    /// Keyed by `<item kind>:<group name>`.
    pub groups: BTreeMap<String, Target>,
    pub items: BTreeMap<String, Target>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RecordState {
    pub revision: u64,
    /// Of the content this computer and the cloud last agreed on. Empty for a record this computer doesn't follow.
    pub hash: String,
    pub deleted: bool,
    /// When the edit this revision holds was made, Unix milliseconds.
    pub modified_at: i64,
    /// Settings only: the content last agreed on, so two edits to different parts of one setting can both be kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cloud {
    pub id: String,
    pub kind: CloudKind,
    pub name: String,
    /// The same on every computer signed into this cloud. Synced data names a cloud by this, never by `id`.
    pub identity: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub cursor: u64,
    #[serde(default)]
    pub records: BTreeMap<String, RecordState>,
    /// When a local edit was first seen, Unix milliseconds. It decides which side of a conflict is newer.
    #[serde(default)]
    pub dirty_since: BTreeMap<String, i64>,
    /// Per item, the items it points at and the identity of the cloud each lives in.
    #[serde(default)]
    pub refs: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub last_sync: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReplacedReason {
    /// Another computer's newer edit took its place.
    Replaced,
    /// Another computer deleted it.
    Deleted,
    /// This computer's edit was newer, so the cloud's version lost.
    Overwritten,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Replaced {
    pub id: String,
    pub key: String,
    pub label: String,
    /// Null for passwords and keys. Their old value is in the vault under `sync:replaced:<id>`.
    pub content: serde_json::Value,
    pub cloud: String,
    pub at: i64,
    pub reason: ReplacedReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SyncFile {
    pub version: u32,
    pub clouds: Vec<Cloud>,
    pub routes: Routes,
    pub replaced: Vec<Replaced>,
    /// Items another computer moved to a cloud this one isn't signed into, with that cloud's identity.
    pub moved: BTreeMap<String, String>,
    /// Category defaults another computer set to a cloud this one isn't signed into, by that cloud's identity.
    pub waiting_routes: BTreeMap<Category, String>,
    /// Found after a first pull and not settled yet. The local side isn't sent until then.
    pub duplicates: Vec<Duplicate>,
}

impl Default for SyncFile {
    fn default() -> Self {
        Self {
            version: SYNC_FILE_VERSION,
            clouds: Vec::new(),
            routes: Routes::default(),
            replaced: Vec::new(),
            moved: BTreeMap::new(),
            waiting_routes: BTreeMap::new(),
            duplicates: Vec::new(),
        }
    }
}

impl SyncFile {
    /// Waiting for the user to say whether it's the same as something in that cloud.
    pub fn held_back(&self, cloud_id: &str, key: &str) -> bool {
        self.duplicates.iter().any(|duplicate| duplicate.cloud == cloud_id && duplicate.local == key)
    }
}

impl SyncFile {
    pub fn cloud(&self, id: &str) -> Option<&Cloud> {
        self.clouds.iter().find(|cloud| cloud.id == id)
    }

    pub fn cloud_mut(&mut self, id: &str) -> Option<&mut Cloud> {
        self.clouds.iter_mut().find(|cloud| cloud.id == id)
    }

    pub fn cloud_by_identity(&self, identity: &str) -> Option<&Cloud> {
        self.clouds.iter().find(|cloud| cloud.identity == identity)
    }

    /// The cloud that holds a live record of this item, other than `except`.
    pub fn holder(&self, key: &str, except: &str) -> Option<&Cloud> {
        self.clouds
            .iter()
            .find(|cloud| cloud.id != except && cloud.records.get(key).is_some_and(|record| !record.deleted && !record.hash.is_empty()))
    }
}

pub type SyncStore = JsonStore<SyncFile>;

pub fn replaced_vault_id(entry_id: &str) -> String {
    format!("sync:replaced:{entry_id}")
}
