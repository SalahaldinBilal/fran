pub mod doppler;
pub mod fran_server;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use super::items::Item;
use super::state::{Category, Cloud};
use crate::error::AppResult;
use crate::secrets::SecretsStore;
use crate::vault::Vault;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CloudKind {
    FranServer,
    Doppler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProblemReason {
    TooLarge,
    QuotaExceeded,
    /// The cloud's sign-in can read but not write.
    ReadOnly,
    /// The cloud no longer has what this item is linked to. The value on this computer stays.
    Missing,
    /// The cloud builds this value from other ones, so it can only be changed there.
    Computed,
    /// The cloud said no to this one item, for a reason of its own like a name it doesn't allow.
    Refused,
}

impl ProblemReason {
    /// Found by a pull, so the next pull replaces them.
    pub fn from_pull(self) -> bool {
        matches!(self, Self::Missing | Self::Computed)
    }
}

/// One item as a cloud holds it. `revision` goes up by one with every accepted push.
#[derive(Debug, Clone, PartialEq)]
pub struct Incoming {
    pub key: String,
    pub revision: u64,
    pub deleted: bool,
    /// On a deleted item: the identity of the cloud it now lives in.
    pub moved_to: Option<String>,
    pub modified_at: i64,
    pub refs: BTreeMap<String, String>,
    pub content: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    pub key: String,
    pub base_revision: u64,
    pub deleted: bool,
    pub moved_to: Option<String>,
    pub modified_at: i64,
    pub refs: BTreeMap<String, String>,
    pub content: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    Accepted { revision: u64 },
    /// The cloud has a newer revision than the one this push was based on.
    Conflict,
    TooLarge,
    QuotaExceeded,
    ReadOnly,
    Refused,
}

pub struct Pulled {
    pub changes: Vec<Incoming>,
    pub cursor: u64,
    pub more: bool,
    /// Item keys the cloud has something to say about, without a change to apply.
    pub problems: Vec<(String, ProblemReason)>,
}

/// A kind of cloud. The engine only ever talks to this, in items and revisions.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Whether a whole category can be routed here.
    fn accepts(&self, category: Category) -> bool;

    /// Whether this one item may be pushed here.
    fn takes(&self, item: &Item) -> bool {
        self.accepts(item.category)
    }

    async fn pull(&self, cursor: u64) -> AppResult<Pulled>;

    /// One answer per change, in any order.
    async fn push(&self, changes: Vec<Outgoing>) -> AppResult<Vec<(String, Pushed)>>;

    /// Sends whenever the cloud says something changed, and closes when the connection drops. None if this cloud can't tell.
    async fn watch(&self) -> Option<mpsc::Receiver<()>> {
        None
    }
}

pub type Opener = Arc<dyn Fn(&Cloud) -> AppResult<Arc<dyn Provider>> + Send + Sync>;

/// The one place that picks a provider by kind.
pub fn opener(vault: Arc<Vault>, secrets: Arc<SecretsStore>) -> Opener {
    Arc::new(move |cloud| match cloud.kind {
        CloudKind::FranServer => fran_server::open(cloud, &vault),
        CloudKind::Doppler => doppler::open(cloud, vault.clone(), secrets.clone()),
    })
}

/// Vault entries a cloud keeps on this computer, removed when it is.
pub fn vault_prefix(cloud_id: &str) -> String {
    format!("cloud:{cloud_id}:")
}
