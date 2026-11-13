pub mod commands;
pub mod fill;

use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

use serde::{Deserialize, Serialize};

use crate::connections::SecretOwner;
use crate::error::{AppError, AppResult};
use crate::json_store::JsonStore;

pub const SECRETS_FILE_VERSION: u32 = 1;
pub const VALUE_SLOT: &str = "value";
/// A `secretRefs` key for a password slot, like `slot:password`. Any other key is a field path.
pub const SLOT_PREFIX: &str = "slot:";

/// Field path or `slot:<name>` to the id of the secret that fills it.
pub type SecretRefs = BTreeMap<String, String>;

/// A named value any field can use. The value itself is in the vault as `secret:<id>:value`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NamedSecret {
    pub id: String,
    pub name: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecretsFile {
    pub version: u32,
    pub secrets: Vec<NamedSecret>,
}

impl Default for SecretsFile {
    fn default() -> Self {
        Self { version: SECRETS_FILE_VERSION, secrets: Vec::new() }
    }
}

impl SecretsFile {
    pub fn secret(&self, id: &str) -> Option<&NamedSecret> {
        self.secrets.iter().find(|secret| secret.id == id)
    }
}

pub type SecretsStore = JsonStore<SecretsFile>;

static STORE: OnceLock<Arc<SecretsStore>> = OnceLock::new();

/// Installed once at start, so routes and VPN plans reach it without it being passed down.
pub fn install(store: Arc<SecretsStore>) {
    let _ = STORE.set(store);
}

pub fn store() -> Option<Arc<SecretsStore>> {
    STORE.get().cloned()
}

pub fn snapshot() -> AppResult<SecretsFile> {
    match store() {
        Some(store) => store.read(Clone::clone),
        None => Ok(SecretsFile::default()),
    }
}

pub fn owner(id: &str) -> SecretOwner {
    SecretOwner::Secret(id.to_string())
}

pub fn vault_id(id: &str) -> String {
    owner(id).secret_id(VALUE_SLOT)
}

pub fn deleted(what: &str) -> AppError {
    AppError::not_found(format!("The secret used for {what} was deleted. Pick another one in its settings."))
}
