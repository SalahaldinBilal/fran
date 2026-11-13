pub mod commands;
pub mod prepare;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::agent::access::AgentAccess;
use crate::db::DriverOptions;
use crate::error::{AppError, AppResult};
use crate::json_store::JsonStore;
use crate::secrets::{SecretRefs, VALUE_SLOT, fill::RefRules};
use crate::vault::Vault;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProfile {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub forward_port: Option<u16>,
    #[serde(default)]
    pub forward_all_networks: bool,
    #[serde(default)]
    pub agent_access: AgentAccess,
    /// Reaches the database server, or the SSH server with inline SSH. Saved hosts bring their own.
    #[serde(default)]
    pub vpn_id: Option<String>,
    /// Fields and password slots filled from named secrets. Field paths start at `options`.
    #[serde(default, skip_serializing_if = "SecretRefs::is_empty")]
    pub secret_refs: SecretRefs,
    #[serde(flatten)]
    pub driver: DriverOptions,
}

impl ConnectionProfile {
    /// The refs a connect reads. One left on a field the method skips, like the SSH host after switching to TCP, is left out.
    pub fn live_refs(&self) -> SecretRefs {
        let live = |key: &str| key.strip_prefix("options.").is_none_or(|path| self.driver.uses_field(path));
        self.secret_refs.iter().filter(|(key, _)| live(key)).map(|(key, secret)| (key.clone(), secret.clone())).collect()
    }
}

pub const SECRET_RULES: RefRules = RefRules {
    // A program path from a cloud would let that cloud pick what Fran runs.
    field: |path| path.starts_with("options.") && !path.ends_with(".kubectlPath"),
    slot: |slot| SecretOwner::Connection(String::new()).accepts(slot),
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ConnectionsFile {
    pub connections: Vec<ConnectionProfile>,
    /// Group names in display order, "" for the ungrouped ones.
    pub group_order: Vec<String>,
}

pub type ConnectionStore = JsonStore<ConnectionsFile>;

impl ConnectionStore {
    pub fn find(&self, id: &str) -> AppResult<ConnectionProfile> {
        self.read(|file| {
            file.connections
                .iter()
                .find(|profile| profile.id == id)
                .cloned()
        })?
        .ok_or_else(|| AppError::not_found("Connection not found"))
    }
}

/// Whose secret a vault entry is. Vault ids are `<kind>:<id>:<slot>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", content = "id", rename_all = "camelCase")]
pub enum SecretOwner {
    Connection(String),
    Identity(String),
    Key(String),
    Proxy(String),
    Vpn(String),
    /// A named secret (`secrets/`), which any field can use.
    Secret(String),
}

impl SecretOwner {
    pub fn prefix(&self) -> String {
        let (kind, id) = match self {
            Self::Connection(id) => ("connection", id),
            Self::Identity(id) => ("identity", id),
            Self::Key(id) => ("key", id),
            Self::Proxy(id) => ("proxy", id),
            Self::Vpn(id) => ("vpn", id),
            Self::Secret(id) => ("secret", id),
        };
        format!("{kind}:{id}:")
    }

    pub fn secret_id(&self, slot: &str) -> String {
        format!("{}{slot}", self.prefix())
    }

    /// Slots the UI may write. A vault key's private half is only ever written by generate and import.
    pub fn accepts(&self, slot: &str) -> bool {
        match self {
            Self::Connection(_) => !slot.is_empty() && slot.chars().all(|character| character.is_ascii_alphanumeric()),
            Self::Identity(_) | Self::Proxy(_) | Self::Vpn(_) => slot == PASSWORD_SLOT,
            Self::Key(_) => slot == PASSPHRASE_SLOT,
            Self::Secret(_) => slot == VALUE_SLOT,
        }
    }

    /// Secrets that can be shown after the OS confirms the user. Private keys and TLS keys are exported instead.
    pub fn revealable(&self, slot: &str) -> bool {
        self.accepts(slot)
    }
}

pub const PASSWORD_SLOT: &str = "password";
pub const PASSPHRASE_SLOT: &str = "passphrase";
pub const PRIVATE_KEY_SLOT: &str = "private";
pub const TLS_KEY_SLOT: &str = "tlsKey";
pub const PRESHARED_KEY_SLOT: &str = "presharedKey";

/// Where a prompted secret is saved when it doesn't belong to the connection being opened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    pub owner: SecretOwner,
    pub slot: String,
}

/// A credential a connect needs, like a password. `id` is the key in the typed-in values and `label` is shown in prompts.
/// Without `store` the slot belongs to the connection being opened and `id` is the driver's slot name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretSlot {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<SecretRef>,
    /// A one-time code. Never offered for saving and never read from the vault.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub one_time: bool,
}

impl SecretSlot {
    pub fn new(id: &str, label: &str) -> Self {
        Self {
            id: id.to_string(),
            label: label.to_string(),
            store: None,
            one_time: false,
        }
    }

    pub fn owned(owner: SecretOwner, slot: &str, label: String) -> Self {
        Self {
            id: owner.secret_id(slot),
            label,
            store: Some(SecretRef {
                owner,
                slot: slot.to_string(),
            }),
            one_time: false,
        }
    }

    pub fn one_time(id: String, label: String) -> Self {
        Self { id, label, store: None, one_time: true }
    }
}

pub fn secret_prefix(connection_id: &str) -> String {
    SecretOwner::Connection(connection_id.to_string()).prefix()
}

pub fn secret_id(connection_id: &str, slot: &str) -> String {
    format!("{}{slot}", secret_prefix(connection_id))
}

pub struct SecretBag {
    values: HashMap<String, Zeroizing<String>>,
}

impl SecretBag {
    pub fn new(values: HashMap<String, String>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|(slot, value)| (slot, Zeroizing::new(value)))
                .collect(),
        }
    }

    pub fn get(&self, slot: &str) -> Option<&str> {
        self.values.get(slot).map(|value| value.as_str())
    }
}

/// Typed-in values win over stored ones. A vault that can't be opened counts as
/// nothing stored, so the user can still connect by typing the password.
pub fn resolve_secrets(
    vault: &Vault,
    connection_id: Option<&str>,
    provided: HashMap<String, String>,
    required: &[SecretSlot],
    optional: &[SecretSlot],
) -> AppResult<SecretBag> {
    let mut provided: HashMap<String, Zeroizing<String>> = provided
        .into_iter()
        .map(|(slot, value)| (slot, Zeroizing::new(value)))
        .collect();

    let mut values = HashMap::new();
    let mut missing = Vec::new();

    for (slot, is_required) in required
        .iter()
        .map(|slot| (slot, true))
        .chain(optional.iter().map(|slot| (slot, false)))
    {
        let value = provided.remove(&slot.id).or_else(|| {
            if slot.one_time {
                return None;
            }
            let stored_id = match &slot.store {
                Some(target) => Some(target.owner.secret_id(&target.slot)),
                None => connection_id.map(|id| secret_id(id, &slot.id)),
            };
            stored_id.and_then(|id| vault.get(&id).ok().flatten())
        });

        match value {
            Some(value) => {
                values.insert(slot.id.clone(), value);
            }
            None if is_required => missing.push(slot.clone()),
            None => {}
        }
    }

    if !missing.is_empty() {
        return Err(AppError::secrets_required(missing));
    }

    Ok(SecretBag { values })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mysql(method: &str, ssh: serde_json::Value) -> ConnectionProfile {
        serde_json::from_value(serde_json::json!({
            "id": "c1",
            "name": "Prod",
            "kind": "mysql",
            "options": { "method": method, "ssh": ssh, "ssl": { "mode": "disabled" } },
            "secretRefs": {
                "options.host": "s-host",
                "options.ssh.host": "s-ssh",
                "options.ssh.keyFile": "s-key",
                "options.ssl.caFile": "s-ca",
                "slot:password": "s-pass",
            },
        }))
        .unwrap()
    }

    fn live(profile: &ConnectionProfile) -> Vec<String> {
        profile.live_refs().into_keys().collect()
    }

    #[test]
    fn a_secret_left_on_a_field_the_method_skips_is_not_read_on_connect() {
        // Switched from an SSH tunnel to TCP, with the tunnel's secrets still on the item.
        let tcp = mysql("tcp", serde_json::json!({ "auth": "publicKey" }));
        assert_eq!(live(&tcp), ["options.host", "slot:password"]);

        let tunnel = mysql("sshTunnel", serde_json::json!({ "auth": "publicKey" }));
        assert_eq!(live(&tunnel), ["options.host", "options.ssh.host", "options.ssh.keyFile", "slot:password"]);

        // A saved host brings its own login, so nothing typed for the inline one is read.
        let saved = mysql("sshTunnel", serde_json::json!({ "hostId": "h1", "auth": "password" }));
        assert_eq!(live(&saved), ["options.host", "slot:password"]);
    }
}
