use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use super::{NamedSecret, SLOT_PREFIX, SecretRefs, SecretsStore, owner, vault_id};
use crate::connections::{ConnectionStore, ConnectionsFile};
use crate::error::{AppError, AppResult};
use crate::ssh_store::{SshFile, SshStore};
use crate::vault::Vault;
use crate::vpn_store::{VpnFile, VpnStore};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SecretUserKind {
    Connection,
    SshHost,
    Identity,
    Proxy,
    Vpn,
}

/// One field or password slot that takes its value from a secret.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretUse {
    pub kind: SecretUserKind,
    pub id: String,
    pub label: String,
    /// The field path, or the slot name when `slot` is set.
    pub field: String,
    pub slot: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretInfo {
    pub id: String,
    pub name: String,
    pub note: String,
    pub has_value: bool,
    pub used_by: Vec<SecretUse>,
}

fn uses_in(found: &mut Vec<SecretUse>, secret: &str, kind: SecretUserKind, id: &str, label: &str, refs: &SecretRefs) {
    for (key, _) in refs.iter().filter(|(_, used)| used.as_str() == secret) {
        let slot = key.strip_prefix(SLOT_PREFIX);
        found.push(SecretUse {
            kind,
            id: id.to_string(),
            label: label.to_string(),
            field: slot.unwrap_or(key).to_string(),
            slot: slot.is_some(),
        });
    }
}

pub fn uses(secret: &str, connections: &ConnectionsFile, ssh: &SshFile, vpn: &VpnFile) -> Vec<SecretUse> {
    let mut found = Vec::new();
    for profile in &connections.connections {
        uses_in(&mut found, secret, SecretUserKind::Connection, &profile.id, &profile.name, &profile.secret_refs);
    }
    for host in &ssh.hosts {
        uses_in(&mut found, secret, SecretUserKind::SshHost, &host.id, &host.label, &host.secret_refs);
    }
    for identity in &ssh.identities {
        uses_in(&mut found, secret, SecretUserKind::Identity, &identity.id, &identity.label, &identity.secret_refs);
    }
    for proxy in &ssh.proxies {
        uses_in(&mut found, secret, SecretUserKind::Proxy, &proxy.id, &proxy.label, &proxy.secret_refs);
    }
    for profile in &vpn.profiles {
        uses_in(&mut found, secret, SecretUserKind::Vpn, &profile.id, &profile.label, &profile.secret_refs);
    }
    found
}

/// Names, notes and what uses each one. Values stay in the vault.
#[tauri::command]
pub async fn list_secrets(
    store: State<'_, Arc<SecretsStore>>,
    vault: State<'_, Arc<Vault>>,
    connections: State<'_, Arc<ConnectionStore>>,
    ssh_store: State<'_, Arc<SshStore>>,
    vpn_store: State<'_, Arc<VpnStore>>,
) -> AppResult<Vec<SecretInfo>> {
    let file = store.read(Clone::clone)?;
    let connections = connections.read(Clone::clone)?;
    let ssh = ssh_store.snapshot()?;
    let vpn = vpn_store.snapshot()?;
    // A locked or unavailable vault still lists the secrets, just without knowing which have a value.
    let stored = vault.ids_with_prefix("secret:").unwrap_or_default();
    Ok(file
        .secrets
        .into_iter()
        .map(|secret| SecretInfo {
            has_value: stored.contains(&vault_id(&secret.id)),
            used_by: uses(&secret.id, &connections, &ssh, &vpn),
            id: secret.id,
            name: secret.name,
            note: secret.note,
        })
        .collect())
}

/// `value` is only written when given, so renaming a secret doesn't need its value again.
#[tauri::command]
pub async fn save_secret(
    store: State<'_, Arc<SecretsStore>>,
    vault: State<'_, Arc<Vault>>,
    mut secret: NamedSecret,
    value: Option<String>,
) -> AppResult<NamedSecret> {
    let value = value.map(Zeroizing::new);
    secret.name = secret.name.trim().to_string();
    secret.note = secret.note.trim().to_string();
    if secret.name.is_empty() {
        return Err(AppError::general("A secret needs a name"));
    }
    let is_new = secret.id.is_empty();
    if is_new && value.is_none() {
        return Err(AppError::general("Enter the secret's value"));
    }
    if is_new {
        secret.id = uuid::Uuid::new_v4().to_string();
    }
    // The value goes in first: a secret listed without one would prompt on every connect.
    if let Some(value) = &value {
        vault.set(&vault_id(&secret.id), value)?;
    }

    let saved = secret.clone();
    let result = store.update(move |file| {
        if file.secrets.iter().any(|other| other.id != secret.id && other.name.eq_ignore_ascii_case(&secret.name)) {
            return Err(AppError::general(format!("There's already a secret named {}", secret.name)));
        }
        match file.secrets.iter_mut().find(|existing| existing.id == secret.id) {
            Some(existing) => *existing = secret,
            None if is_new => file.secrets.push(secret),
            None => return Err(AppError::not_found("That secret was deleted")),
        }
        Ok(())
    });
    if result.is_err() && is_new {
        vault.remove(&vault_id(&saved.id))?;
    }
    result?;
    Ok(saved)
}

/// Fields that used it keep pointing at it and say so on the next connect.
#[tauri::command]
pub async fn delete_secret(store: State<'_, Arc<SecretsStore>>, vault: State<'_, Arc<Vault>>, id: String) -> AppResult<()> {
    let target = id.clone();
    store.update(move |file| {
        file.secrets.retain(|secret| secret.id != target);
        Ok(())
    })?;
    vault.remove_prefix(&owner(&id).prefix())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_store::{Identity, IdentityAuth, SshHost};

    #[test]
    fn uses_list_fields_and_slots_of_every_owner() {
        let mut ssh = SshFile::default();
        ssh.hosts.push(SshHost {
            id: "h1".to_string(),
            label: "api".to_string(),
            secret_refs: [("host".to_string(), "s1".to_string()), ("port".to_string(), "s2".to_string())].into(),
            ..Default::default()
        });
        ssh.identities.push(Identity {
            id: "i1".to_string(),
            label: "deploy".to_string(),
            user: String::new(),
            auth: IdentityAuth::Password,
            secret_refs: [("slot:password".to_string(), "s1".to_string())].into(),
        });

        let found = uses("s1", &ConnectionsFile::default(), &ssh, &VpnFile::default());
        let summary: Vec<(SecretUserKind, &str, &str, bool)> = found.iter().map(|used| (used.kind, used.label.as_str(), used.field.as_str(), used.slot)).collect();
        assert_eq!(summary, [(SecretUserKind::SshHost, "api", "host", false), (SecretUserKind::Identity, "deploy", "password", true)]);
    }
}
