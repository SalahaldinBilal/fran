// The one place a saved secret goes back to the window, and only after the OS confirms the user.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use super::Vault;
use super::os_auth::{self, Outcome};
use crate::connections::{ConnectionStore, ConnectionsFile, SecretOwner};
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::secrets::SecretsFile;
use crate::ssh_store::{SshFile, SshStore};
use crate::vpn_store::{VpnFile, VpnStore};

pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
pub const UNLOCK_FOR: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RevealOptions {
    /// Asked for when the OS has nothing to check and the app lock is on.
    pub lock_password: Option<String>,
    /// Linux: Fran's own password dialog instead of polkit, after the user declined the polkit setup.
    pub password_dialog: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SecretGroup {
    Connection,
    Identity,
    Key,
    Proxy,
    Vpn,
    /// A named secret's value.
    Secret,
    /// Fran's own keys, like the one for agent history.
    Internal,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedSecret {
    pub id: String,
    pub owner: Option<SecretOwner>,
    pub slot: String,
    pub group: SecretGroup,
    /// None when what it belonged to was deleted.
    pub owner_label: Option<String>,
    pub label: String,
    pub revealable: bool,
}

struct Stores {
    connections: ConnectionsFile,
    ssh: SshFile,
    vpn: VpnFile,
    secrets: SecretsFile,
}

fn connection_slot_label(file: &ConnectionsFile, id: &str, slot: &str) -> String {
    let declared = file.connections.iter().find(|profile| profile.id == id).and_then(|profile| {
        let mut slots = profile.driver.required_secrets();
        slots.extend(profile.driver.optional_secrets());
        slots.into_iter().find(|candidate| candidate.id == slot).map(|candidate| candidate.label)
    });
    declared.unwrap_or_else(|| match slot {
        "password" => "Password".to_string(),
        "sshPassword" => "SSH password".to_string(),
        "sshKeyPassphrase" => "SSH key passphrase".to_string(),
        "apiToken" => "API token".to_string(),
        other => other.to_string(),
    })
}

/// `kind:id:slot` back into its owner and slot. Fran's own keys have none.
fn owner_of(vault_id: &str) -> Option<(SecretOwner, &str)> {
    let (kind, rest) = vault_id.split_once(':')?;
    let (id, slot) = rest.rsplit_once(':')?;
    let id = id.to_string();
    let owner = match kind {
        "connection" => SecretOwner::Connection(id),
        "identity" => SecretOwner::Identity(id),
        "key" => SecretOwner::Key(id),
        "proxy" => SecretOwner::Proxy(id),
        "vpn" => SecretOwner::Vpn(id),
        "secret" => SecretOwner::Secret(id),
        _ => return None,
    };
    Some((owner, slot))
}

fn describe(vault_id: &str, stores: &Stores) -> SavedSecret {
    let unknown = || SavedSecret {
        id: vault_id.to_string(),
        owner: None,
        slot: String::new(),
        group: SecretGroup::Unknown,
        owner_label: None,
        label: vault_id.to_string(),
        revealable: false,
    };
    let internal = |owner: &str| SavedSecret {
        id: vault_id.to_string(),
        owner: None,
        slot: String::new(),
        group: SecretGroup::Internal,
        owner_label: Some(owner.to_string()),
        label: "Encryption key".to_string(),
        revealable: false,
    };
    match vault_id {
        "agent:historyKey" => return internal("Agent history"),
        "terminal:logKey" => return internal("Terminal logs"),
        id if id.starts_with("cloud:") || id.starts_with("sync:") => return internal("Cloud sync"),
        _ => {}
    }

    let Some((kind, rest)) = vault_id.split_once(':') else {
        return unknown();
    };
    let Some((id, slot)) = rest.rsplit_once(':') else {
        return unknown();
    };
    let (owner, group, owner_label, label) = match kind {
        "connection" => (
            SecretOwner::Connection(id.to_string()),
            SecretGroup::Connection,
            stores.connections.connections.iter().find(|profile| profile.id == id).map(|profile| profile.name.clone()),
            connection_slot_label(&stores.connections, id, slot),
        ),
        "identity" => (
            SecretOwner::Identity(id.to_string()),
            SecretGroup::Identity,
            stores.ssh.identity(id).map(|identity| format!("{} ({})", identity.label, identity.user)),
            "Password".to_string(),
        ),
        "key" => (
            SecretOwner::Key(id.to_string()),
            SecretGroup::Key,
            stores.ssh.key(id).map(|key| key.label.clone()),
            if slot == "private" { "Private key" } else { "Passphrase" }.to_string(),
        ),
        "proxy" => (
            SecretOwner::Proxy(id.to_string()),
            SecretGroup::Proxy,
            stores.ssh.proxy(id).map(|proxy| proxy.label.clone()),
            "Password".to_string(),
        ),
        "vpn" => (
            SecretOwner::Vpn(id.to_string()),
            SecretGroup::Vpn,
            stores.vpn.profile(id).map(|profile| profile.label.clone()),
            match slot {
                "private" if stores.vpn.profile(id).is_some_and(|profile| profile.is_wireguard()) => "Private key",
                "private" => "Client key",
                "tlsKey" => "TLS key",
                "presharedKey" => "Preshared key",
                _ => "Password",
            }
            .to_string(),
        ),
        "secret" => (
            SecretOwner::Secret(id.to_string()),
            SecretGroup::Secret,
            stores.secrets.secret(id).map(|secret| secret.name.clone()),
            "Secret".to_string(),
        ),
        _ => return unknown(),
    };
    SavedSecret {
        id: vault_id.to_string(),
        revealable: owner.revealable(slot),
        owner: Some(owner),
        slot: slot.to_string(),
        group,
        owner_label,
        label,
    }
}

fn stores(connections: &ConnectionStore, ssh: &SshStore, vpn: &VpnStore) -> AppResult<Stores> {
    Ok(Stores { connections: connections.read(Clone::clone)?, ssh: ssh.snapshot()?, vpn: vpn.snapshot()?, secrets: crate::secrets::snapshot()? })
}

/// "Password" reads as "password" in a sentence, "SSH password" stays as it is.
fn in_sentence(label: &str) -> String {
    let mut chars = label.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if first.is_uppercase() && second.is_lowercase() => format!("{}{}", first.to_lowercase(), &label[first.len_utf8()..]),
        _ => label.to_string(),
    }
}

/// Asks the OS to confirm the user. With nothing to check, the app lock password stands in when the lock is on.
pub async fn confirm_user(window: &WebviewWindow, vault: &Arc<Vault>, action: &str, options: &RevealOptions) -> AppResult<()> {
    if vault.is_locked() {
        return Err(AppError::app_locked());
    }
    let outcome = os_auth::confirm(window, action, options.password_dialog).await?;
    let reason = match outcome {
        Outcome::Confirmed => return Ok(()),
        Outcome::NoProtection if !vault.lock_enabled() => return Ok(()),
        Outcome::NoProtection => None,
        Outcome::Unavailable(reason) => Some(reason),
    };
    if !vault.lock_enabled() {
        return Err(AppError::general(format!(
            "{}. Turn on the app lock in Settings, Security, and Fran asks for its password instead.",
            reason.unwrap_or_default()
        )));
    }
    let password = options
        .lock_password
        .clone()
        .map(Zeroizing::new)
        .ok_or_else(|| AppError::new("Enter the app lock password", ErrorDetail::LockPasswordRequired))?;
    let vault = vault.clone();
    tauri::async_runtime::spawn_blocking(move || vault.check_lock_password(&password))
        .await
        .map_err(|error| AppError::general(error.to_string()))?
}

/// While the passwords are unlocked, showing and copying one doesn't ask again. Exports always ask.
#[derive(Default)]
pub struct RevealSession {
    until: std::sync::Mutex<Option<Instant>>,
}

impl RevealSession {
    pub fn remaining(&self) -> Duration {
        self.until
            .lock()
            .ok()
            .and_then(|until| *until)
            .map(|until| until.saturating_duration_since(Instant::now()))
            .unwrap_or_default()
    }

    pub fn active(&self) -> bool {
        !self.remaining().is_zero()
    }

    fn open(&self) {
        if let Ok(mut until) = self.until.lock() {
            *until = Some(Instant::now() + UNLOCK_FOR);
        }
    }

    pub fn close(&self) {
        if let Ok(mut until) = self.until.lock() {
            *until = None;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn take(
    window: &WebviewWindow,
    vault: &Arc<Vault>,
    session: &RevealSession,
    stores: Stores,
    owner: &SecretOwner,
    slot: &str,
    verb: &str,
    options: &RevealOptions,
) -> AppResult<Zeroizing<String>> {
    if !owner.revealable(slot) {
        return Err(AppError::general("Keys can't be shown. Export them from the Secrets page instead."));
    }
    let id = owner.secret_id(slot);
    if vault.get(&id)?.is_none() {
        return Err(AppError::not_found("Nothing is saved there"));
    }
    let described = describe(&id, &stores);
    let action = match &described.owner_label {
        Some(name) => format!("{verb} the {} for {name}", in_sentence(&described.label)),
        None => format!("{verb} a saved {}", in_sentence(&described.label)),
    };
    if vault.is_locked() {
        session.close();
        return Err(AppError::app_locked());
    }
    if !session.active() {
        confirm_user(window, vault, &action, options).await?;
    }
    vault.get(&id)?.ok_or_else(|| AppError::not_found("Nothing is saved there"))
}

#[tauri::command]
pub async fn list_saved_secrets(
    vault: State<'_, Arc<Vault>>,
    connections: State<'_, Arc<ConnectionStore>>,
    ssh_store: State<'_, Arc<SshStore>>,
    vpn_store: State<'_, Arc<VpnStore>>,
) -> AppResult<Vec<SavedSecret>> {
    let stores = stores(&connections, &ssh_store, &vpn_store)?;
    Ok(vault.ids_with_prefix("")?.iter().map(|id| describe(id, &stores)).collect())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn reveal_secret(
    window: WebviewWindow,
    vault: State<'_, Arc<Vault>>,
    connections: State<'_, Arc<ConnectionStore>>,
    ssh_store: State<'_, Arc<SshStore>>,
    vpn_store: State<'_, Arc<VpnStore>>,
    session: State<'_, Arc<RevealSession>>,
    owner: SecretOwner,
    slot: String,
    options: RevealOptions,
) -> AppResult<String> {
    let stores = stores(&connections, &ssh_store, &vpn_store)?;
    let value = take(&window, &vault, &session, stores, &owner, &slot, "show", &options).await?;
    Ok(value.to_string())
}

/// Asks the OS once, then every password can be shown for `UNLOCK_FOR`. Returns how long, in milliseconds.
#[tauri::command]
pub async fn unlock_secrets(
    window: WebviewWindow,
    vault: State<'_, Arc<Vault>>,
    session: State<'_, Arc<RevealSession>>,
    options: RevealOptions,
) -> AppResult<u64> {
    confirm_user(&window, &vault, "show your saved passwords", &options).await?;
    session.open();
    Ok(session.remaining().as_millis() as u64)
}

#[tauri::command]
pub async fn lock_secrets(session: State<'_, Arc<RevealSession>>) -> AppResult<()> {
    session.close();
    Ok(())
}

/// Milliseconds left, 0 when locked.
#[tauri::command]
pub async fn get_secrets_unlock(vault: State<'_, Arc<Vault>>, session: State<'_, Arc<RevealSession>>) -> AppResult<u64> {
    if vault.is_locked() {
        session.close();
    }
    Ok(session.remaining().as_millis() as u64)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedSecret {
    pub id: String,
    pub value: String,
}

/// Every password, passphrase and token at once. Only while unlocked, never keys.
#[tauri::command]
pub async fn reveal_all_secrets(vault: State<'_, Arc<Vault>>, session: State<'_, Arc<RevealSession>>) -> AppResult<Vec<RevealedSecret>> {
    if vault.is_locked() {
        session.close();
        return Err(AppError::app_locked());
    }
    if !session.active() {
        return Err(AppError::general("Unlock the passwords first"));
    }
    let mut revealed = Vec::new();
    for id in vault.ids_with_prefix("")? {
        if !owner_of(&id).is_some_and(|(owner, slot)| owner.revealable(slot)) {
            continue;
        }
        if let Some(value) = vault.get(&id)? {
            revealed.push(RevealedSecret { id, value: value.to_string() });
        }
    }
    Ok(revealed)
}

/// Writes straight to the clipboard, so the value never passes through the window. Cleared after 30 seconds if still there.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn copy_secret(
    app: AppHandle,
    window: WebviewWindow,
    vault: State<'_, Arc<Vault>>,
    connections: State<'_, Arc<ConnectionStore>>,
    ssh_store: State<'_, Arc<SshStore>>,
    vpn_store: State<'_, Arc<VpnStore>>,
    session: State<'_, Arc<RevealSession>>,
    owner: SecretOwner,
    slot: String,
    options: RevealOptions,
) -> AppResult<()> {
    let stores = stores(&connections, &ssh_store, &vpn_store)?;
    let value = take(&window, &vault, &session, stores, &owner, &slot, "copy", &options).await?;
    let fingerprint = digest(&SHA256, value.as_bytes());
    app.clipboard().write_text(value.to_string()).map_err(|error| AppError::general(format!("Couldn't copy: {error}")))?;
    drop(value);

    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(CLIPBOARD_CLEAR_AFTER).await;
        if let Ok(current) = app.clipboard().read_text() {
            let current = Zeroizing::new(current);
            if digest(&SHA256, current.as_bytes()).as_ref() == fingerprint.as_ref() {
                let _ = app.clipboard().write_text(String::new());
            }
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn get_os_auth_status() -> AppResult<bool> {
    Ok(os_auth::account_unprotected().await)
}

#[tauri::command]
pub async fn install_os_auth() -> AppResult<()> {
    os_auth::install().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::NamedSecret;
    use crate::ssh_store::{Identity, IdentityAuth};

    fn sample() -> Stores {
        let mut ssh = SshFile::default();
        ssh.identities.push(Identity { id: "i1".to_string(), label: "deploy".to_string(), user: "deploy".to_string(), auth: IdentityAuth::Password, secret_refs: Default::default() });
        let secrets = SecretsFile {
            secrets: vec![NamedSecret { id: "s1".to_string(), name: "PROD_DB_HOST".to_string(), ..NamedSecret::default() }],
            ..Default::default()
        };
        Stores { connections: ConnectionsFile::default(), ssh, vpn: VpnFile::default(), secrets }
    }

    #[test]
    fn keys_are_listed_but_never_revealable() {
        let stores = sample();
        for id in ["key:k1:private", "vpn:v1:private", "vpn:v1:tlsKey", "agent:historyKey", "terminal:logKey", "odd"] {
            assert!(!describe(id, &stores).revealable, "{id}");
        }
        for id in ["identity:i1:password", "key:k1:passphrase", "proxy:p1:password", "vpn:v1:password", "connection:c1:sshPassword", "secret:s1:value"] {
            assert!(describe(id, &stores).revealable, "{id}");
        }
    }

    #[test]
    fn owners_and_labels() {
        let stores = sample();
        let identity = describe("identity:i1:password", &stores);
        assert_eq!(identity.group, SecretGroup::Identity);
        assert_eq!(identity.owner_label.as_deref(), Some("deploy (deploy)"));
        let deleted = describe("connection:gone:sshPassword", &stores);
        assert_eq!((deleted.owner_label, deleted.label.as_str()), (None, "SSH password"));
        assert_eq!(describe("agent:historyKey", &stores).group, SecretGroup::Internal);
    }

    #[test]
    fn unlock_window_opens_and_closes() {
        let session = RevealSession::default();
        assert!(!session.active());
        session.open();
        assert!(session.active());
        assert!(session.remaining() <= UNLOCK_FOR);
        session.close();
        assert!(!session.active());
        assert!(owner_of("agent:historyKey").is_none());
        assert_eq!(owner_of("vpn:v1:password").map(|(_, slot)| slot), Some("password"));
    }

    #[test]
    fn labels_read_in_a_sentence() {
        assert_eq!(in_sentence("Password"), "password");
        assert_eq!(in_sentence("SSH password"), "SSH password");
        assert_eq!(in_sentence("API token"), "API token");
    }
}
