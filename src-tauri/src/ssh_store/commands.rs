use std::{collections::HashMap, fs, path::Path, sync::Arc};

use serde::Serialize;
use tauri::State;

use super::{
    HOST_SECRET_RULES, IDENTITY_SECRET_RULES, Identity, IdentityAuth, KeyMeta, KeyStorage, PROXY_SECRET_RULES, Proxy, SshFile, SshHost,
    SshStore, now_millis,
};
use crate::secrets::fill::{blanked, check_refs};
use crate::connections::{ConnectionStore, PASSWORD_SLOT, PRIVATE_KEY_SLOT, SecretOwner};
use crate::error::{AppError, AppResult};
use crate::json_store::write_atomic;
use crate::ssh::config_import::{
    self, ConfigEntry, ImportCandidate, ImportPreview, JumpSpec, ParsedConfig, expand_home, home_dir, local_user,
};
use crate::ssh::keys::{self, KeyAlgorithm};
use crate::snippets::SnippetStore;
use crate::ssh::route::chain;
use crate::vault::Vault;
use crate::vault::reveal::{RevealOptions, confirm_user};

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn in_use(name: &str, users: Vec<String>) -> AppResult<()> {
    if users.is_empty() {
        return Ok(());
    }
    Err(AppError::general(format!("{name} is used by {}. Point them somewhere else first.", users.join(", "))))
}

fn trimmed(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

#[tauri::command]
pub async fn list_ssh(store: State<'_, Arc<SshStore>>) -> AppResult<SshFile> {
    store.snapshot()
}

/// Hosts in `ids` order (others keep theirs, after them) and the group order, from dragging in Home.
#[tauri::command]
pub async fn save_ssh_host_order(store: State<'_, Arc<SshStore>>, ids: Vec<String>, groups: Vec<String>) -> AppResult<()> {
    store.update(move |file| {
        file.hosts.sort_by_key(|host| ids.iter().position(|id| *id == host.id).unwrap_or(usize::MAX));
        file.group_order = groups.into_iter().map(|group| group.trim().to_string()).filter(|group| !group.is_empty()).collect();
        Ok(())
    })
}

/// Moves a host to another group without touching anything else about it.
#[tauri::command]
pub async fn move_ssh_host(store: State<'_, Arc<SshStore>>, id: String, group: Option<String>) -> AppResult<()> {
    let group = trimmed(group);
    store.update(move |file| {
        let host = file.hosts.iter_mut().find(|host| host.id == id).ok_or_else(|| AppError::not_found("That host was deleted"))?;
        host.group = group;
        Ok(())
    })
}

#[tauri::command]
pub async fn rename_ssh_group(store: State<'_, Arc<SshStore>>, from: String, to: String) -> AppResult<()> {
    let to = to.trim().to_string();
    if to.is_empty() {
        return Err(AppError::general("A group needs a name"));
    }
    store.update(move |file| {
        for host in file.hosts.iter_mut().filter(|host| host.group.as_deref() == Some(from.as_str())) {
            host.group = Some(to.clone());
        }
        if file.group_order.contains(&to) {
            file.group_order.retain(|name| *name != from);
        } else {
            for name in &mut file.group_order {
                if *name == from {
                    *name = to.clone();
                }
            }
        }
        Ok(())
    })
}

#[tauri::command]
pub async fn save_ssh_host(
    store: State<'_, Arc<SshStore>>,
    snippets: State<'_, Arc<SnippetStore>>,
    vpn_store: State<'_, Arc<crate::vpn_store::VpnStore>>,
    mut host: SshHost,
) -> AppResult<SshHost> {
    host.label = host.label.trim().to_string();
    host.host = host.host.trim().to_string();
    host.group = trimmed(host.group);
    host.identity_id = trimmed(host.identity_id);
    host.proxy_id = trimmed(host.proxy_id);
    host.vpn_id = trimmed(host.vpn_id);
    if let Some(id) = &host.vpn_id {
        vpn_store.find(id)?;
    }
    host.startup_snippet_id = trimmed(host.startup_snippet_id);
    if let Some(id) = &host.startup_snippet_id {
        if !snippets.exists(id)? {
            return Err(AppError::not_found("The snippet to run on connect was deleted"));
        }
    }
    if host.label.is_empty() {
        return Err(AppError::general("A host needs a name"));
    }
    check_refs(&host, &host.secret_refs, &HOST_SECRET_RULES, &crate::secrets::snapshot()?)?;
    let mut host = blanked(&host, &host.secret_refs)?;
    if host.host.is_empty() && !host.secret_refs.contains_key("host") {
        return Err(AppError::general("A host needs an address"));
    }
    if host.port == 0 {
        return Err(AppError::general("Choose a port"));
    }
    if host.id.is_empty() {
        host.id = new_id();
    }

    let saved = host.clone();
    store.update(move |file| {
        match &host.identity_id {
            Some(id) if file.identity(id).is_none() => return Err(AppError::not_found("That identity was deleted")),
            None => return Err(AppError::general("Pick how this host logs in")),
            _ => {}
        }
        if let Some(id) = &host.proxy_id {
            if file.proxy(id).is_none() {
                return Err(AppError::not_found("That proxy was deleted"));
            }
        }

        let id = host.id.clone();
        match file.hosts.iter_mut().find(|existing| existing.id == id) {
            Some(existing) => *existing = host,
            None => file.hosts.push(host),
        }
        // Also catches hosts that already jump through this one and now form a loop.
        for other in file.hosts.iter().filter(|other| other.id == id || other.jumps.contains(&id)) {
            chain(file, &other.id)?;
        }
        Ok(())
    })?;
    Ok(saved)
}

#[tauri::command]
pub async fn delete_ssh_host(
    store: State<'_, Arc<SshStore>>,
    connections: State<'_, Arc<ConnectionStore>>,
    id: String,
) -> AppResult<()> {
    let file = store.snapshot()?;
    let label = file.host_label(&id);
    let mut users: Vec<String> = connections.read(|connections| {
        connections
            .connections
            .iter()
            .filter(|profile| profile.driver.ssh_options().and_then(|ssh| ssh.host_id.as_deref()) == Some(id.as_str()))
            .map(|profile| profile.name.clone())
            .collect()
    })?;
    users.extend(file.hosts_jumping_through(&id).into_iter().map(|host| host.label.clone()));
    users.extend(file.forwards.iter().filter(|forward| forward.host_id == id).map(|forward| forward.label.clone()));
    in_use(&label, users)?;

    store.update(move |file| {
        file.hosts.retain(|host| host.id != id);
        Ok(())
    })
}

#[tauri::command]
pub async fn save_identity(
    store: State<'_, Arc<SshStore>>,
    vault: State<'_, Arc<Vault>>,
    mut identity: Identity,
) -> AppResult<Identity> {
    identity.user = identity.user.trim().to_string();
    identity.label = identity.label.trim().to_string();
    check_refs(&identity, &identity.secret_refs, &IDENTITY_SECRET_RULES, &crate::secrets::snapshot()?)?;
    let mut identity = blanked(&identity, &identity.secret_refs)?;
    let user_from_secret = identity.secret_refs.contains_key("user");
    if identity.user.is_empty() && !user_from_secret {
        return Err(AppError::general("Enter a user name"));
    }
    if identity.label.is_empty() && user_from_secret {
        return Err(AppError::general("Give this identity a name, since its user name comes from a secret"));
    }
    if identity.label.is_empty() {
        identity.label = identity.user.clone();
    }
    if identity.id.is_empty() {
        identity.id = new_id();
    }

    let saved = identity.clone();
    let previous = store.update(move |file| {
        if let IdentityAuth::Key { key_id } = &identity.auth {
            if file.key(key_id).is_none() {
                return Err(AppError::not_found("That key was deleted"));
            }
        }
        let previous = file.identity(&identity.id).map(|existing| existing.auth.clone());
        match file.identities.iter_mut().find(|existing| existing.id == identity.id) {
            Some(existing) => *existing = identity,
            None => file.identities.push(identity),
        }
        Ok(previous)
    })?;

    if previous == Some(IdentityAuth::Password) && saved.auth != IdentityAuth::Password {
        vault.remove(&SecretOwner::Identity(saved.id.clone()).secret_id(PASSWORD_SLOT))?;
    }
    Ok(saved)
}

#[tauri::command]
pub async fn delete_identity(store: State<'_, Arc<SshStore>>, vault: State<'_, Arc<Vault>>, id: String) -> AppResult<()> {
    let file = store.snapshot()?;
    let label = file.identity(&id).map(|identity| identity.label.clone()).unwrap_or_default();
    in_use(
        &label,
        file.hosts.iter().filter(|host| host.identity_id.as_deref() == Some(id.as_str())).map(|host| host.label.clone()).collect(),
    )?;

    let target = id.clone();
    store.update(move |file| {
        file.identities.retain(|identity| identity.id != target);
        Ok(())
    })?;
    vault.remove_prefix(&SecretOwner::Identity(id).prefix())
}

#[tauri::command]
pub async fn save_proxy(store: State<'_, Arc<SshStore>>, vault: State<'_, Arc<Vault>>, mut proxy: Proxy) -> AppResult<Proxy> {
    proxy.host = proxy.host.trim().to_string();
    proxy.user = proxy.user.trim().to_string();
    proxy.label = proxy.label.trim().to_string();
    check_refs(&proxy, &proxy.secret_refs, &PROXY_SECRET_RULES, &crate::secrets::snapshot()?)?;
    let mut proxy = blanked(&proxy, &proxy.secret_refs)?;
    let host_from_secret = proxy.secret_refs.contains_key("host");
    if proxy.host.is_empty() && !host_from_secret {
        return Err(AppError::general("Enter the proxy address"));
    }
    if proxy.port == 0 {
        return Err(AppError::general("Choose a port"));
    }
    if proxy.label.is_empty() && host_from_secret {
        return Err(AppError::general("Give this proxy a name, since its address comes from a secret"));
    }
    if proxy.label.is_empty() {
        proxy.label = proxy.host.clone();
    }
    if proxy.id.is_empty() {
        proxy.id = new_id();
    }

    let saved = proxy.clone();
    store.update(move |file| {
        match file.proxies.iter_mut().find(|existing| existing.id == proxy.id) {
            Some(existing) => *existing = proxy,
            None => file.proxies.push(proxy),
        }
        Ok(())
    })?;
    if saved.user.is_empty() && !saved.secret_refs.contains_key("user") {
        vault.remove(&SecretOwner::Proxy(saved.id.clone()).secret_id(PASSWORD_SLOT))?;
    }
    Ok(saved)
}

#[tauri::command]
pub async fn delete_proxy(store: State<'_, Arc<SshStore>>, vault: State<'_, Arc<Vault>>, id: String) -> AppResult<()> {
    let file = store.snapshot()?;
    let label = file.proxy(&id).map(|proxy| proxy.label.clone()).unwrap_or_default();
    in_use(
        &label,
        file.hosts.iter().filter(|host| host.proxy_id.as_deref() == Some(id.as_str())).map(|host| host.label.clone()).collect(),
    )?;

    let target = id.clone();
    store.update(move |file| {
        file.proxies.retain(|proxy| proxy.id != target);
        Ok(())
    })?;
    vault.remove_prefix(&SecretOwner::Proxy(id).prefix())
}

fn key_meta(label: String, public: &russh::keys::PublicKey, storage: KeyStorage) -> AppResult<KeyMeta> {
    let info = keys::describe(public)?;
    Ok(KeyMeta {
        id: new_id(),
        label,
        algorithm: info.algorithm,
        public_key: info.public_key,
        fingerprint: info.fingerprint,
        storage,
        created: now_millis(),
    })
}

fn already_saved(file: &SshFile, fingerprint: &str) -> AppResult<()> {
    match file.keys.iter().find(|key| key.fingerprint == fingerprint) {
        Some(existing) => Err(AppError::general(format!("That key is already in the keychain as {}", existing.label))),
        None => Ok(()),
    }
}

/// Puts the private half in the vault, then the metadata in ssh.json. A failed second step takes the first back out.
fn save_vault_key(store: &SshStore, vault: &Vault, key: &russh::keys::PrivateKey, label: String) -> AppResult<KeyMeta> {
    let meta = key_meta(label, key.public_key(), KeyStorage::Vault)?;
    store.read(|file| already_saved(file, &meta.fingerprint))??;

    let secret_id = SecretOwner::Key(meta.id.clone()).secret_id(PRIVATE_KEY_SLOT);
    vault.set(&secret_id, &keys::to_vault_text(key)?)?;

    let saved = meta.clone();
    if let Err(error) = store.update(move |file| {
        file.keys.push(meta);
        Ok(())
    }) {
        let _ = vault.remove(&secret_id);
        return Err(error);
    }
    Ok(saved)
}

#[tauri::command]
pub async fn generate_key(
    store: State<'_, Arc<SshStore>>,
    vault: State<'_, Arc<Vault>>,
    label: String,
    algorithm: KeyAlgorithm,
    comment: String,
) -> AppResult<KeyMeta> {
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err(AppError::general("Give the key a name"));
    }
    let comment = match comment.trim() {
        "" => label.clone(),
        comment => comment.to_string(),
    };
    let key = tauri::async_runtime::spawn_blocking(move || keys::generate(algorithm, &comment))
        .await
        .map_err(|error| AppError::general(error.to_string()))??;
    save_vault_key(&store, &vault, &key, label)
}

fn file_label(path: &str) -> String {
    Path::new(&expand_home(path))
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

#[tauri::command]
pub async fn import_key(
    store: State<'_, Arc<SshStore>>,
    vault: State<'_, Arc<Vault>>,
    path: String,
    label: String,
    to_vault: bool,
    passphrase: Option<String>,
) -> AppResult<KeyMeta> {
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err(AppError::general("Choose a key file"));
    }
    let label = match label.trim() {
        "" => file_label(&path),
        label => label.to_string(),
    };
    let passphrase = passphrase.map(zeroize::Zeroizing::new);

    if to_vault {
        let key = keys::read_private(&path, passphrase.as_ref().map(|value| value.as_str()))?;
        return save_vault_key(&store, &vault, &key, label);
    }

    let meta = key_meta(label, &keys::read_public(&path)?, KeyStorage::File { path })?;
    let saved = meta.clone();
    store.update(move |file| {
        already_saved(file, &meta.fingerprint)?;
        file.keys.push(meta);
        Ok(())
    })?;
    Ok(saved)
}

const MAX_PASTED_KEY: usize = 64 * 1024;

/// A pasted private key goes straight to the vault. Only its metadata comes back.
#[tauri::command]
pub async fn import_key_text(
    store: State<'_, Arc<SshStore>>,
    vault: State<'_, Arc<Vault>>,
    text: String,
    label: String,
    passphrase: Option<String>,
) -> AppResult<KeyMeta> {
    let text = zeroize::Zeroizing::new(text);
    let passphrase = passphrase.map(zeroize::Zeroizing::new);
    if text.trim().is_empty() {
        return Err(AppError::general("Paste the private key"));
    }
    if text.len() > MAX_PASTED_KEY {
        return Err(AppError::general("That's too long to be a private key"));
    }
    let key = keys::parse_private(&text, passphrase.as_ref().map(|value| value.as_str()), "The pasted text")?;
    let label = match label.trim() {
        "" => match key.comment().as_str_lossy().trim() {
            "" => format!("Pasted {} key", key.algorithm().as_str()),
            comment => comment.to_string(),
        },
        label => label.to_string(),
    };
    save_vault_key(&store, &vault, &key, label)
}

#[tauri::command]
pub async fn rename_key(store: State<'_, Arc<SshStore>>, id: String, label: String) -> AppResult<KeyMeta> {
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err(AppError::general("Give the key a name"));
    }
    store.update(move |file| {
        let key = file.keys.iter_mut().find(|key| key.id == id).ok_or_else(|| AppError::not_found("That key was deleted"))?;
        key.label = label;
        Ok(key.clone())
    })
}

/// Writes the private key, protected with a new passphrase, to a path the user picked in the save dialog.
/// The OS confirms the user first, like showing a password.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn export_key(
    window: tauri::WebviewWindow,
    store: State<'_, Arc<SshStore>>,
    vault: State<'_, Arc<Vault>>,
    id: String,
    path: String,
    passphrase: String,
    options: RevealOptions,
) -> AppResult<()> {
    let passphrase = zeroize::Zeroizing::new(passphrase);
    let meta = store.read(|file| file.key(&id).cloned())?.ok_or_else(|| AppError::not_found("That key was deleted"))?;
    if let KeyStorage::File { path } = &meta.storage {
        return Err(AppError::general(format!("This key is already a file at {path}")));
    }
    if path.trim().is_empty() {
        return Err(AppError::general("Choose where to save the key"));
    }
    confirm_user(&window, &vault, &format!("export the private key {}", meta.label), &options).await?;

    let text = vault
        .get(&SecretOwner::Key(id).secret_id(PRIVATE_KEY_SLOT))?
        .ok_or_else(|| AppError::vault(format!("The key {} is missing from the vault", meta.label)))?;
    let exported = keys::export(&keys::from_vault_text(&text)?, &passphrase)?;
    write_private_file(Path::new(path.trim()), exported.as_bytes())
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    write_atomic(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[tauri::command]
pub async fn delete_key(store: State<'_, Arc<SshStore>>, vault: State<'_, Arc<Vault>>, id: String) -> AppResult<()> {
    let file = store.snapshot()?;
    let label = file.key(&id).map(|key| key.label.clone()).unwrap_or_default();
    in_use(
        &label,
        file.identities
            .iter()
            .filter(|identity| matches!(&identity.auth, IdentityAuth::Key { key_id } if *key_id == id))
            .map(|identity| identity.label.clone())
            .collect(),
    )?;

    let target = id.clone();
    store.update(move |file| {
        file.keys.retain(|key| key.id != target);
        Ok(())
    })?;
    vault.remove_prefix(&SecretOwner::Key(id).prefix())
}

fn ssh_dir() -> AppResult<std::path::PathBuf> {
    home_dir().map(|home| home.join(".ssh")).ok_or_else(|| AppError::general("Couldn't find your home folder"))
}

fn read_config() -> AppResult<(String, Option<ParsedConfig>)> {
    let dir = ssh_dir()?;
    let path = dir.join("config");
    let display = path.to_string_lossy().to_string();
    match fs::read_to_string(&path) {
        Ok(text) => Ok((display, Some(config_import::parse(&text, &dir)))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((display, None)),
        Err(error) => Err(AppError::general(format!("Couldn't read {display}: {error}"))),
    }
}

const DEFAULT_KEY_FILES: &[&str] = &["id_ed25519", "id_ecdsa", "id_rsa"];

/// The key a host would log in with, like OpenSSH: its IdentityFile, else the first default key that exists. None means the agent.
fn key_file_for(entry_file: Option<&str>) -> Option<String> {
    if let Some(file) = entry_file {
        return Some(file.to_string());
    }
    DEFAULT_KEY_FILES
        .iter()
        .map(|name| format!("~/.ssh/{name}"))
        .find(|path| Path::new(&expand_home(path)).is_file())
}

fn jump_label(spec: &JumpSpec) -> String {
    match spec.port {
        Some(port) => format!("{}:{port}", spec.host),
        None => spec.host.clone(),
    }
}

fn existing_host<'a>(file: &'a SshFile, host: &str, port: u16, user: &str) -> Option<&'a SshHost> {
    file.hosts.iter().find(|existing| {
        existing.host.eq_ignore_ascii_case(host)
            && existing.port == port
            && existing.identity_id.as_deref().and_then(|id| file.identity(id)).is_some_and(|identity| identity.user == user)
    })
}

fn candidate(entry: &ConfigEntry, file: &SshFile) -> ImportCandidate {
    let host = entry.host_name.clone().unwrap_or_else(|| entry.alias.clone());
    let port = entry.port.unwrap_or(22);
    let user = entry.user.clone().unwrap_or_else(local_user);
    let identity_file = key_file_for(entry.identity_file.as_deref());

    let skip_reason = if user.is_empty() {
        Some("No user, and the local user name is unknown".to_string())
    } else if let Some(existing) = existing_host(file, &host, port, &user) {
        Some(format!("Already saved as {}", existing.label))
    } else if let Some(path) = identity_file.as_deref().filter(|path| !Path::new(&expand_home(path)).is_file()) {
        Some(format!("Its key file {path} doesn't exist"))
    } else {
        None
    };

    ImportCandidate {
        alias: entry.alias.clone(),
        host,
        port,
        user,
        identity_file,
        jumps: entry.proxy_jump.iter().map(jump_label).collect(),
        skip_reason,
    }
}

#[tauri::command]
pub async fn preview_ssh_config_import(store: State<'_, Arc<SshStore>>) -> AppResult<ImportPreview> {
    let (path, parsed) = read_config()?;
    let file = store.snapshot()?;
    Ok(match parsed {
        None => ImportPreview { path, found: false, candidates: Vec::new(), skipped_patterns: Vec::new() },
        Some(parsed) => ImportPreview {
            path,
            found: true,
            candidates: parsed.entries.iter().map(|entry| candidate(entry, &file)).collect(),
            skipped_patterns: parsed.skipped_patterns,
        },
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    pub imported: Vec<String>,
    pub skipped: Vec<String>,
}

struct Importer<'a> {
    parsed: &'a ParsedConfig,
    file: &'a mut SshFile,
    created: HashMap<String, String>,
    visiting: Vec<String>,
    outcome: ImportOutcome,
}

impl Importer<'_> {
    fn identity_for(&mut self, user: &str, key_file: Option<String>) -> AppResult<String> {
        let auth = match key_file {
            Some(path) => IdentityAuth::Key { key_id: self.key_for(&path)? },
            None => IdentityAuth::Agent { socket: String::new() },
        };
        if let Some(existing) = self.file.identities.iter().find(|identity| identity.user == user && identity.auth == auth) {
            return Ok(existing.id.clone());
        }

        let how = match &auth {
            IdentityAuth::Key { key_id } => self.file.key(key_id).map(|key| key.label.clone()).unwrap_or_default(),
            _ => "agent".to_string(),
        };
        let identity = Identity { id: new_id(), label: format!("{user} ({how})"), user: user.to_string(), auth, secret_refs: Default::default() };
        let id = identity.id.clone();
        self.file.identities.push(identity);
        Ok(id)
    }

    fn key_for(&mut self, path: &str) -> AppResult<String> {
        let expanded = expand_home(path);
        let same_file = |key: &KeyMeta| matches!(&key.storage, KeyStorage::File { path } if expand_home(path) == expanded);
        if let Some(existing) = self.file.keys.iter().find(|key| same_file(key)) {
            return Ok(existing.id.clone());
        }

        let public = keys::read_public(path)?;
        let fingerprint = public.fingerprint(russh::keys::HashAlg::Sha256).to_string();
        if let Some(existing) = self.file.keys.iter().find(|key| key.fingerprint == fingerprint) {
            return Ok(existing.id.clone());
        }
        let meta = key_meta(file_label(path), &public, KeyStorage::File { path: path.to_string() })?;
        let id = meta.id.clone();
        self.file.keys.push(meta);
        Ok(id)
    }

    /// An already saved host is linked instead of added again.
    fn add_host(&mut self, label: String, host: String, port: u16, user: &str, key_file: Option<String>, jumps: Vec<String>) -> AppResult<(String, bool)> {
        if let Some(existing) = existing_host(self.file, &host, port, user) {
            return Ok((existing.id.clone(), false));
        }
        let identity_id = self.identity_for(user, key_file)?;
        let saved = SshHost { id: new_id(), label, host, port, identity_id: Some(identity_id), jumps, ..Default::default() };
        let id = saved.id.clone();
        self.file.hosts.push(saved);
        Ok((id, true))
    }

    /// Jump hosts are imported before the hosts that use them.
    fn import(&mut self, alias: &str) -> AppResult<String> {
        if let Some(id) = self.created.get(alias) {
            return Ok(id.clone());
        }
        if self.visiting.iter().any(|seen| seen == alias) {
            return Err(AppError::general(format!("{alias} is reached through itself")));
        }
        let entry = self.parsed.entry(alias).ok_or_else(|| AppError::not_found(format!("{alias} isn't in the config")))?.clone();
        let host = entry.host_name.clone().unwrap_or_else(|| entry.alias.clone());
        let port = entry.port.unwrap_or(22);
        let user = entry.user.clone().unwrap_or_else(local_user);
        if user.is_empty() {
            return Err(AppError::general(format!("{alias} has no user")));
        }

        self.visiting.push(alias.to_string());
        let mut jumps = Vec::new();
        for spec in &entry.proxy_jump {
            let id = match self.parsed.entry(&spec.host) {
                Some(_) => self.import(&spec.host)?,
                None => {
                    let jump_user = spec.user.clone().unwrap_or_else(|| user.clone());
                    let label = jump_label(spec);
                    self.add_host(label, spec.host.clone(), spec.port.unwrap_or(22), &jump_user, key_file_for(None), Vec::new())?.0
                }
            };
            jumps.push(id);
        }
        self.visiting.pop();

        let (id, added) = self.add_host(entry.alias.clone(), host, port, &user, key_file_for(entry.identity_file.as_deref()), jumps)?;
        self.created.insert(alias.to_string(), id.clone());
        if added {
            self.outcome.imported.push(alias.to_string());
        }
        Ok(id)
    }
}

/// Re-reads the config instead of trusting what the preview sent back.
#[tauri::command]
pub async fn import_ssh_config(store: State<'_, Arc<SshStore>>, aliases: Vec<String>) -> AppResult<ImportOutcome> {
    let (path, parsed) = read_config()?;
    let parsed = parsed.ok_or_else(|| AppError::not_found(format!("{path} doesn't exist")))?;

    store.update(move |file| {
        let mut importer = Importer {
            parsed: &parsed,
            file,
            created: HashMap::new(),
            visiting: Vec::new(),
            outcome: ImportOutcome { imported: Vec::new(), skipped: Vec::new() },
        };
        for alias in &aliases {
            let before = (importer.file.clone(), importer.created.clone(), importer.outcome.imported.len());
            if let Err(error) = importer.import(alias) {
                *importer.file = before.0;
                importer.created = before.1;
                importer.outcome.imported.truncate(before.2);
                importer.visiting.clear();
                importer.outcome.skipped.push(format!("{alias}: {}", error.message));
            }
        }
        Ok(importer.outcome)
    })
}
