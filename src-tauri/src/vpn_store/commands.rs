use std::{path::Path, sync::Arc};

use serde::Serialize;
use tauri::State;

use super::{SECRET_RULES, TlsWrap, VpnFile, VpnKind, VpnProfile, VpnProto, VpnRemote, VpnStore};
use crate::secrets::fill::{blanked, check_refs, with_placeholders};
use crate::connections::{ConnectionStore, PASSWORD_SLOT, PRESHARED_KEY_SLOT, PRIVATE_KEY_SLOT, SecretOwner, TLS_KEY_SLOT};
use crate::error::{AppError, AppResult};
use crate::ssh_store::SshStore;
use crate::ssh_store::commands::write_private_file;
use crate::vault::Vault;
use crate::vault::reveal::{RevealOptions, confirm_user};
use crate::vpn::config;
use crate::vpn::keys::{self, CertSummary};
use crate::vpn::manager::VpnManager;
use crate::vpn::wireguard;

const MAX_PROFILE_FILE: u64 = 1024 * 1024;

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn trimmed(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn owner(id: &str) -> SecretOwner {
    SecretOwner::Vpn(id.to_string())
}

#[tauri::command]
pub async fn list_vpn(store: State<'_, Arc<VpnStore>>) -> AppResult<VpnFile> {
    store.snapshot()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnCertificates {
    pub ca: Vec<CertSummary>,
    pub cert: Vec<CertSummary>,
}

/// Names and expiry of pasted or saved certificates, which are public.
#[tauri::command]
pub async fn describe_vpn_certificates(ca: String, cert: String) -> AppResult<VpnCertificates> {
    Ok(VpnCertificates { ca: keys::certificate_summaries(&ca), cert: keys::certificate_summaries(&cert) })
}

/// Cleans what the editor sent. Key, import notes and the system mode reasons come from what's saved, not from the editor.
fn checked(mut profile: VpnProfile, existing: Option<&VpnProfile>) -> AppResult<VpnProfile> {
    profile.label = profile.label.trim().to_string();
    profile.user = profile.user.trim().to_string();
    profile.group = trimmed(profile.group);
    if profile.label.is_empty() {
        return Err(AppError::general("A VPN needs a name"));
    }
    if existing.is_some_and(|existing| existing.kind != profile.kind) {
        return Err(AppError::general("A VPN can't switch between OpenVPN and WireGuard. Make a new one."));
    }
    check_refs(&profile, &profile.secret_refs, &SECRET_RULES, &crate::secrets::snapshot()?)?;
    let mut profile = blanked(&profile, &profile.secret_refs)?;
    if profile.is_wireguard() {
        return checked_wireguard(profile, existing);
    }
    if profile.remotes.is_empty() {
        return Err(AppError::general("Add the VPN server"));
    }
    for (index, remote) in profile.remotes.iter_mut().enumerate() {
        remote.host = remote.host.trim().to_string();
        if remote.host.is_empty() && !profile.secret_refs.contains_key(&format!("remotes.{index}.host")) {
            return Err(AppError::general("A server has no address"));
        }
        if remote.port == 0 {
            return Err(AppError::general(format!("Choose a port for {}", remote.host)));
        }
    }
    if profile.auth.uses_password() && profile.user.is_empty() && !profile.secret_refs.contains_key("user") {
        return Err(AppError::general("Enter the user name for the VPN login"));
    }
    profile.ca = match profile.ca.trim() {
        "" => String::new(),
        text => keys::clean_certificates(text, "CA")?,
    };
    profile.cert = match profile.cert.trim() {
        "" => String::new(),
        text => keys::clean_certificates(text, "client certificate")?,
    };
    profile.peer_fingerprints = profile
        .peer_fingerprints
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(config::clean_fingerprint)
        .collect::<AppResult<_>>()?;
    if profile.ca.is_empty() && profile.peer_fingerprints.is_empty() {
        return Err(AppError::general("Add the CA certificate or the server's fingerprint, so Fran can check the server"));
    }
    profile.ciphers.retain(|cipher| config::is_current_cipher(cipher));

    profile.key_kind = existing.and_then(|existing| existing.key_kind.clone()).filter(|_| profile.auth.uses_cert());
    profile.imported = existing.and_then(|existing| existing.imported.clone());
    profile.system_options = existing.map(|existing| existing.system_options.clone()).unwrap_or_default();
    profile.pkcs11_provider = trimmed(profile.pkcs11_provider);
    if let Some(library) = &profile.pkcs11_provider {
        let path = Path::new(library);
        if !path.is_absolute() || !path.is_file() {
            return Err(AppError::general(format!("There's no smartcard library at {library}")));
        }
    }
    profile.needs_system = config::system_reasons(&profile);
    // Checks the fields can be written out, with a placeholder for the TLS key that lives in the vault.
    let placeholder = (profile.tls_wrap.needs_key()).then(|| match profile.tls_wrap {
        TlsWrap::CryptV2 => "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nAAAA\n-----END OpenVPN tls-crypt-v2 client key-----\n",
        _ => "-----BEGIN OpenVPN Static key V1-----\n00\n-----END OpenVPN Static key V1-----\n",
    });
    config::core_profile(&with_placeholders(&profile, &profile.secret_refs)?, placeholder)?;
    Ok(profile)
}

/// Only the fields WireGuard uses are kept, so nothing from OpenVPN's side of the editor ends up in vpn.json.
fn checked_wireguard(profile: VpnProfile, existing: Option<&VpnProfile>) -> AppResult<VpnProfile> {
    let remote = profile.remotes.first().ok_or_else(|| AppError::general("Add the WireGuard server's endpoint"))?;
    // An endpoint that comes from a secret is checked on connect, once its value is known.
    let remote = match profile.secret_refs.keys().any(|path| path.starts_with("remotes.0.")) {
        true if remote.port != 0 => VpnRemote { host: remote.host.clone(), port: remote.port, proto: VpnProto::Udp },
        _ => wireguard::clean_endpoint(remote)?,
    };
    let mut wire_guard = wireguard::clean(profile.wire_guard)?;
    wire_guard.public_key = existing.and_then(|existing| existing.wire_guard.public_key.clone());
    let secret_refs = profile.secret_refs.into_iter().filter(|(path, _)| path.starts_with("remotes.0.")).collect();
    Ok(VpnProfile {
        id: profile.id,
        label: profile.label,
        group: profile.group,
        color: profile.color,
        kind: VpnKind::WireGuard,
        secret_refs,
        remotes: vec![remote],
        require_server_cert: false,
        route_all: profile.route_all,
        use_vpn_dns: profile.use_vpn_dns,
        imported: existing.and_then(|existing| existing.imported.clone()),
        wire_guard,
        ..Default::default()
    })
}

/// Removes vault entries the profile no longer uses.
fn drop_unused(vault: &Vault, profile: &VpnProfile) -> AppResult<()> {
    let owner = owner(&profile.id);
    if profile.is_wireguard() {
        vault.remove(&owner.secret_id(PASSWORD_SLOT))?;
        vault.remove(&owner.secret_id(TLS_KEY_SLOT))?;
        return Ok(());
    }
    vault.remove(&owner.secret_id(PRESHARED_KEY_SLOT))?;
    if !profile.auth.uses_password() {
        vault.remove(&owner.secret_id(PASSWORD_SLOT))?;
    }
    if !profile.auth.uses_cert() {
        vault.remove(&owner.secret_id(PRIVATE_KEY_SLOT))?;
    }
    if !profile.tls_wrap.needs_key() {
        vault.remove(&owner.secret_id(TLS_KEY_SLOT))?;
    }
    Ok(())
}

#[tauri::command]
pub async fn save_vpn_profile(
    store: State<'_, Arc<VpnStore>>,
    vault: State<'_, Arc<Vault>>,
    mut profile: VpnProfile,
) -> AppResult<VpnProfile> {
    if profile.id.is_empty() {
        profile.id = new_id();
    }
    let existing = store.read(|file| file.profile(&profile.id).cloned())?;
    let profile = checked(profile, existing.as_ref())?;
    let saved = profile.clone();
    store.update(move |file| {
        match file.profiles.iter_mut().find(|existing| existing.id == profile.id) {
            Some(existing) => *existing = profile,
            None => file.profiles.push(profile),
        }
        Ok(())
    })?;
    drop_unused(&vault, &saved)?;
    Ok(saved)
}

fn update_profile(store: &VpnStore, id: &str, change: impl FnOnce(&mut VpnProfile)) -> AppResult<VpnProfile> {
    store.update(|file| {
        let profile = file.profiles.iter_mut().find(|profile| profile.id == id).ok_or_else(|| AppError::not_found("That VPN was deleted"))?;
        change(profile);
        profile.needs_system = config::system_reasons(profile);
        Ok(profile.clone())
    })
}

/// The pasted key goes straight to the vault. Only what kind of key it is comes back.
#[tauri::command]
pub async fn set_vpn_key(store: State<'_, Arc<VpnStore>>, vault: State<'_, Arc<Vault>>, id: String, pem: String) -> AppResult<VpnProfile> {
    let pem = zeroize::Zeroizing::new(pem);
    let (key, clean) = keys::read_client_key(&pem)?;
    store.find(&id)?;
    vault.set(&owner(&id).secret_id(PRIVATE_KEY_SLOT), &clean)?;
    update_profile(&store, &id, |profile| profile.key_kind = Some(key.kind()))
}

#[tauri::command]
pub async fn clear_vpn_key(store: State<'_, Arc<VpnStore>>, vault: State<'_, Arc<Vault>>, id: String) -> AppResult<VpnProfile> {
    vault.remove(&owner(&id).secret_id(PRIVATE_KEY_SLOT))?;
    update_profile(&store, &id, |profile| profile.key_kind = None)
}

fn wireguard_profile(store: &VpnStore, id: &str) -> AppResult<VpnProfile> {
    let profile = store.find(id)?;
    if !profile.is_wireguard() {
        return Err(AppError::general("That VPN isn't WireGuard"));
    }
    Ok(profile)
}

/// A pasted WireGuard private key goes to the vault. Only its public key comes back.
#[tauri::command]
pub async fn set_vpn_wireguard_key(store: State<'_, Arc<VpnStore>>, vault: State<'_, Arc<Vault>>, id: String, key: String) -> AppResult<VpnProfile> {
    let key = zeroize::Zeroizing::new(key);
    wireguard_profile(&store, &id)?;
    let clean = zeroize::Zeroizing::new(wireguard::clean_key(&key, "private key")?);
    let public_key = wireguard::public_key(&clean)?;
    vault.set(&owner(&id).secret_id(PRIVATE_KEY_SLOT), &clean)?;
    update_profile(&store, &id, |profile| profile.wire_guard.public_key = Some(public_key))
}

/// Makes a key pair in Fran. The private half goes straight to the vault, and the public half is what the server needs.
#[tauri::command]
pub async fn generate_vpn_wireguard_key(store: State<'_, Arc<VpnStore>>, vault: State<'_, Arc<Vault>>, id: String) -> AppResult<VpnProfile> {
    wireguard_profile(&store, &id)?;
    let (private_key, public_key) = wireguard::generate();
    vault.set(&owner(&id).secret_id(PRIVATE_KEY_SLOT), &private_key)?;
    update_profile(&store, &id, |profile| profile.wire_guard.public_key = Some(public_key))
}

/// An empty key removes the one saved.
#[tauri::command]
pub async fn set_vpn_preshared_key(store: State<'_, Arc<VpnStore>>, vault: State<'_, Arc<Vault>>, id: String, key: String) -> AppResult<()> {
    let key = zeroize::Zeroizing::new(key);
    wireguard_profile(&store, &id)?;
    let slot = owner(&id).secret_id(PRESHARED_KEY_SLOT);
    if key.trim().is_empty() {
        return vault.remove(&slot);
    }
    vault.set(&slot, &wireguard::clean_key(&key, "preshared key")?)
}

#[tauri::command]
pub async fn set_vpn_tls_key(store: State<'_, Arc<VpnStore>>, vault: State<'_, Arc<Vault>>, id: String, text: String) -> AppResult<()> {
    let text = zeroize::Zeroizing::new(text);
    let profile = store.find(&id)?;
    if !profile.tls_wrap.needs_key() {
        return Err(AppError::general("This VPN doesn't use tls-auth or tls-crypt"));
    }
    let clean = keys::clean_tls_key(&text, matches!(profile.tls_wrap, TlsWrap::CryptV2))?;
    vault.set(&owner(&id).secret_id(TLS_KEY_SLOT), &clean)
}

#[tauri::command]
pub async fn delete_vpn_profile(
    store: State<'_, Arc<VpnStore>>,
    vault: State<'_, Arc<Vault>>,
    connections: State<'_, Arc<ConnectionStore>>,
    ssh_store: State<'_, Arc<SshStore>>,
    manager: State<'_, Arc<VpnManager>>,
    id: String,
) -> AppResult<()> {
    let label = store.find(&id)?.label;
    let mut users: Vec<String> = connections.read(|file| {
        file.connections.iter().filter(|profile| profile.vpn_id.as_deref() == Some(id.as_str())).map(|profile| profile.name.clone()).collect()
    })?;
    users.extend(ssh_store.read(|file| {
        file.hosts.iter().filter(|host| host.vpn_id.as_deref() == Some(id.as_str())).map(|host| host.label.clone()).collect::<Vec<_>>()
    })?);
    if !users.is_empty() {
        return Err(AppError::general(format!("{label} is used by {}. Point them somewhere else first.", users.join(", "))));
    }

    manager.turn_off_system(&id).await;
    manager.disconnect(&id).await;
    let target = id.clone();
    store.update(move |file| {
        file.profiles.retain(|profile| profile.id != target);
        Ok(())
    })?;
    vault.remove_prefix(&owner(&id).prefix())
}

#[tauri::command]
pub async fn save_vpn_order(store: State<'_, Arc<VpnStore>>, ids: Vec<String>, groups: Vec<String>) -> AppResult<()> {
    store.update(move |file| {
        file.profiles.sort_by_key(|profile| ids.iter().position(|id| *id == profile.id).unwrap_or(usize::MAX));
        file.group_order = groups.into_iter().map(|group| group.trim().to_string()).filter(|group| !group.is_empty()).collect();
        Ok(())
    })
}

#[tauri::command]
pub async fn move_vpn_profile(store: State<'_, Arc<VpnStore>>, id: String, group: Option<String>) -> AppResult<()> {
    let group = trimmed(group);
    update_profile(&store, &id, |profile| profile.group = group).map(drop)
}

#[tauri::command]
pub async fn rename_vpn_group(store: State<'_, Arc<VpnStore>>, from: String, to: String) -> AppResult<()> {
    let to = to.trim().to_string();
    if to.is_empty() {
        return Err(AppError::general("A group needs a name"));
    }
    store.update(move |file| {
        for profile in file.profiles.iter_mut().filter(|profile| profile.group.as_deref() == Some(from.as_str())) {
            profile.group = Some(to.clone());
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

/// Writes the profile as a standard .ovpn or WireGuard .conf with its keys inline, to a path picked in the save dialog, after the OS confirms the user.
#[tauri::command]
pub async fn export_vpn_profile(
    window: tauri::WebviewWindow,
    store: State<'_, Arc<VpnStore>>,
    vault: State<'_, Arc<Vault>>,
    id: String,
    path: String,
    options: RevealOptions,
) -> AppResult<()> {
    let profile = store.find(&id)?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err(AppError::general("Choose where to save the profile"));
    }
    confirm_user(&window, &vault, &format!("export the VPN {} with its keys", profile.label), &options).await?;
    let owner = owner(&id);
    let key = vault.get(&owner.secret_id(PRIVATE_KEY_SLOT))?;
    if profile.is_wireguard() {
        let key = key.ok_or_else(|| AppError::general(format!("VPN {} has no private key to export", profile.label)))?;
        let preshared = vault.get(&owner.secret_id(PRESHARED_KEY_SLOT))?;
        let text = zeroize::Zeroizing::new(wireguard::portable(&profile, &key, preshared.as_deref().map(|key| key.as_str()))?);
        return write_private_file(Path::new(&path), text.as_bytes());
    }
    let tls_key = vault.get(&owner.secret_id(TLS_KEY_SLOT))?;
    let text = zeroize::Zeroizing::new(config::portable_profile(
        &profile,
        tls_key.as_deref().map(|key| key.as_str()),
        key.as_deref().map(|key| key.as_str()),
    )?);
    write_private_file(Path::new(&path), text.as_bytes())
}

/// Reads an .ovpn or a WireGuard .conf the user picked and saves it right away. Keys go to the vault and never come
/// back. A profile with a PKCS#12 file asks for its password through `secretsRequired`.
#[tauri::command]
pub async fn import_vpn_file(
    store: State<'_, Arc<VpnStore>>,
    vault: State<'_, Arc<Vault>>,
    path: String,
    secrets: Option<std::collections::HashMap<String, String>>,
) -> AppResult<VpnProfile> {
    let pkcs12_password = secrets.and_then(|mut secrets| secrets.remove(config::PKCS12_SLOT)).map(zeroize::Zeroizing::new);
    let path = Path::new(path.trim());
    let size = std::fs::metadata(path).map_err(|error| AppError::general(format!("Couldn't open {}: {error}", path.display())))?.len();
    if size > MAX_PROFILE_FILE {
        return Err(AppError::general("That file is too large to be a VPN profile"));
    }
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(path).map_err(|error| AppError::general(format!("Couldn't read {}: {error}", path.display())))?,
    );
    let file_name = path.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
    let (mut profile, secrets) = if wireguard::looks_like(&text) {
        let wireguard::Parsed { profile, private_key, preshared_key } = wireguard::parse(&text, &file_name)?;
        (profile, [(PRIVATE_KEY_SLOT, Some(private_key)), (PRESHARED_KEY_SLOT, preshared_key), (PASSWORD_SLOT, None)])
    } else {
        let config::Parsed { profile, private_key, tls_key, password } =
            config::parse_with(&text, &file_name, path.parent(), pkcs12_password.as_deref().map(|password| password.as_str()))?;
        (profile, [(PRIVATE_KEY_SLOT, private_key), (TLS_KEY_SLOT, tls_key), (PASSWORD_SLOT, password)])
    };
    profile.id = new_id();

    let owner = owner(&profile.id);
    for (slot, value) in &secrets {
        let Some(value) = value else { continue };
        if let Err(error) = vault.set(&owner.secret_id(*slot), value) {
            let _ = vault.remove_prefix(&owner.prefix());
            return Err(error);
        }
    }
    let saved = profile.clone();
    if let Err(error) = store.update(move |file| {
        file.profiles.push(profile);
        Ok(())
    }) {
        let _ = vault.remove_prefix(&owner.prefix());
        return Err(error);
    }
    Ok(saved)
}
