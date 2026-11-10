use std::{collections::HashSet, path::Path, sync::Arc};

use russh::keys::{PrivateKey, decode_secret_key, load_secret_key};
use zeroize::Zeroizing;

use super::proxy::ProxyTarget;
use super::{SSH_PASSPHRASE_SLOT, SSH_PASSWORD_SLOT, SshAuthMethod, SshOptions};
use crate::connections::{PASSPHRASE_SLOT, PASSWORD_SLOT, PRIVATE_KEY_SLOT, SecretBag, SecretOwner, SecretSlot};
use crate::error::{AppError, AppResult};
use crate::ssh_store::{Identity, IdentityAuth, KeyMeta, KeyStorage, Proxy, SshFile, SshHost, SshStore};
use crate::vault::Vault;
use crate::vpn::manager::{VpnLeg, VpnPlan};

pub const MAX_HOPS: usize = 8;
const DEFAULT_KEEPALIVE_SECS: u32 = 30;

pub enum HopAuth {
    Password(Zeroizing<String>),
    Key(Arc<PrivateKey>),
    /// An empty socket means the usual agent for the OS.
    Agent { socket: String },
}

pub struct Hop {
    pub label: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: HopAuth,
    pub keepalive_secs: u32,
}

/// Hops from the outermost to the target. The VPN and the proxy are only used to reach the first one.
pub struct SshRoute {
    pub hops: Vec<Hop>,
    pub proxy: Option<ProxyTarget>,
    pub vpn: Option<VpnLeg>,
}

/// The VPN for a host's first hop: its own, else its first jump's, the same way the proxy is found.
pub fn route_vpn<'a>(file: &'a SshFile, host_id: &str) -> Option<&'a str> {
    let mut seen = Vec::new();
    let mut current = file.host(host_id)?;
    loop {
        if let Some(vpn) = current.vpn_id.as_deref() {
            return Some(vpn);
        }
        seen.push(current.id.as_str());
        let first = current.jumps.first()?;
        if seen.contains(&first.as_str()) || seen.len() > MAX_HOPS {
            return None;
        }
        current = file.host(first)?;
    }
}

/// Saved hosts from the outermost hop to `host_id`, and the proxy for the first hop.
/// The first jump host is reached through its own route, the same way OpenSSH treats ProxyJump.
pub fn chain<'a>(file: &'a SshFile, host_id: &str) -> AppResult<(Vec<&'a SshHost>, Option<&'a str>)> {
    let mut path = Vec::new();
    let (hops, proxy) = expand(file, host_id, &mut path)?;

    let mut seen = HashSet::new();
    for hop in &hops {
        if !seen.insert(hop.id.as_str()) {
            return Err(AppError::general(format!("{} appears twice in the route", hop.label)));
        }
    }
    if hops.len() > MAX_HOPS {
        return Err(AppError::general(format!(
            "The route to {} has {} hops. At most {MAX_HOPS} are allowed.",
            file.host_label(host_id),
            hops.len()
        )));
    }
    Ok((hops, proxy))
}

fn expand<'a>(file: &'a SshFile, id: &str, path: &mut Vec<String>) -> AppResult<(Vec<&'a SshHost>, Option<&'a str>)> {
    if path.iter().any(|seen| seen == id) {
        return Err(AppError::general(format!("{} is reached through itself", file.host_label(id))));
    }
    let host = file.host(id).ok_or_else(|| match path.last() {
        Some(parent) => AppError::not_found(format!("A jump host of {} was deleted", file.host_label(parent))),
        None => AppError::not_found("That SSH host was deleted"),
    })?;
    if path.len() >= MAX_HOPS {
        return Err(AppError::general(format!("The route to {} is more than {MAX_HOPS} hops long", host.label)));
    }

    path.push(id.to_string());
    let (mut hops, inner_proxy) = match host.jumps.split_first() {
        None => (Vec::new(), None),
        Some((first, rest)) => {
            let (mut hops, inner_proxy) = expand(file, first, path)?;
            for jump in rest {
                if path.iter().any(|seen| seen == jump) {
                    return Err(AppError::general(format!("{} is reached through itself", file.host_label(jump))));
                }
                hops.push(file.host(jump).ok_or_else(|| {
                    AppError::not_found(format!("A jump host of {} was deleted", host.label))
                })?);
            }
            (hops, inner_proxy)
        }
    };
    path.pop();

    hops.push(host);
    Ok((hops, host.proxy_id.as_deref().or(inner_proxy)))
}

pub struct PlannedHop {
    host: SshHost,
    identity: Identity,
    key: Option<KeyMeta>,
}

/// A route whose secrets haven't been looked up yet, so all of them can be asked for in one prompt.
pub enum RoutePlan {
    Inline { options: SshOptions, vpn: Option<VpnPlan> },
    Saved { hops: Vec<PlannedHop>, proxy: Option<Proxy>, vpn: Option<VpnPlan> },
}

impl RoutePlan {
    /// `connection_vpn` only applies to inline SSH. A saved host brings its own VPN.
    pub fn for_options(options: &SshOptions, store: &SshStore, connection_vpn: Option<&str>) -> AppResult<Self> {
        match options.host_id.as_deref() {
            Some("") => Err(AppError::general("Pick a saved SSH host for this connection")),
            Some(host_id) => Self::for_host(host_id, store),
            None => Ok(Self::Inline {
                options: options.clone(),
                vpn: connection_vpn.map(VpnPlan::for_profile).transpose()?,
            }),
        }
    }

    pub fn for_host(host_id: &str, store: &SshStore) -> AppResult<Self> {
        let file = store.snapshot()?;
        let (hosts, proxy_id) = chain(&file, host_id)?;
        let vpn = route_vpn(&file, host_id).map(VpnPlan::for_profile).transpose()?;

        let mut hops = Vec::with_capacity(hosts.len());
        for host in hosts {
            let identity = host
                .identity_id
                .as_deref()
                .and_then(|id| file.identity(id))
                .ok_or_else(|| AppError::general(format!("{} has no login. Pick an identity in its settings.", host.label)))?;
            let key = match &identity.auth {
                IdentityAuth::Key { key_id } => Some(file.key(key_id).cloned().ok_or_else(|| {
                    AppError::not_found(format!("The key used by {} was deleted", identity.label))
                })?),
                IdentityAuth::Password | IdentityAuth::Agent { .. } => None,
            };
            hops.push(PlannedHop {
                host: host.clone(),
                identity: identity.clone(),
                key,
            });
        }

        let proxy = match proxy_id {
            Some(id) => Some(file.proxy(id).cloned().ok_or_else(|| AppError::not_found("The proxy for this route was deleted"))?),
            None => None,
        };
        Ok(Self::Saved { hops, proxy, vpn })
    }

    fn vpn(&self) -> Option<&VpnPlan> {
        match self {
            Self::Inline { vpn, .. } | Self::Saved { vpn, .. } => vpn.as_ref(),
        }
    }

    /// Inline options already add their SSH slots through the driver's own list.
    pub fn required_secrets(&self) -> Vec<SecretSlot> {
        let mut slots = self.vpn().map(VpnPlan::required_secrets).unwrap_or_default();
        let Self::Saved { hops, proxy, .. } = self else {
            return slots;
        };

        for hop in hops {
            if hop.identity.auth == IdentityAuth::Password {
                slots.push(identity_password_slot(&hop.identity, &hop.host));
            }
        }
        if let Some(proxy) = proxy.as_ref().filter(|proxy| !proxy.user.trim().is_empty()) {
            slots.push(proxy_password_slot(proxy));
        }
        dedupe(slots)
    }

    pub fn optional_secrets(&self) -> Vec<SecretSlot> {
        let Self::Saved { hops, .. } = self else {
            return Vec::new();
        };
        dedupe(
            hops.iter()
                .filter_map(|hop| hop.key.as_ref())
                .filter(|key| matches!(key.storage, KeyStorage::File { .. }))
                .map(key_passphrase_slot)
                .collect(),
        )
    }

    pub fn resolve(&self, secrets: &SecretBag, vault: &Vault) -> AppResult<SshRoute> {
        let vpn = self.vpn().map(|plan| plan.resolve(secrets));
        match self {
            Self::Inline { options, .. } => Ok(SshRoute {
                hops: vec![inline_hop(options, secrets)?],
                proxy: None,
                vpn,
            }),
            Self::Saved { hops, proxy, .. } => {
                let mut resolved = Vec::with_capacity(hops.len());
                for hop in hops {
                    resolved.push(saved_hop(hop, secrets, vault)?);
                }
                let proxy = match proxy {
                    Some(proxy) => Some(proxy_target(proxy, secrets)?),
                    None => None,
                };
                Ok(SshRoute { hops: resolved, proxy, vpn })
            }
        }
    }
}

fn dedupe(slots: Vec<SecretSlot>) -> Vec<SecretSlot> {
    let mut seen = HashSet::new();
    slots.into_iter().filter(|slot| seen.insert(slot.id.clone())).collect()
}

pub fn identity_password_slot(identity: &Identity, host: &SshHost) -> SecretSlot {
    SecretSlot::owned(
        SecretOwner::Identity(identity.id.clone()),
        PASSWORD_SLOT,
        format!("SSH password for {} on {}", identity.user, host.label),
    )
}

pub fn key_passphrase_slot(key: &KeyMeta) -> SecretSlot {
    SecretSlot::owned(SecretOwner::Key(key.id.clone()), PASSPHRASE_SLOT, format!("Passphrase for the key {}", key.label))
}

pub fn proxy_password_slot(proxy: &Proxy) -> SecretSlot {
    SecretSlot::owned(SecretOwner::Proxy(proxy.id.clone()), PASSWORD_SLOT, format!("Password for the proxy {}", proxy.label))
}

fn inline_hop(options: &SshOptions, secrets: &SecretBag) -> AppResult<Hop> {
    if options.host.trim().is_empty() {
        return Err(AppError::ssh("SSH host is empty"));
    }
    let auth = match options.auth {
        SshAuthMethod::Password => HopAuth::Password(Zeroizing::new(
            secrets
                .get(SSH_PASSWORD_SLOT)
                .ok_or_else(|| AppError::secrets_required(vec![SshOptions::password_slot()]))?
                .to_string(),
        )),
        SshAuthMethod::PublicKey => HopAuth::Key(Arc::new(load_key_file(
            &options.key_file,
            secrets.get(SSH_PASSPHRASE_SLOT),
            SshOptions::passphrase_slot,
        )?)),
        SshAuthMethod::Agent => HopAuth::Agent {
            socket: options.agent_socket.clone(),
        },
    };
    Ok(Hop {
        label: options.host.trim().to_string(),
        host: options.host.trim().to_string(),
        port: options.port,
        user: options.user.clone(),
        auth,
        keepalive_secs: DEFAULT_KEEPALIVE_SECS,
    })
}

fn saved_hop(hop: &PlannedHop, secrets: &SecretBag, vault: &Vault) -> AppResult<Hop> {
    let auth = match (&hop.identity.auth, &hop.key) {
        (IdentityAuth::Password, _) => {
            let slot = identity_password_slot(&hop.identity, &hop.host);
            let password = secrets.get(&slot.id).ok_or_else(|| AppError::secrets_required(vec![slot.clone()]))?;
            HopAuth::Password(Zeroizing::new(password.to_string()))
        }
        (IdentityAuth::Agent { socket }, _) => HopAuth::Agent { socket: socket.clone() },
        (IdentityAuth::Key { .. }, Some(key)) => HopAuth::Key(Arc::new(load_saved_key(key, secrets, vault)?)),
        (IdentityAuth::Key { .. }, None) => {
            return Err(AppError::not_found(format!("The key used by {} was deleted", hop.identity.label)));
        }
    };
    if hop.host.host.trim().is_empty() {
        return Err(AppError::ssh(format!("{} has no address", hop.host.label)));
    }
    Ok(Hop {
        label: hop.host.label.clone(),
        host: hop.host.host.trim().to_string(),
        port: hop.host.port,
        user: hop.identity.user.clone(),
        auth,
        keepalive_secs: hop.host.keepalive_secs,
    })
}

pub fn load_saved_key(key: &KeyMeta, secrets: &SecretBag, vault: &Vault) -> AppResult<PrivateKey> {
    match &key.storage {
        KeyStorage::Vault => {
            let text = vault
                .get(&SecretOwner::Key(key.id.clone()).secret_id(PRIVATE_KEY_SLOT))?
                .ok_or_else(|| AppError::vault(format!("The key {} is missing from the vault", key.label)))?;
            decode_secret_key(&text, None)
                .map_err(|error| AppError::ssh(format!("The key {} in the vault is damaged: {error}", key.label)))
        }
        KeyStorage::File { path } => {
            let slot = key_passphrase_slot(key);
            load_key_file(path, secrets.get(&slot.id), || slot.clone())
        }
    }
}

/// An encrypted key without a passphrase asks for one.
pub fn load_key_file(path: &str, passphrase: Option<&str>, slot: impl FnOnce() -> SecretSlot) -> AppResult<PrivateKey> {
    let expanded = super::config_import::expand_home(path);
    let file = Path::new(&expanded);
    if path.trim().is_empty() || !file.is_file() {
        return Err(AppError::ssh(format!("SSH key file not found: {path}")));
    }
    match passphrase {
        Some(passphrase) => load_secret_key(file, Some(passphrase))
            .map_err(|error| AppError::ssh(format!("SSH key could not be opened: {error}"))),
        None => load_secret_key(file, None).map_err(|_| AppError::secrets_required(vec![slot()])),
    }
}

fn proxy_target(proxy: &Proxy, secrets: &SecretBag) -> AppResult<ProxyTarget> {
    let login = match proxy.user.trim() {
        "" => None,
        user => {
            let slot = proxy_password_slot(proxy);
            let password = secrets.get(&slot.id).ok_or_else(|| AppError::secrets_required(vec![slot.clone()]))?;
            Some((user.to_string(), Zeroizing::new(password.to_string())))
        }
    };
    Ok(ProxyTarget {
        kind: proxy.kind,
        label: proxy.label.clone(),
        host: proxy.host.trim().to_string(),
        port: proxy.port,
        login,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, jumps: &[&str], proxy: Option<&str>) -> SshHost {
        SshHost {
            id: id.to_string(),
            label: id.to_string(),
            host: format!("{id}.example"),
            jumps: jumps.iter().map(|jump| jump.to_string()).collect(),
            proxy_id: proxy.map(str::to_string),
            ..Default::default()
        }
    }

    fn file(hosts: Vec<SshHost>) -> SshFile {
        SshFile {
            hosts,
            ..Default::default()
        }
    }

    fn ids(file: &SshFile, id: &str) -> Vec<String> {
        chain(file, id).unwrap().0.iter().map(|host| host.id.clone()).collect()
    }

    #[test]
    fn direct_host_is_one_hop() {
        let file = file(vec![host("a", &[], None)]);
        assert_eq!(ids(&file, "a"), ["a"]);
    }

    #[test]
    fn jumps_come_first_in_order() {
        let file = file(vec![host("a", &[], None), host("b", &[], None), host("c", &["a", "b"], None)]);
        assert_eq!(ids(&file, "c"), ["a", "b", "c"]);
    }

    #[test]
    fn first_jump_uses_its_own_route() {
        let file = file(vec![host("edge", &[], None), host("bastion", &["edge"], None), host("api", &["bastion"], None)]);
        assert_eq!(ids(&file, "api"), ["edge", "bastion", "api"]);
    }

    #[test]
    fn missing_hosts_are_reported() {
        let file = file(vec![host("a", &["gone"], None)]);
        let error = chain(&file, "a").unwrap_err();
        assert!(error.message.contains("jump host of a was deleted"), "{}", error.message);
        assert!(chain(&file, "nope").is_err());
    }

    #[test]
    fn cycles_are_refused() {
        let direct = file(vec![host("a", &["a"], None)]);
        assert!(chain(&direct, "a").unwrap_err().message.contains("through itself"));

        let nested = file(vec![host("a", &["b"], None), host("b", &["a"], None)]);
        assert!(chain(&nested, "a").unwrap_err().message.contains("through itself"));

        let later = file(vec![host("a", &[], None), host("b", &["a", "b"], None)]);
        assert!(chain(&later, "b").unwrap_err().message.contains("through itself"));
    }

    #[test]
    fn duplicates_are_refused() {
        let file = file(vec![host("a", &[], None), host("b", &["a"], None), host("c", &["b", "a"], None)]);
        assert!(chain(&file, "c").unwrap_err().message.contains("appears twice"));
    }

    #[test]
    fn depth_is_limited() {
        let mut hosts = vec![host("h0", &[], None)];
        for index in 1..=MAX_HOPS {
            let previous = format!("h{}", index - 1);
            hosts.push(host(&format!("h{index}"), &[previous.as_str()], None));
        }
        let file = file(hosts);
        assert_eq!(chain(&file, &format!("h{}", MAX_HOPS - 1)).unwrap().0.len(), MAX_HOPS);
        assert!(chain(&file, &format!("h{MAX_HOPS}")).is_err());
    }

    #[test]
    fn proxy_comes_from_the_host_or_its_first_jump() {
        let file = file(vec![host("a", &[], Some("p1")), host("b", &["a"], None), host("c", &["a"], Some("p2"))]);
        assert_eq!(chain(&file, "b").unwrap().1, Some("p1"));
        assert_eq!(chain(&file, "c").unwrap().1, Some("p2"));
    }

    #[test]
    fn vpn_comes_from_the_host_or_its_first_jump() {
        let mut a = host("a", &[], None);
        a.vpn_id = Some("office".to_string());
        let mut c = host("c", &["a"], None);
        c.vpn_id = Some("lab".to_string());
        let file = file(vec![a, host("b", &["a"], None), c, host("d", &["e"], None), host("e", &["d"], None)]);
        assert_eq!(route_vpn(&file, "b"), Some("office"));
        assert_eq!(route_vpn(&file, "c"), Some("lab"));
        assert_eq!(route_vpn(&file, "d"), None);
        assert_eq!(SecretOwner::Vpn("v1".to_string()).secret_id(PASSWORD_SLOT), "vpn:v1:password");
        assert!(!SecretOwner::Vpn("v1".to_string()).accepts(PRIVATE_KEY_SLOT));
    }

    #[test]
    fn owned_secret_ids() {
        let slot = proxy_password_slot(&Proxy {
            id: "p1".to_string(),
            label: "office".to_string(),
            kind: crate::ssh_store::ProxyKind::Socks5,
            host: "127.0.0.1".to_string(),
            port: 1080,
            user: "me".to_string(),
        });
        assert_eq!(slot.id, "proxy:p1:password");
        assert_eq!(SecretOwner::Identity("i1".to_string()).secret_id(PASSWORD_SLOT), "identity:i1:password");
        assert_eq!(SecretOwner::Key("k1".to_string()).secret_id(PRIVATE_KEY_SLOT), "key:k1:private");
        assert!(!SecretOwner::Key("k1".to_string()).accepts(PRIVATE_KEY_SLOT));
        assert!(SecretOwner::Key("k1".to_string()).accepts(PASSPHRASE_SLOT));
        assert!(!SecretOwner::Identity("i1".to_string()).accepts("private"));
    }
}
