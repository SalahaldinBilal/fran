use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::state::Category;
use crate::connections::{ConnectionProfile, ConnectionStore, PRESHARED_KEY_SLOT, PRIVATE_KEY_SLOT, TLS_KEY_SLOT};
use crate::error::{AppError, AppResult};
use crate::saved_queries::{SavedQuery, SavedQueryStore};
use crate::secrets::{NamedSecret, SecretsStore};
use crate::settings::SettingsStore;
use crate::snippets::{Snippet, SnippetStore};
use crate::ssh::HostKeyInfo;
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh_store::{ForwardRule, Identity, KeyMeta, Proxy, SshHost, SshStore};
use crate::vault::Vault;
use crate::vpn_store::{VpnProfile, VpnStore};

pub const CONNECTION: &str = "connection";
pub const SSH_HOST: &str = "sshHost";
pub const IDENTITY: &str = "identity";
pub const KEY: &str = "key";
pub const PROXY: &str = "proxy";
pub const FORWARD: &str = "forward";
pub const VPN: &str = "vpn";
pub const SAVED_QUERY: &str = "savedQuery";
pub const SNIPPET: &str = "snippet";
pub const KNOWN_HOST: &str = "knownHost";
pub const SETTING: &str = "setting";
pub const SECRET: &str = "secret";
pub const VAULT: &str = "vault";
/// The order of a list and its groups, `order:<list>`. One item per list, so a reorder doesn't touch every item.
pub const ORDER: &str = "order";

const ORDER_CONNECTIONS: &str = "connections";
const ORDER_SSH_HOSTS: &str = "sshHosts";
const ORDER_VPN: &str = "vpn";

/// Vault entries that belong to an item. Fran's own keys (logs, clouds, sync) have other prefixes and never leave.
const VAULT_OWNERS: [&str; 6] = [CONNECTION, IDENTITY, KEY, PROXY, VPN, SECRET];

/// Settings that describe this computer or this install, not the user's taste.
const LOCAL_SETTINGS: [&str; 5] = ["features", "homeLayout", "onboardingVersion", "recentConnections", "trayNoticeShown"];
const LOCAL_SETTING_PARTS: [(&str, &str); 2] = [("vpn", "program"), ("vpn", "systemWith")];

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub key: String,
    pub category: Category,
    /// `<item kind>:<group name>`, for kinds that have groups.
    pub group: Option<String>,
    /// The item a password or key belongs to.
    pub owner: Option<String>,
    /// The identity of the one cloud this item can live in, whatever the routes say.
    pub pinned: Option<String>,
    pub label: String,
    pub content: Value,
}

/// The item that holds a named secret's value.
pub fn secret_value_key(secret_id: &str) -> String {
    item_key(VAULT, &crate::secrets::vault_id(secret_id))
}

pub fn item_key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

pub fn split_key(key: &str) -> AppResult<(&str, &str)> {
    key.split_once(':').filter(|(_, id)| !id.is_empty()).ok_or_else(|| AppError::general("A synced item has a name this app can't read"))
}

/// Kind and group name into a group route's key.
pub fn group_key(kind: &str, group: &str) -> String {
    format!("{kind}:{group}")
}

pub fn category_of(key: &str) -> Option<Category> {
    let (kind, id) = key.split_once(':')?;
    Some(match kind {
        CONNECTION => Category::Connections,
        SSH_HOST => Category::SshHosts,
        IDENTITY | KEY => Category::Identities,
        PROXY => Category::Proxies,
        FORWARD => Category::Forwards,
        VPN => Category::VpnProfiles,
        SAVED_QUERY => Category::SavedQueries,
        SNIPPET => Category::Snippets,
        KNOWN_HOST => Category::KnownHosts,
        SETTING => Category::Settings,
        SECRET => Category::Secrets,
        VAULT => vault_category(id),
        // Built and applied by the engine from sync.json, see `shared_routes`.
        "routes" if id == "categories" => Category::Settings,
        ORDER => match id {
            ORDER_CONNECTIONS => Category::Connections,
            ORDER_SSH_HOSTS => Category::SshHosts,
            ORDER_VPN => Category::VpnProfiles,
            _ => return None,
        },
        _ => return None,
    })
}

pub fn is_order(key: &str) -> bool {
    key.split_once(':').is_some_and(|(kind, _)| kind == ORDER)
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct Order {
    ids: Vec<String>,
    groups: Vec<String>,
}

/// Puts the listed ids first, in that order. Ids the list doesn't name keep their place among themselves, after them.
fn sort_by_order<T>(list: &mut [T], ids: &[String], id: impl Fn(&T) -> &str) {
    list.sort_by_key(|item| ids.iter().position(|wanted| wanted == id(item)).unwrap_or(usize::MAX));
}

/// The incoming group order, then groups only this computer has.
fn merged_groups(incoming: Vec<String>, local: &[String]) -> Vec<String> {
    let extra: Vec<String> = local.iter().filter(|group| !incoming.contains(group)).cloned().collect();
    incoming.into_iter().chain(extra).collect()
}

fn vault_category(vault_id: &str) -> Category {
    match vault_id.rsplit_once(':').map(|(_, slot)| slot) {
        Some(PRIVATE_KEY_SLOT | TLS_KEY_SLOT | PRESHARED_KEY_SLOT) => Category::PrivateKeys,
        _ => Category::Passwords,
    }
}

fn syncable_vault_id(vault_id: &str) -> bool {
    let mut parts = vault_id.splitn(3, ':');
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(id), Some(slot)) if VAULT_OWNERS.contains(&owner) && !id.is_empty() && !slot.is_empty())
}

fn local_setting(name: &str) -> bool {
    LOCAL_SETTINGS.contains(&name)
}

fn without_local_parts(name: &str, mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        for (_, part) in LOCAL_SETTING_PARTS.iter().filter(|(setting, _)| *setting == name) {
            object.remove(*part);
        }
    }
    value
}

fn with_local_parts(name: &str, mut value: Value, current: Option<&Value>) -> Value {
    if let Some(object) = value.as_object_mut() {
        for (_, part) in LOCAL_SETTING_PARTS.iter().filter(|(setting, _)| *setting == name) {
            object.remove(*part);
            if let Some(kept) = current.and_then(|current| current.get(*part)) {
                object.insert(part.to_string(), kept.clone());
            }
        }
    }
    value
}

fn text(content: &Value, field: &str) -> String {
    content.get(field).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn collect_host_ids(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            for (name, field) in fields {
                match field.as_str() {
                    Some(id) if name == "hostId" && !id.is_empty() => found.push(item_key(SSH_HOST, id)),
                    _ => collect_host_ids(field, found),
                }
            }
        }
        Value::Array(values) => values.iter().for_each(|value| collect_host_ids(value, found)),
        _ => {}
    }
}

fn optional(content: &Value, field: &str, kind: &str, found: &mut Vec<String>) {
    if let Some(id) = content.get(field).and_then(Value::as_str).filter(|id| !id.is_empty()) {
        found.push(item_key(kind, id));
    }
}

/// The other items this one points at.
pub fn references(item: &Item) -> Vec<String> {
    let mut found = Vec::new();
    let content = &item.content;
    let Some((kind, _)) = item.key.split_once(':') else {
        return found;
    };
    match kind {
        CONNECTION => {
            optional(content, "vpnId", VPN, &mut found);
            collect_host_ids(content, &mut found);
        }
        SSH_HOST => {
            optional(content, "identityId", IDENTITY, &mut found);
            optional(content, "proxyId", PROXY, &mut found);
            optional(content, "vpnId", VPN, &mut found);
            optional(content, "startupSnippetId", SNIPPET, &mut found);
            let jumps = content.get("jumps").and_then(Value::as_array).into_iter().flatten();
            found.extend(jumps.filter_map(Value::as_str).map(|id| item_key(SSH_HOST, id)));
        }
        IDENTITY => {
            if let Some(auth) = content.get("auth") {
                optional(auth, "keyId", KEY, &mut found);
            }
        }
        FORWARD => optional(content, "hostId", SSH_HOST, &mut found),
        SAVED_QUERY => optional(content, "connectionId", CONNECTION, &mut found),
        _ => {}
    }
    if let Some(refs) = content.get("secretRefs").and_then(Value::as_object) {
        found.extend(refs.values().filter_map(Value::as_str).map(|id| item_key(SECRET, id)));
    }
    found.sort();
    found.dedup();
    found
}

pub struct Stores {
    pub connections: Arc<ConnectionStore>,
    pub ssh: Arc<SshStore>,
    pub vpn: Arc<VpnStore>,
    pub secrets: Arc<SecretsStore>,
    pub saved_queries: Arc<SavedQueryStore>,
    pub snippets: Arc<SnippetStore>,
    pub known_hosts: Arc<KnownHosts>,
    pub settings: Arc<SettingsStore>,
    pub vault: Arc<Vault>,
}

fn known_host_id(host: &HostKeyInfo) -> String {
    format!("{}:{}", host.host.to_ascii_lowercase(), host.port)
}

struct Collector {
    items: BTreeMap<String, Item>,
}

impl Collector {
    fn add<T: Serialize>(&mut self, kind: &str, id: &str, group: Option<&str>, label: &str, value: &T) -> AppResult<()> {
        if id.is_empty() {
            return Ok(());
        }
        let key = item_key(kind, id);
        let category = category_of(&key).ok_or_else(|| AppError::general("Unknown kind of synced item"))?;
        let group = group.filter(|group| !group.is_empty()).map(|group| group_key(kind, group));
        let item = Item { key: key.clone(), category, group, owner: None, pinned: None, label: label.to_string(), content: serde_json::to_value(value)? };
        self.items.insert(key, item);
        Ok(())
    }
}

fn replace_or_push<T>(list: &mut Vec<T>, item: T, same: impl Fn(&T) -> bool) {
    match list.iter_mut().find(|existing| same(existing)) {
        Some(existing) => *existing = item,
        None => list.push(item),
    }
}

fn parsed<T: DeserializeOwned>(content: &Value) -> AppResult<T> {
    serde_json::from_value(content.clone()).map_err(|error| AppError::general(format!("A synced item couldn't be read: {error}")))
}

impl Stores {
    /// Everything that can sync, by key. Fails while the vault is locked, since passwords are part of it.
    pub fn collect(&self) -> AppResult<BTreeMap<String, Item>> {
        let mut found = Collector { items: BTreeMap::new() };

        let connections = self.connections.read(Clone::clone)?;
        let order = Order { ids: connections.connections.iter().map(|profile| profile.id.clone()).collect(), groups: connections.group_order.clone() };
        found.add(ORDER, ORDER_CONNECTIONS, None, "Order of connections", &order)?;
        for profile in connections.connections {
            found.add(CONNECTION, &profile.id, profile.group.as_deref(), &profile.name, &profile)?;
        }

        let ssh = self.ssh.snapshot()?;
        let order = Order { ids: ssh.hosts.iter().map(|host| host.id.clone()).collect(), groups: ssh.group_order.clone() };
        found.add(ORDER, ORDER_SSH_HOSTS, None, "Order of SSH hosts", &order)?;
        for host in &ssh.hosts {
            found.add(SSH_HOST, &host.id, host.group.as_deref(), &host.label, host)?;
        }
        for identity in &ssh.identities {
            found.add(IDENTITY, &identity.id, None, &identity.label, identity)?;
        }
        for key in &ssh.keys {
            found.add(KEY, &key.id, None, &key.label, key)?;
        }
        for proxy in &ssh.proxies {
            found.add(PROXY, &proxy.id, None, &proxy.label, proxy)?;
        }
        for forward in &ssh.forwards {
            found.add(FORWARD, &forward.id, None, &forward.label, forward)?;
        }

        let vpn = self.vpn.read(Clone::clone)?;
        let order = Order { ids: vpn.profiles.iter().map(|profile| profile.id.clone()).collect(), groups: vpn.group_order.clone() };
        found.add(ORDER, ORDER_VPN, None, "Order of VPN profiles", &order)?;
        for profile in vpn.profiles {
            found.add(VPN, &profile.id, profile.group.as_deref(), &profile.label, &profile)?;
        }
        for query in self.saved_queries.read(|file| file.queries.clone())? {
            found.add(SAVED_QUERY, &query.id, None, &query.name, &query)?;
        }
        for snippet in self.snippets.read(|file| file.snippets.clone())? {
            found.add(SNIPPET, &snippet.id, None, &snippet.label, &snippet)?;
        }
        for host in self.known_hosts.read(|file| file.hosts.clone())? {
            let id = known_host_id(&host);
            found.add(KNOWN_HOST, &id, None, &id, &host)?;
        }
        let mut linked = BTreeMap::new();
        for secret in self.secrets.read(|file| file.secrets.clone())? {
            found.add(SECRET, &secret.id, None, &secret.name, &secret)?;
            if let Some(link) = secret.link {
                linked.insert(secret_value_key(&secret.id), link.cloud);
            }
        }

        if let Some(Value::Object(settings)) = self.settings.read(|file| file.settings.clone())? {
            for (name, value) in settings.into_iter().filter(|(name, _)| !local_setting(name)) {
                found.add(SETTING, &name, None, &name, &without_local_parts(&name, value))?;
            }
        }

        for owner in VAULT_OWNERS {
            for vault_id in self.vault.ids_with_prefix(&format!("{owner}:"))? {
                if !syncable_vault_id(&vault_id) {
                    continue;
                }
                let Some(value) = self.vault.get(&vault_id)? else {
                    continue;
                };
                let key = item_key(VAULT, &vault_id);
                let owner_key = vault_id.rsplit_once(':').map(|(owner, _)| owner.to_string());
                let label = owner_key.as_ref().and_then(|owner| found.items.get(owner)).map(|owner| owner.label.clone()).unwrap_or_default();
                let item = Item {
                    pinned: linked.get(&key).cloned(),
                    key: key.clone(),
                    category: vault_category(&vault_id),
                    group: None,
                    owner: owner_key,
                    label,
                    content: json!({ "value": value.as_str() }),
                };
                found.items.insert(key, item);
            }
        }

        Ok(found.items)
    }

    /// Writes an item that came from a cloud. It goes through the same stores as a save, without the editor's checks.
    pub fn write(&self, key: &str, content: &Value) -> AppResult<()> {
        let (kind, id) = split_key(key)?;
        match kind {
            CONNECTION => {
                let mut profile: ConnectionProfile = parsed(content)?;
                profile.id = id.to_string();
                self.connections.update(|file| {
                    replace_or_push(&mut file.connections, profile, |existing| existing.id == id);
                    Ok(())
                })
            }
            SSH_HOST => {
                let mut host: SshHost = parsed(content)?;
                host.id = id.to_string();
                self.ssh.update(|file| {
                    replace_or_push(&mut file.hosts, host, |existing| existing.id == id);
                    Ok(())
                })
            }
            IDENTITY => {
                let mut identity: Identity = parsed(content)?;
                identity.id = id.to_string();
                self.ssh.update(|file| {
                    replace_or_push(&mut file.identities, identity, |existing| existing.id == id);
                    Ok(())
                })
            }
            KEY => {
                let mut meta: KeyMeta = parsed(content)?;
                meta.id = id.to_string();
                self.ssh.update(|file| {
                    replace_or_push(&mut file.keys, meta, |existing| existing.id == id);
                    Ok(())
                })
            }
            PROXY => {
                let mut proxy: Proxy = parsed(content)?;
                proxy.id = id.to_string();
                self.ssh.update(|file| {
                    replace_or_push(&mut file.proxies, proxy, |existing| existing.id == id);
                    Ok(())
                })
            }
            FORWARD => {
                let mut forward: ForwardRule = parsed(content)?;
                forward.id = id.to_string();
                self.ssh.update(|file| {
                    replace_or_push(&mut file.forwards, forward, |existing| existing.id == id);
                    Ok(())
                })
            }
            VPN => {
                let mut profile: VpnProfile = parsed(content)?;
                profile.id = id.to_string();
                self.vpn.update(|file| {
                    replace_or_push(&mut file.profiles, profile, |existing| existing.id == id);
                    Ok(())
                })
            }
            SAVED_QUERY => {
                let mut query: SavedQuery = parsed(content)?;
                query.id = id.to_string();
                self.saved_queries.update(|file| {
                    replace_or_push(&mut file.queries, query, |existing| existing.id == id);
                    Ok(())
                })
            }
            SNIPPET => {
                let mut snippet: Snippet = parsed(content)?;
                snippet.id = id.to_string();
                self.snippets.update(|file| {
                    replace_or_push(&mut file.snippets, snippet, |existing| existing.id == id);
                    Ok(())
                })
            }
            KNOWN_HOST => {
                let host: HostKeyInfo = parsed(content)?;
                if known_host_id(&host) != id {
                    return Err(AppError::general("A synced host key doesn't match its name"));
                }
                self.known_hosts.update(|file| {
                    replace_or_push(&mut file.hosts, host, |existing| known_host_id(existing) == id);
                    Ok(())
                })
            }
            SECRET => {
                let mut secret: NamedSecret = parsed(content)?;
                secret.id = id.to_string();
                self.secrets.update(|file| {
                    replace_or_push(&mut file.secrets, secret, |existing| existing.id == id);
                    Ok(())
                })
            }
            SETTING => {
                if local_setting(id) {
                    return Ok(());
                }
                self.settings.update(|file| {
                    let settings = file.settings.get_or_insert_with(|| json!({}));
                    let Some(object) = settings.as_object_mut() else {
                        return Err(AppError::general("settings.json isn't in a shape sync can write to"));
                    };
                    let merged = with_local_parts(id, content.clone(), object.get(id));
                    object.insert(id.to_string(), merged);
                    Ok(())
                })
            }
            VAULT => {
                if !syncable_vault_id(id) {
                    return Err(AppError::general("A synced password has a name this app won't store"));
                }
                let value = content.get("value").and_then(Value::as_str).ok_or_else(|| AppError::general("A synced password has no value"))?;
                self.vault.set(id, value)
            }
            ORDER => {
                let order: Order = parsed(content)?;
                match id {
                    ORDER_CONNECTIONS => self.connections.update(|file| {
                        sort_by_order(&mut file.connections, &order.ids, |profile| profile.id.as_str());
                        file.group_order = merged_groups(order.groups, &file.group_order);
                        Ok(())
                    }),
                    ORDER_SSH_HOSTS => self.ssh.update(|file| {
                        sort_by_order(&mut file.hosts, &order.ids, |host| host.id.as_str());
                        file.group_order = merged_groups(order.groups, &file.group_order);
                        Ok(())
                    }),
                    ORDER_VPN => self.vpn.update(|file| {
                        sort_by_order(&mut file.profiles, &order.ids, |profile| profile.id.as_str());
                        file.group_order = merged_groups(order.groups, &file.group_order);
                        Ok(())
                    }),
                    _ => Err(AppError::general(format!("This version of Fran doesn't know the synced order {id}"))),
                }
            }
            _ => Err(AppError::general(format!("This version of Fran doesn't know synced items of kind {kind}"))),
        }
    }

    /// Removes an item another computer deleted, with the passwords and keys kept under it.
    pub fn remove(&self, key: &str) -> AppResult<()> {
        let (kind, id) = split_key(key)?;
        match kind {
            CONNECTION => self.connections.update(|file| {
                file.connections.retain(|profile| profile.id != id);
                Ok(())
            })?,
            SSH_HOST => self.ssh.update(|file| {
                file.hosts.retain(|host| host.id != id);
                Ok(())
            })?,
            IDENTITY => self.ssh.update(|file| {
                file.identities.retain(|identity| identity.id != id);
                Ok(())
            })?,
            KEY => self.ssh.update(|file| {
                file.keys.retain(|meta| meta.id != id);
                Ok(())
            })?,
            PROXY => self.ssh.update(|file| {
                file.proxies.retain(|proxy| proxy.id != id);
                Ok(())
            })?,
            FORWARD => self.ssh.update(|file| {
                file.forwards.retain(|forward| forward.id != id);
                Ok(())
            })?,
            VPN => self.vpn.update(|file| {
                file.profiles.retain(|profile| profile.id != id);
                Ok(())
            })?,
            SAVED_QUERY => self.saved_queries.update(|file| {
                file.queries.retain(|query| query.id != id);
                Ok(())
            })?,
            SNIPPET => self.snippets.update(|file| {
                file.snippets.retain(|snippet| snippet.id != id);
                Ok(())
            })?,
            KNOWN_HOST => self.known_hosts.update(|file| {
                file.hosts.retain(|host| known_host_id(host) != id);
                Ok(())
            })?,
            SECRET => self.secrets.update(|file| {
                file.secrets.retain(|secret| secret.id != id);
                Ok(())
            })?,
            SETTING => self.settings.update(|file| {
                if let Some(object) = file.settings.as_mut().and_then(Value::as_object_mut) {
                    object.remove(id);
                }
                Ok(())
            })?,
            VAULT => {
                if syncable_vault_id(id) {
                    self.vault.remove(id)?;
                }
                return Ok(());
            }
            // An order has nothing to delete. The list stays as it is.
            _ => return Ok(()),
        }
        if VAULT_OWNERS.contains(&kind) {
            self.vault.remove_prefix(&format!("{kind}:{id}:"))?;
        }
        Ok(())
    }
}

pub fn label_of(key: &str, content: &Value) -> String {
    let named = ["name", "label", "host"].iter().map(|field| text(content, field)).find(|value| !value.is_empty());
    named.unwrap_or_else(|| key.split_once(':').map(|(_, id)| id.to_string()).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_passwords_land_in_their_own_categories() {
        assert_eq!(category_of("vault:connection:c1:password"), Some(Category::Passwords));
        assert_eq!(category_of("vault:secret:s1:value"), Some(Category::Passwords));
        assert_eq!(category_of("vault:key:k1:passphrase"), Some(Category::Passwords));
        assert_eq!(category_of("vault:key:k1:private"), Some(Category::PrivateKeys));
        assert_eq!(category_of("vault:vpn:v1:tlsKey"), Some(Category::PrivateKeys));
        assert_eq!(category_of("vault:vpn:v1:presharedKey"), Some(Category::PrivateKeys));
        assert_eq!(category_of("plugin:x"), None);
    }

    #[test]
    fn frans_own_vault_keys_are_never_items() {
        for id in ["agent:historyKey", "terminal:logKey", "cloud:c1:dataKey", "cloud:c1:session", "sync:local:hashKey", "sync:replaced:r1"] {
            assert!(!syncable_vault_id(id), "{id}");
        }
        assert!(syncable_vault_id("connection:c1:password"));
    }

    #[test]
    fn a_synced_vpn_setting_keeps_this_computers_program_path() {
        let sent = without_local_parts("vpn", json!({ "program": "C:/OpenVPN/openvpn.exe", "systemWith": "openvpn", "idleCloseSecs": 120 }));
        assert_eq!(sent, json!({ "idleCloseSecs": 120 }));

        let here = json!({ "program": "/usr/sbin/openvpn", "systemWith": "fran", "idleCloseSecs": 30 });
        let applied = with_local_parts("vpn", json!({ "idleCloseSecs": 120, "program": "C:/evil.exe" }), Some(&here));
        assert_eq!(applied, json!({ "program": "/usr/sbin/openvpn", "systemWith": "fran", "idleCloseSecs": 120 }));
    }

    #[test]
    fn references_cover_hosts_identities_keys_vpns_and_secrets() {
        let connection = Item {
            key: "connection:c1".into(),
            category: Category::Connections,
            group: None,
            owner: None,
            pinned: None,
            label: "prod".into(),
            content: json!({
                "vpnId": "v1",
                "kind": "postgres",
                "options": { "transport": { "kind": "ssh", "ssh": { "hostId": "h1" } } },
                "secretRefs": { "options.host": "s1", "slot:password": "s2" },
            }),
        };
        assert_eq!(references(&connection), ["secret:s1", "secret:s2", "sshHost:h1", "vpn:v1"]);

        let host = Item {
            key: "sshHost:h1".into(),
            category: Category::SshHosts,
            group: None,
            owner: None,
            pinned: None,
            label: "bastion".into(),
            content: json!({ "identityId": "i1", "jumps": ["h0"], "proxyId": null, "vpnId": "" }),
        };
        assert_eq!(references(&host), ["identity:i1", "sshHost:h0"]);

        let identity = Item {
            key: "identity:i1".into(),
            category: Category::Identities,
            group: None,
            owner: None,
            pinned: None,
            label: "deploy".into(),
            content: json!({ "auth": { "kind": "key", "keyId": "k1" } }),
        };
        assert_eq!(references(&identity), ["key:k1"]);
    }
}
