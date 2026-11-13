//! After the first pull from a cloud: items made here and in the cloud separately that are plainly the same thing.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::items::{CONNECTION, FORWARD, IDENTITY, Item, KEY, PROXY, SAVED_QUERY, SECRET, SNIPPET, SSH_HOST, Stores, VPN, references, split_key};
use super::state::{Cloud, SyncFile};
use crate::error::AppResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Duplicate {
    pub id: String,
    pub cloud: String,
    /// Only on this computer. Merging drops it for the other one.
    pub local: String,
    pub remote: String,
    pub label: String,
}

fn field(content: &Value, path: &str) -> String {
    let found = path.split('.').try_fold(content, |value, segment| match value {
        Value::Object(map) => map.get(segment),
        Value::Array(items) => segment.parse::<usize>().ok().and_then(|index| items.get(index)),
        _ => None,
    });
    match found {
        Some(Value::String(text)) => text.trim().to_lowercase(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// Name and target. Two items with the same one are taken as the same thing.
fn match_key(item: &Item) -> Option<String> {
    let (kind, _) = item.key.split_once(':')?;
    let content = &item.content;
    let target: &[&str] = match kind {
        CONNECTION => &["kind", "options.host", "options.port", "options.database", "options.path", "options.socketPath", "options.accountId"],
        SSH_HOST => &["host", "port"],
        IDENTITY => &["user", "auth.kind"],
        // A key file lives at its own path on each computer, so only a matching one counts.
        KEY => return Some(format!("{kind}|{}|{}", field(content, "fingerprint"), content.get("storage").map(Value::to_string).unwrap_or_default())),
        PROXY => &["kind", "host", "port"],
        VPN => &["kind", "remotes.0.host", "remotes.0.port"],
        FORWARD => &["kind", "listenPort", "targetHost", "targetPort"],
        SNIPPET => &["command"],
        SAVED_QUERY => &["sql"],
        SECRET => &[],
        _ => return None,
    };
    let target: Vec<String> = target.iter().map(|path| field(content, path)).collect();
    Some(format!("{kind}|{}|{}", item.label.trim().to_lowercase(), target.join("|")))
}

/// Items no cloud has seen, paired with the first item of this cloud they match.
pub fn find(file: &SyncFile, cloud: &Cloud, items: &BTreeMap<String, Item>) -> Vec<Duplicate> {
    let already = &file.duplicates;
    let in_cloud = |key: &str| cloud.records.get(key).is_some_and(|record| !record.deleted && !record.hash.is_empty());
    let unsynced = |key: &str| file.clouds.iter().all(|cloud| !cloud.records.contains_key(key));
    let mut remote: BTreeMap<String, Vec<&Item>> = BTreeMap::new();
    for item in items.values().filter(|item| in_cloud(&item.key)) {
        if let Some(key) = match_key(item) {
            remote.entry(key).or_default().push(item);
        }
    }
    let mut taken: BTreeSet<String> = already.iter().map(|duplicate| duplicate.remote.clone()).collect();
    let listed: BTreeSet<&str> = already.iter().map(|duplicate| duplicate.local.as_str()).collect();
    let mut found = Vec::new();
    for item in items.values().filter(|item| unsynced(&item.key) && !listed.contains(item.key.as_str())) {
        let Some(matches) = match_key(item).and_then(|key| remote.get(&key)) else {
            continue;
        };
        let Some(other) = matches.iter().find(|other| !taken.contains(&other.key)) else {
            continue;
        };
        taken.insert(other.key.clone());
        found.push(Duplicate {
            id: uuid::Uuid::new_v4().to_string(),
            cloud: cloud.id.clone(),
            local: item.key.clone(),
            remote: other.key.clone(),
            label: item.label.clone(),
        });
    }
    found
}

fn with_id_replaced(value: &Value, old: &str, new: &str) -> Value {
    match value {
        Value::String(text) if text == old => Value::String(new.to_string()),
        Value::Array(items) => Value::Array(items.iter().map(|item| with_id_replaced(item, old, new)).collect()),
        Value::Object(fields) => Value::Object(fields.iter().map(|(name, field)| (name.clone(), with_id_replaced(field, old, new))).collect()),
        other => other.clone(),
    }
}

/// Keeps the cloud's copy, with the local one's passwords where it has none and every pointer moved to it. Returns the kinds changed.
pub fn merge(stores: &Stores, local: &str, remote: &str) -> AppResult<BTreeSet<String>> {
    let (kind, old) = split_key(local)?;
    let (_, new) = split_key(remote)?;
    let mut kinds = BTreeSet::from([kind.to_string()]);

    let prefix = format!("{kind}:{old}:");
    for vault_id in stores.vault.ids_with_prefix(&prefix)? {
        let target = format!("{kind}:{new}:{}", &vault_id[prefix.len()..]);
        if stores.vault.get(&target)?.is_none()
            && let Some(value) = stores.vault.get(&vault_id)?
        {
            stores.vault.set(&target, &value)?;
        }
    }

    for item in stores.collect()?.values().filter(|item| item.key != local && references(item).iter().any(|target| target == local)) {
        stores.write(&item.key, &with_id_replaced(&item.content, old, new))?;
        if let Some((kind, _)) = item.key.split_once(':') {
            kinds.insert(kind.to_string());
        }
    }
    stores.remove(local)?;
    Ok(kinds)
}
