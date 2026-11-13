use std::{
    collections::HashMap,
    sync::Mutex,
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{SLOT_PREFIX, SecretRefs, SecretsFile, VALUE_SLOT, owner, vault_id};
use crate::connections::{SecretRef, SecretSlot, secret_id};
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::ssh_store::SshFile;
use crate::vault::Vault;
use crate::vpn_store::VpnFile;

// Shorter values would be replaced all over an error message.
const SCRUB_MIN_LEN: usize = 3;

/// Never a secret's target, whatever the item: ids, names and pointers to other items.
const EXCLUDED_LEAVES: &[&str] = &[
    "id",
    "name",
    "label",
    "group",
    "color",
    "kind",
    "vpnId",
    "identityId",
    "proxyId",
    "hostId",
    "keyId",
    "startupSnippetId",
];

/// Which of an item's fields and password slots a secret may fill.
pub struct RefRules {
    pub field: fn(&str) -> bool,
    pub slot: fn(&str) -> bool,
}

fn leaf<'v>(value: &'v Value, path: &str) -> Option<&'v Value> {
    path.split('.').try_fold(value, |value, segment| match value {
        Value::Object(map) => map.get(segment),
        Value::Array(items) => segment.parse::<usize>().ok().and_then(|index| items.get(index)),
        _ => None,
    })
}

fn leaf_mut<'v>(value: &'v mut Value, path: &str) -> Option<&'v mut Value> {
    path.split('.').try_fold(value, |value, segment| match value {
        Value::Object(map) => map.get_mut(segment),
        Value::Array(items) => segment.parse::<usize>().ok().and_then(|index| items.get_mut(index)),
        _ => None,
    })
}

fn field_paths(refs: &SecretRefs) -> impl Iterator<Item = (&String, &String)> {
    refs.iter().filter(|(key, _)| !key.starts_with(SLOT_PREFIX))
}

/// Run on save. A path has to name a text or number field the item's rules allow, and the secret has to exist.
pub fn check_refs<T: Serialize>(item: &T, refs: &SecretRefs, rules: &RefRules, secrets: &SecretsFile) -> AppResult<()> {
    if refs.is_empty() {
        return Ok(());
    }
    let json = serde_json::to_value(item)?;
    for (key, secret) in refs {
        if secrets.secret(secret).is_none() {
            return Err(AppError::not_found("That secret was deleted. Pick another one."));
        }
        if let Some(slot) = key.strip_prefix(SLOT_PREFIX) {
            if !(rules.slot)(slot) {
                return Err(AppError::general(format!("A secret can't be used for {slot} here")));
            }
            continue;
        }
        let last = key.rsplit('.').next().unwrap_or_default();
        let fits = matches!(leaf(&json, key), Some(Value::String(_) | Value::Number(_)));
        if !fits || EXCLUDED_LEAVES.contains(&last) || !(rules.field)(key) {
            return Err(AppError::general(format!("A secret can't be used for {key}")));
        }
    }
    Ok(())
}

fn replace_text<T: Serialize + DeserializeOwned>(item: &T, refs: &SecretRefs, text: &str) -> AppResult<T> {
    let mut json = serde_json::to_value(item)?;
    for (path, _) in field_paths(refs) {
        if let Some(value @ Value::String(_)) = leaf_mut(&mut json, path) {
            *value = Value::String(text.to_string());
        }
    }
    Ok(serde_json::from_value(json)?)
}

/// What gets saved: text fields a secret fills are kept empty, so no old value stays in the file.
pub fn blanked<T: Serialize + DeserializeOwned + Clone>(item: &T, refs: &SecretRefs) -> AppResult<T> {
    if refs.is_empty() {
        return Ok(item.clone());
    }
    replace_text(item, refs, "")
}

/// For save checks that need every field to hold something.
pub fn with_placeholders<T: Serialize + DeserializeOwned>(item: &T, refs: &SecretRefs) -> AppResult<T> {
    replace_text(item, refs, "secret")
}

/// Vault id a password slot normally reads, to the secret it uses instead.
pub type SlotSources = HashMap<String, String>;

fn add_sources(sources: &mut SlotSources, owner: crate::connections::SecretOwner, refs: &SecretRefs) {
    for (key, secret) in refs {
        if let Some(slot) = key.strip_prefix(SLOT_PREFIX) {
            sources.insert(owner.secret_id(slot), secret.clone());
        }
    }
}

pub fn slot_sources(connection: Option<(&str, &SecretRefs)>, ssh: &SshFile, vpn: &VpnFile) -> SlotSources {
    use crate::connections::SecretOwner;

    let mut sources = SlotSources::new();
    if let Some((id, refs)) = connection {
        add_sources(&mut sources, SecretOwner::Connection(id.to_string()), refs);
    }
    for identity in &ssh.identities {
        add_sources(&mut sources, SecretOwner::Identity(identity.id.clone()), &identity.secret_refs);
    }
    for proxy in &ssh.proxies {
        add_sources(&mut sources, SecretOwner::Proxy(proxy.id.clone()), &proxy.secret_refs);
    }
    for profile in &vpn.profiles {
        add_sources(&mut sources, SecretOwner::Vpn(profile.id.clone()), &profile.secret_refs);
    }
    sources
}

/// Fills fields from secrets for one connect. The filled items stay in Rust.
pub struct Filler<'a> {
    stored: Box<dyn Fn(&str) -> Option<Zeroizing<String>> + Send + Sync + 'a>,
    names: HashMap<String, String>,
    typed: HashMap<String, Zeroizing<String>>,
    used: Mutex<Vec<(Zeroizing<String>, String)>>,
}

impl<'a> Filler<'a> {
    /// `provided` is what the user typed into a prompt, keyed by slot id.
    /// A vault that can't be opened counts as nothing stored, like for passwords.
    pub fn new(vault: &'a Vault, provided: &HashMap<String, String>) -> AppResult<Self> {
        Ok(Self::with_lookup(&super::snapshot()?, provided, move |id| vault.get(id).ok().flatten()))
    }

    /// `stored` reads a vault id.
    pub fn with_lookup(
        secrets: &SecretsFile,
        provided: &HashMap<String, String>,
        stored: impl Fn(&str) -> Option<Zeroizing<String>> + Send + Sync + 'a,
    ) -> Self {
        Self {
            stored: Box::new(stored),
            names: secrets.secrets.iter().map(|secret| (secret.id.clone(), secret.name.clone())).collect(),
            typed: provided
                .iter()
                .filter(|(slot, _)| slot.starts_with("secret:"))
                .map(|(slot, value)| (slot.clone(), Zeroizing::new(value.clone())))
                .collect(),
            used: Mutex::new(Vec::new()),
        }
    }

    fn slot(&self, id: &str, name: &str) -> SecretSlot {
        SecretSlot::owned(owner(id), VALUE_SLOT, format!("Secret {name}"))
    }

    /// Typed-in values win over stored ones, like passwords.
    fn value(&self, id: &str, name: &str) -> Result<Zeroizing<String>, SecretSlot> {
        let vault_id = vault_id(id);
        self.typed
            .get(&vault_id)
            .cloned()
            .or_else(|| (self.stored)(&vault_id))
            .ok_or_else(|| self.slot(id, name))
    }

    /// A copy of `item` with every field in `refs` taken from its secret. Secrets without a value come back
    /// as `secretsRequired`, all of them at once.
    pub fn fill<T: Serialize + DeserializeOwned + Clone>(&self, item: &T, refs: &SecretRefs, what: &str) -> AppResult<T> {
        if field_paths(refs).next().is_none() {
            return Ok(item.clone());
        }
        let mut json = serde_json::to_value(item)?;
        let mut missing = Vec::new();
        for (path, secret) in field_paths(refs) {
            let name = self.names.get(secret).ok_or_else(|| super::deleted(what))?;
            let Some(target) = leaf_mut(&mut json, path) else {
                continue;
            };
            let value = match self.value(secret, name) {
                Ok(value) => value,
                Err(slot) => {
                    missing.push(slot);
                    continue;
                }
            };
            if value.chars().any(char::is_control) {
                return Err(AppError::general(format!("The secret {name} has a line break or control character, which a field can't take")));
            }
            *target = match &*target {
                Value::Number(_) => {
                    let number: u64 = value
                        .trim()
                        .parse()
                        .map_err(|_| AppError::general(format!("The secret {name} isn't a number, which {path} of {what} needs")))?;
                    Value::Number(number.into())
                }
                _ => Value::String(value.to_string()),
            };
            if let Ok(mut used) = self.used.lock() {
                used.push((value, name.clone()));
            }
        }
        if !missing.is_empty() {
            let mut seen = std::collections::HashSet::new();
            missing.retain(|slot| seen.insert(slot.id.clone()));
            return Err(AppError::secrets_required(missing));
        }
        serde_json::from_value(json).map_err(|error| AppError::general(format!("A secret doesn't fit a field of {what}: {error}")))
    }

    /// Points each slot that uses a secret at that secret, so the value is read from it and a typed one is saved to it.
    pub fn redirect(&self, slots: &mut [SecretSlot], connection_id: Option<&str>, sources: &SlotSources) -> AppResult<()> {
        for slot in slots.iter_mut().filter(|slot| !slot.one_time) {
            let stored = match &slot.store {
                Some(target) => target.owner.secret_id(&target.slot),
                None => secret_id(connection_id.unwrap_or_default(), &slot.id),
            };
            let Some(secret) = sources.get(&stored) else {
                continue;
            };
            let name = self.names.get(secret).ok_or_else(|| super::deleted(&slot.label))?;
            slot.label = format!("{} (secret {name})", slot.label);
            slot.store = Some(SecretRef { owner: owner(secret), slot: VALUE_SLOT.to_string() });
        }
        Ok(())
    }

    /// Takes the values this connect filled in out of an error before it goes to the window.
    pub fn scrub(&self, mut error: AppError) -> AppError {
        if matches!(error.detail, ErrorDetail::SecretsRequired { .. }) {
            return error;
        }
        if let Ok(used) = self.used.lock() {
            for (value, name) in used.iter().filter(|(value, _)| value.len() >= SCRUB_MIN_LEN) {
                error.message = error.message.replace(value.as_str(), &format!("[secret {name}]"));
            }
        }
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::NamedSecret;
    use crate::ssh_store::{Proxy, ProxyKind, SshHost};

    fn secrets() -> SecretsFile {
        SecretsFile {
            secrets: vec![
                NamedSecret { id: "s1".to_string(), name: "PROD_HOST".to_string(), note: String::new() },
                NamedSecret { id: "s2".to_string(), name: "PROD_PORT".to_string(), note: String::new() },
            ],
            ..Default::default()
        }
    }

    // Nothing is stored, so values only come from what was typed and the OS keychain is never touched.
    fn filler<'a>(secrets: &SecretsFile, provided: &HashMap<String, String>) -> Filler<'a> {
        Filler::with_lookup(secrets, provided, |_| None)
    }

    fn typed(values: &[(&str, &str)]) -> HashMap<String, String> {
        values.iter().map(|(id, value)| (vault_id(id), value.to_string())).collect()
    }

    fn refs(pairs: &[(&str, &str)]) -> SecretRefs {
        pairs.iter().map(|(path, secret)| (path.to_string(), secret.to_string())).collect()
    }

    fn proxy() -> Proxy {
        Proxy {
            id: "p1".to_string(),
            label: "office".to_string(),
            kind: ProxyKind::Socks5,
            host: String::new(),
            port: 1080,
            user: "me".to_string(),
            secret_refs: refs(&[("host", "s1"), ("port", "s2")]),
        }
    }

    const ANY: RefRules = RefRules { field: |_| true, slot: |slot| slot == "password" };

    #[test]
    fn text_and_number_fields_are_filled() {
        let provided = typed(&[("s1", "db.internal.example"), ("s2", "9050")]);
        let filler = filler(&secrets(), &provided);
        let proxy = proxy();
        let filled = filler.fill(&proxy, &proxy.secret_refs, "the proxy office").unwrap();
        assert_eq!((filled.host.as_str(), filled.port, filled.user.as_str()), ("db.internal.example", 9050, "me"));
    }

    #[test]
    fn a_port_that_is_not_a_number_names_the_secret() {
        let provided = typed(&[("s1", "db.internal.example"), ("s2", "five thousand")]);
        let filler = filler(&secrets(), &provided);
        let proxy = proxy();
        let error = filler.fill(&proxy, &proxy.secret_refs, "the proxy office").unwrap_err();
        assert!(error.message.contains("PROD_PORT") && error.message.contains("port"), "{}", error.message);
        assert!(!error.message.contains("five thousand"), "{}", error.message);
    }

    #[test]
    fn secrets_without_a_value_are_asked_for_together() {
        let filler = filler(&secrets(), &HashMap::new());
        let proxy = proxy();
        let error = filler.fill(&proxy, &proxy.secret_refs, "the proxy office").unwrap_err();
        let ErrorDetail::SecretsRequired { slots } = error.detail else {
            panic!("{}", error.message);
        };
        let ids: Vec<&str> = slots.iter().map(|slot| slot.id.as_str()).collect();
        assert_eq!(ids, ["secret:s1:value", "secret:s2:value"]);
        assert_eq!(slots[0].label, "Secret PROD_HOST");
    }

    #[test]
    fn a_deleted_secret_is_an_error_not_a_prompt() {
        let filler = filler(&SecretsFile::default(), &HashMap::new());
        let proxy = proxy();
        let error = filler.fill(&proxy, &proxy.secret_refs, "the proxy office").unwrap_err();
        assert!(matches!(error.detail, ErrorDetail::NotFound), "{}", error.message);
    }

    #[test]
    fn a_value_with_a_line_break_is_refused() {
        let provided = typed(&[("s1", "vpn.example\nscript-security 2"), ("s2", "1194")]);
        let filler = filler(&secrets(), &provided);
        let proxy = proxy();
        assert!(filler.fill(&proxy, &proxy.secret_refs, "the proxy office").is_err());
    }

    #[test]
    fn filled_values_are_taken_out_of_errors() {
        let provided = typed(&[("s1", "db.internal.example"), ("s2", "9050")]);
        let filler = filler(&secrets(), &provided);
        let proxy = proxy();
        filler.fill(&proxy, &proxy.secret_refs, "the proxy office").unwrap();
        let error = filler.scrub(AppError::general("Couldn't reach db.internal.example:9050"));
        assert_eq!(error.message, "Couldn't reach [secret PROD_HOST]:[secret PROD_PORT]");
    }

    #[test]
    fn save_refuses_ids_missing_fields_and_other_slots() {
        let host = SshHost { id: "h1".to_string(), label: "api".to_string(), ..Default::default() };
        let secrets = secrets();
        assert!(check_refs(&host, &refs(&[("host", "s1"), ("port", "s2")]), &ANY, &secrets).is_ok());
        assert!(check_refs(&host, &refs(&[("slot:password", "s1")]), &ANY, &secrets).is_ok());
        for bad in ["id", "label", "identityId", "nope", "jumps", "agentForwarding", "slot:private"] {
            assert!(check_refs(&host, &refs(&[(bad, "s1")]), &ANY, &secrets).is_err(), "{bad}");
        }
        assert!(check_refs(&host, &refs(&[("host", "gone")]), &ANY, &secrets).is_err());
    }

    #[test]
    fn saved_items_keep_no_old_text_in_secret_fields() {
        let mut proxy = proxy();
        proxy.host = "old.example".to_string();
        let saved = blanked(&proxy, &proxy.secret_refs).unwrap();
        assert_eq!((saved.host.as_str(), saved.port), ("", 1080));
    }

    #[test]
    fn a_slot_that_uses_a_secret_reads_and_saves_there() {
        let filler = filler(&secrets(), &HashMap::new());
        let mut ssh = SshFile::default();
        let mut proxy = proxy();
        proxy.secret_refs = refs(&[("slot:password", "s1")]);
        ssh.proxies.push(proxy.clone());
        let sources = slot_sources(Some(("c1", &refs(&[("slot:password", "s2")]))), &ssh, &VpnFile::default());

        let mut slots = vec![
            SecretSlot::new("password", "Password"),
            SecretSlot::new("sshPassword", "SSH password"),
            crate::ssh::route::proxy_password_slot(&proxy),
        ];
        filler.redirect(&mut slots, Some("c1"), &sources).unwrap();
        let stored: Vec<Option<String>> = slots.iter().map(|slot| slot.store.as_ref().map(|store| store.owner.secret_id(&store.slot))).collect();
        assert_eq!(stored, [Some("secret:s2:value".to_string()), None, Some("secret:s1:value".to_string())]);
        assert_eq!(slots[0].id, "password");
    }
}
