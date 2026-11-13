pub mod client;
pub mod commands;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sync_proto::{
    ChangePassword, ChangeRecovery, CreateAccount, DeleteAccount, Device, KEY_LEN, KdfParams, PushRecord, PushRequest, PushStatus, RecoveryFinish,
    RecoveryStart, SignIn, SignedIn,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use self::client::Client;
use super::{Incoming, Outgoing, Provider, Pulled, Pushed, vault_prefix};
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::sync::crypto::{self, Key, PasswordKeys, RecordKeys, RecoveryKey};
use crate::sync::state::{Category, Cloud};
use crate::vault::Vault;

const DATA_KEY_SLOT: &str = "dataKey";
const SESSION_SLOT: &str = "session";
const PUSH_BATCH: usize = 500;
const MIN_PASSWORD_CHARS: usize = 10;

/// What `sync.json` keeps about a Fran server cloud. Nothing here is secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub url: String,
    pub email: String,
    pub account_id: String,
    pub instance_id: String,
}

impl Config {
    pub fn of(cloud: &Cloud) -> AppResult<Self> {
        serde_json::from_value(cloud.config.clone()).map_err(|_| AppError::general("This cloud's saved details are damaged. Remove it and add it again."))
    }

    /// The same on every computer signed into this account on this server.
    pub fn identity(&self) -> String {
        format!("franServer:{}:{}", self.instance_id, self.account_id)
    }
}

/// What a record holds once decrypted. The server sees none of it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    key: String,
    #[serde(default)]
    deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    moved_to: Option<String>,
    #[serde(default)]
    modified_at: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    refs: BTreeMap<String, String>,
    #[serde(default)]
    content: Value,
}

pub struct FranServer {
    client: Client,
    token: Zeroizing<String>,
    keys: RecordKeys,
}

fn signed_out() -> AppError {
    AppError::new("This computer is signed out of that cloud. Sign in again.", ErrorDetail::SyncSignedOut)
}

pub fn session_token(cloud_id: &str, vault: &Vault) -> AppResult<Zeroizing<String>> {
    vault.get(&format!("{}{SESSION_SLOT}", vault_prefix(cloud_id)))?.ok_or_else(signed_out)
}

pub fn data_key(cloud_id: &str, vault: &Vault) -> AppResult<Key> {
    let stored = vault.get(&format!("{}{DATA_KEY_SLOT}", vault_prefix(cloud_id)))?.ok_or_else(signed_out)?;
    let bytes = Zeroizing::new(hex::decode(stored.as_str()).map_err(|_| signed_out())?);
    if bytes.len() != KEY_LEN {
        return Err(signed_out());
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn open(cloud: &Cloud, vault: &Vault) -> AppResult<Arc<dyn Provider>> {
    let config = Config::of(cloud)?;
    Ok(Arc::new(FranServer {
        client: Client::new(&config.url)?,
        token: session_token(&cloud.id, vault)?,
        keys: RecordKeys::new(&data_key(&cloud.id, vault)?),
    }))
}

impl FranServer {
    fn opened(&self, record: &sync_proto::Record) -> AppResult<Incoming> {
        let plaintext = self.keys.open(&record.id, record.revision, record.ciphertext.as_slice())?;
        let envelope: Envelope =
            serde_json::from_slice(&plaintext).map_err(|_| AppError::general("A synced record was written by a version of Fran this one can't read"))?;
        // Without this a server could hand one item's record back under another item's id.
        if self.keys.record_id(&envelope.key) != record.id {
            return Err(AppError::general("A synced record doesn't belong where the server put it"));
        }
        Ok(Incoming {
            key: envelope.key,
            revision: record.revision,
            deleted: envelope.deleted,
            moved_to: envelope.moved_to,
            modified_at: envelope.modified_at,
            refs: envelope.refs,
            content: envelope.content,
        })
    }

    fn sealed(&self, change: &Outgoing) -> AppResult<PushRecord> {
        let id = self.keys.record_id(&change.key);
        let envelope = Envelope {
            key: change.key.clone(),
            deleted: change.deleted,
            moved_to: change.moved_to.clone(),
            modified_at: change.modified_at,
            refs: change.refs.clone(),
            content: if change.deleted { Value::Null } else { change.content.clone() },
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&envelope)?);
        let ciphertext = self.keys.seal(&id, change.base_revision + 1, &plaintext)?;
        Ok(PushRecord { id, base_revision: change.base_revision, deleted: change.deleted, ciphertext: ciphertext.into() })
    }
}

#[async_trait]
impl Provider for FranServer {
    fn accepts(&self, _category: Category) -> bool {
        true
    }

    async fn pull(&self, cursor: u64) -> AppResult<Pulled> {
        let page = self.client.pull(&self.token, cursor).await?;
        let changes = page.records.iter().map(|record| self.opened(record)).collect::<AppResult<Vec<_>>>()?;
        Ok(Pulled { changes, cursor: page.cursor, more: page.more, problems: Vec::new() })
    }

    async fn push(&self, changes: Vec<Outgoing>) -> AppResult<Vec<(String, Pushed)>> {
        let mut answers = Vec::with_capacity(changes.len());
        for batch in changes.chunks(PUSH_BATCH) {
            let records = batch.iter().map(|change| self.sealed(change)).collect::<AppResult<Vec<_>>>()?;
            let keys: HashMap<String, &str> = records.iter().zip(batch).map(|(record, change)| (record.id.clone(), change.key.as_str())).collect();
            let response = self.client.push(&self.token, &PushRequest { records }).await?;
            for result in response.results {
                let Some(key) = keys.get(&result.id) else {
                    continue;
                };
                let pushed = match result.status {
                    PushStatus::Accepted => Pushed::Accepted { revision: result.revision },
                    PushStatus::Conflict => Pushed::Conflict,
                    PushStatus::TooLarge => Pushed::TooLarge,
                    PushStatus::QuotaExceeded => Pushed::QuotaExceeded,
                };
                answers.push((key.to_string(), pushed));
            }
        }
        Ok(answers)
    }

    async fn watch(&self) -> Option<mpsc::Receiver<()>> {
        self.client.events(&self.token).await.ok()
    }
}

/// A fresh sign-in, before it's saved. The token and the data key go to the vault and nowhere else.
pub struct Session {
    pub config: Config,
    pub token: Zeroizing<String>,
    pub data_key: Key,
}

impl Session {
    fn new(client: &Client, instance_id: String, email: &str, signed_in: SignedIn, data_key: Key) -> Self {
        Self {
            config: Config { url: client.base().to_string(), email: email.to_string(), account_id: signed_in.account_id, instance_id },
            token: Zeroizing::new(signed_in.token),
            data_key,
        }
    }

    pub fn save(&self, cloud_id: &str, vault: &Vault) -> AppResult<()> {
        let prefix = vault_prefix(cloud_id);
        let key = Zeroizing::new(hex::encode(self.data_key.as_slice()));
        vault.set(&format!("{prefix}{DATA_KEY_SLOT}"), &key)?;
        vault.set(&format!("{prefix}{SESSION_SLOT}"), &self.token)
    }
}

fn normal_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::general("Enter the account's email address"));
    }
    Ok(email)
}

fn checked_new_password(password: &str) -> AppResult<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AppError::general(format!("Use at least {MIN_PASSWORD_CHARS} characters. This password is the only thing protecting your synced data.")));
    }
    Ok(())
}

// Argon2id with 64 MiB takes about a second, too long for an async worker thread.
async fn derive(password: Zeroizing<String>, kdf: KdfParams) -> AppResult<PasswordKeys> {
    tokio::task::spawn_blocking(move || crypto::password_keys(&password, &kdf))
        .await
        .map_err(|_| AppError::general("Couldn't derive the sync keys"))?
}

async fn keys_for(client: &Client, email: &str, password: &str) -> AppResult<PasswordKeys> {
    let kdf = client.kdf(email).await?;
    derive(Zeroizing::new(password.to_string()), kdf).await
}

pub struct SignedUp {
    pub session: Session,
    /// Shown once. It's the only way back in after a forgotten password.
    pub recovery_key: Zeroizing<String>,
}

pub async fn sign_up(url: &str, email: &str, password: &str, invite: Option<String>, device: Device) -> AppResult<SignedUp> {
    let email = normal_email(email)?;
    checked_new_password(password)?;
    let client = Client::new(url)?;
    let info = client.info().await?;
    let keys = keys_for(&client, &email, password).await?;
    let data_key = crypto::new_data_key()?;
    let recovery = RecoveryKey::generate()?;
    let account = CreateAccount {
        email: email.clone(),
        auth_key: keys.auth.to_vec().into(),
        wrapped_data_key: crypto::wrap_data_key(&keys.master, &data_key)?.into(),
        recovery_auth_key: recovery.auth_key().to_vec().into(),
        recovery_wrapped_data_key: crypto::wrap_data_key(&recovery.wrapping_key(), &data_key)?.into(),
        invite: invite.map(|code| code.trim().to_string()).filter(|code| !code.is_empty()),
        device,
    };
    let signed_in = client.create_account(&account).await?;
    Ok(SignedUp { session: Session::new(&client, info.instance_id, &email, signed_in, data_key), recovery_key: recovery.display() })
}

pub async fn sign_in(url: &str, email: &str, password: &str, totp: Option<String>, device: Device) -> AppResult<Session> {
    let email = normal_email(email)?;
    let client = Client::new(url)?;
    let info = client.info().await?;
    let keys = keys_for(&client, &email, password).await?;
    let totp = totp.map(|code| code.trim().to_string()).filter(|code| !code.is_empty());
    let signed_in = client.sign_in(&SignIn { email: email.clone(), auth_key: keys.auth.to_vec().into(), totp, device }).await?;
    let data_key = crypto::unwrap_data_key(&keys.master, signed_in.wrapped_data_key.as_slice())?;
    Ok(Session::new(&client, info.instance_id, &email, signed_in, data_key))
}

/// Signs in with the recovery key and sets a new password. The data key stays the same, so nothing is re-encrypted.
pub async fn recover(url: &str, email: &str, recovery_key: &str, new_password: &str, device: Device) -> AppResult<Session> {
    let email = normal_email(email)?;
    checked_new_password(new_password)?;
    let recovery = RecoveryKey::parse(recovery_key)?;
    let client = Client::new(url)?;
    let info = client.info().await?;
    let recovery_auth_key: sync_proto::Bytes = recovery.auth_key().to_vec().into();
    let started = client.recovery_start(&RecoveryStart { email: email.clone(), recovery_auth_key: recovery_auth_key.clone() }).await?;
    let data_key = crypto::unwrap_data_key(&recovery.wrapping_key(), started.recovery_wrapped_data_key.as_slice())?;
    let keys = keys_for(&client, &email, new_password).await?;
    let finish = RecoveryFinish {
        email: email.clone(),
        recovery_auth_key,
        auth_key: keys.auth.to_vec().into(),
        wrapped_data_key: crypto::wrap_data_key(&keys.master, &data_key)?.into(),
        device,
    };
    let signed_in = client.recovery_finish(&finish).await?;
    Ok(Session::new(&client, info.instance_id, &email, signed_in, data_key))
}

/// A signed-in cloud's account calls. Each one that changes the account asks for the password again.
pub struct Account {
    pub client: Client,
    pub config: Config,
    pub token: Zeroizing<String>,
    data_key: Key,
}

impl Account {
    pub fn open(cloud: &Cloud, vault: &Vault) -> AppResult<Self> {
        let config = Config::of(cloud)?;
        Ok(Self { client: Client::new(&config.url)?, token: session_token(&cloud.id, vault)?, data_key: data_key(&cloud.id, vault)?, config })
    }

    async fn keys(&self, password: &str) -> AppResult<PasswordKeys> {
        keys_for(&self.client, &self.config.email, password).await
    }

    pub async fn change_password(&self, current: &str, next: &str) -> AppResult<()> {
        checked_new_password(next)?;
        let old = self.keys(current).await?;
        let new = self.keys(next).await?;
        let change = ChangePassword {
            auth_key: old.auth.to_vec().into(),
            new_auth_key: new.auth.to_vec().into(),
            new_wrapped_data_key: crypto::wrap_data_key(&new.master, &self.data_key)?.into(),
        };
        self.client.change_password(&self.token, &change).await
    }

    /// Makes the old recovery key useless and returns the new one to show once.
    pub async fn new_recovery_key(&self, password: &str) -> AppResult<Zeroizing<String>> {
        let keys = self.keys(password).await?;
        let recovery = RecoveryKey::generate()?;
        let change = ChangeRecovery {
            auth_key: keys.auth.to_vec().into(),
            recovery_auth_key: recovery.auth_key().to_vec().into(),
            recovery_wrapped_data_key: crypto::wrap_data_key(&recovery.wrapping_key(), &self.data_key)?.into(),
        };
        self.client.change_recovery(&self.token, &change).await?;
        Ok(recovery.display())
    }

    pub async fn auth_key(&self, password: &str) -> AppResult<sync_proto::Bytes> {
        Ok(self.keys(password).await?.auth.to_vec().into())
    }

    pub async fn delete(&self, password: &str) -> AppResult<()> {
        let auth_key = self.auth_key(password).await?;
        self.client.delete_account(&self.token, &DeleteAccount { auth_key }).await
    }
}

pub fn this_device(name: &str) -> Device {
    let name = name.trim();
    Device { name: if name.is_empty() { "A computer".to_string() } else { name.chars().take(80).collect() }, os: std::env::consts::OS.to_string() }
}
