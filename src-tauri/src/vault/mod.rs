pub mod commands;
pub mod lock;
pub mod os_auth;
pub mod reveal;

use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    path::PathBuf,
    sync::Mutex,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AppError, AppResult};
use crate::json_store::write_atomic;

const KEYRING_SERVICE: &str = "com.fran.app";
const KEYRING_ACCOUNT: &str = "vault-master-key";
const MAGIC: &[u8; 8] = b"FRDBVLT1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub available: bool,
    pub message: Option<String>,
    /// The vault key is wrapped with the app lock password instead of kept in the OS keychain.
    pub lock_enabled: bool,
    pub locked: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Secrets {
    version: u32,
    entries: BTreeMap<String, String>,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        for value in self.entries.values_mut() {
            value.zeroize();
        }
    }
}

struct Unlocked {
    key: Zeroizing<Vec<u8>>,
    secrets: Secrets,
}

/// Secrets encrypted with XChaCha20-Poly1305 in one file. The key never touches disk in the clear: it
/// lives in the OS keychain (Credential Manager, Keychain, Secret Service), or with the app lock on,
/// wrapped by a key derived from the lock password in `vault.lock`.
pub struct Vault {
    path: PathBuf,
    lock_path: PathBuf,
    state: Mutex<Option<Unlocked>>,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            lock_path: path.with_file_name("vault.lock"),
            path,
            state: Mutex::new(None),
        }
    }

    pub fn lock_enabled(&self) -> bool {
        self.lock_path.exists()
    }

    pub fn is_locked(&self) -> bool {
        self.lock_enabled() && self.lock_state().map(|state| state.is_none()).unwrap_or(true)
    }

    pub fn status(&self) -> VaultStatus {
        let lock_enabled = self.lock_enabled();
        if lock_enabled && self.is_locked() {
            return VaultStatus { available: true, message: None, lock_enabled, locked: true };
        }
        match self.with_unlocked(|_| Ok(())) {
            Ok(()) => VaultStatus { available: true, message: None, lock_enabled, locked: false },
            Err(error) => VaultStatus { available: false, message: Some(error.message), lock_enabled, locked: false },
        }
    }

    /// Opens the vault with the app lock password. Slow on purpose: the key comes from Argon2id.
    pub fn unlock_with_password(&self, password: &str) -> AppResult<()> {
        let file = lock::read(&self.lock_path)?;
        let key = lock::unwrap(&file, password)?;
        let secrets = self.read_secrets(&key)?;
        *self.lock_state()? = Some(Unlocked { key, secrets });
        Ok(())
    }

    /// Forgets the key and every secret held in memory. Only with the app lock on, otherwise it would just reopen.
    pub fn lock(&self) -> AppResult<bool> {
        if !self.lock_enabled() {
            return Ok(false);
        }
        *self.lock_state()? = None;
        Ok(true)
    }

    /// Moves the vault key out of the OS keychain into `vault.lock`, wrapped with the password.
    pub fn enable_lock(&self, password: &str) -> AppResult<()> {
        if self.lock_enabled() {
            return Err(AppError::general("The app lock is already on"));
        }
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        // The vault file has to exist, or a later unlock couldn't tell a fresh vault from a lost one.
        self.with_unlocked(|unlocked| persist(&self.path, &unlocked.key, &unlocked.secrets))?;
        lock::write(&self.lock_path, &lock::wrap(&key, password)?)?;

        match keychain_entry().and_then(|entry| match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keychain_error(error)),
        }) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = fs::remove_file(&self.lock_path);
                Err(error)
            }
        }
    }

    /// Puts the vault key back in the OS keychain. Needs the password, even while unlocked.
    pub fn disable_lock(&self, password: &str) -> AppResult<()> {
        let file = lock::read(&self.lock_path)?;
        let key = lock::unwrap(&file, password)?;
        keychain_entry()?.set_secret(&key).map_err(keychain_error)?;
        if let Err(error) = fs::remove_file(&self.lock_path) {
            let _ = keychain_entry().map(|entry| entry.delete_credential());
            return Err(AppError::vault(format!("The app lock file couldn't be removed: {error}")));
        }
        let mut state = self.lock_state()?;
        if state.is_none() {
            let secrets = self.read_secrets(&key)?;
            *state = Some(Unlocked { key, secrets });
        }
        Ok(())
    }

    /// Only checks the app lock password. Slow on purpose, like unlocking.
    pub fn check_lock_password(&self, password: &str) -> AppResult<()> {
        let file = lock::read(&self.lock_path)?;
        lock::unwrap(&file, password).map(drop)
    }

    pub fn change_lock_password(&self, current: &str, next: &str) -> AppResult<()> {
        let file = lock::read(&self.lock_path)?;
        let key = lock::unwrap(&file, current)?;
        lock::write(&self.lock_path, &lock::wrap(&key, next)?)
    }

    fn read_secrets(&self, key: &[u8]) -> AppResult<Secrets> {
        match fs::read(&self.path) {
            Ok(bytes) => decrypt(key, &bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Secrets { version: 1, entries: BTreeMap::new() }),
            Err(error) => Err(AppError::vault(format!("Vault file could not be read: {error}"))),
        }
    }

    pub fn get(&self, id: &str) -> AppResult<Option<Zeroizing<String>>> {
        self.with_unlocked(|unlocked| {
            Ok(unlocked
                .secrets
                .entries
                .get(id)
                .map(|value| Zeroizing::new(value.clone())))
        })
    }

    pub fn ids_with_prefix(&self, prefix: &str) -> AppResult<Vec<String>> {
        self.with_unlocked(|unlocked| {
            Ok(unlocked
                .secrets
                .entries
                .keys()
                .filter(|id| id.starts_with(prefix))
                .cloned()
                .collect())
        })
    }

    pub fn set(&self, id: &str, value: &str) -> AppResult<()> {
        self.modify(|secrets| {
            if let Some(mut old) = secrets.entries.insert(id.to_string(), value.to_string()) {
                old.zeroize();
            }
        })
    }

    pub fn remove(&self, id: &str) -> AppResult<()> {
        self.modify(|secrets| {
            if let Some(mut old) = secrets.entries.remove(id) {
                old.zeroize();
            }
        })
    }

    pub fn remove_prefix(&self, prefix: &str) -> AppResult<()> {
        self.modify(|secrets| {
            let ids: Vec<String> = secrets
                .entries
                .keys()
                .filter(|id| id.starts_with(prefix))
                .cloned()
                .collect();

            for id in ids {
                if let Some(mut old) = secrets.entries.remove(&id) {
                    old.zeroize();
                }
            }
        })
    }

    pub fn copy_prefix(&self, from_prefix: &str, to_prefix: &str) -> AppResult<()> {
        self.modify(|secrets| {
            let copies: Vec<(String, String)> = secrets
                .entries
                .iter()
                .filter_map(|(id, value)| {
                    id.strip_prefix(from_prefix)
                        .map(|rest| (format!("{to_prefix}{rest}"), value.clone()))
                })
                .collect();

            secrets.entries.extend(copies);
        })
    }

    /// Wipes every stored secret, the keychain key and the app lock. Only for a vault that can no longer be opened.
    pub fn reset(&self) -> AppResult<()> {
        let mut state = self.lock_state()?;
        *state = None;

        for path in [&self.path, &self.lock_path] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        let entry = keychain_entry()?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keychain_error(error)),
        }
    }

    fn lock_state(&self) -> AppResult<std::sync::MutexGuard<'_, Option<Unlocked>>> {
        self.state
            .lock()
            .map_err(|_| AppError::vault("Vault lock poisoned"))
    }

    fn with_unlocked<R>(&self, action: impl FnOnce(&mut Unlocked) -> AppResult<R>) -> AppResult<R> {
        let mut state = self.lock_state()?;

        if state.is_none() {
            *state = Some(self.unlock()?);
        }

        match state.as_mut() {
            Some(unlocked) => action(unlocked),
            None => Err(AppError::vault("Vault is locked")),
        }
    }

    fn modify(&self, change: impl FnOnce(&mut Secrets)) -> AppResult<()> {
        let path = self.path.clone();
        self.with_unlocked(|unlocked| {
            let backup = unlocked.secrets.entries.clone();
            change(&mut unlocked.secrets);

            let result = persist(&path, &unlocked.key, &unlocked.secrets);
            if result.is_err() {
                for value in unlocked.secrets.entries.values_mut() {
                    value.zeroize();
                }
                unlocked.secrets.entries = backup;
            } else {
                let mut backup = backup;
                for value in backup.values_mut() {
                    value.zeroize();
                }
            }
            result
        })
    }

    fn unlock(&self) -> AppResult<Unlocked> {
        if self.lock_enabled() {
            return Err(AppError::app_locked());
        }
        let file = match fs::read(&self.path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(AppError::vault(format!("Vault file could not be read: {error}"))),
        };

        let key = load_or_create_key(file.is_some())?;

        let secrets = match file {
            Some(bytes) => decrypt(&key, &bytes)?,
            None => Secrets {
                version: 1,
                entries: BTreeMap::new(),
            },
        };

        Ok(Unlocked { key, secrets })
    }
}

fn keychain_entry() -> AppResult<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).map_err(keychain_error)
}

fn keychain_error(error: keyring::Error) -> AppError {
    AppError::vault(format!("OS keychain unavailable: {error}"))
}

fn load_or_create_key(vault_exists: bool) -> AppResult<Zeroizing<Vec<u8>>> {
    let entry = keychain_entry()?;

    match entry.get_secret() {
        Ok(bytes) => checked_key(bytes),
        Err(keyring::Error::NoEntry) if !vault_exists => {
            let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
            getrandom::fill(&mut key)
                .map_err(|error| AppError::vault(format!("No secure random source: {error}")))?;
            entry.set_secret(&key).map_err(keychain_error)?;
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => adopt_old_key(&entry),
        Err(error) => Err(keychain_error(error)),
    }
}

/// A vault copied from Fran DB still has its key under the old keychain name. The old entry stays for Fran DB.
fn adopt_old_key(entry: &keyring::Entry) -> AppResult<Zeroizing<Vec<u8>>> {
    let old = keyring::Entry::new(crate::legacy::OLD_IDENTIFIER, KEYRING_ACCOUNT).map_err(keychain_error)?;
    let key = match old.get_secret() {
        Ok(bytes) => checked_key(bytes)?,
        Err(keyring::Error::NoEntry) => {
            return Err(AppError::vault(
                "The vault key is missing from the OS keychain, so saved passwords can't be read. Reset the vault to start over.",
            ));
        }
        Err(error) => return Err(keychain_error(error)),
    };
    entry.set_secret(&key).map_err(keychain_error)?;
    Ok(key)
}

fn checked_key(bytes: Vec<u8>) -> AppResult<Zeroizing<Vec<u8>>> {
    let key = Zeroizing::new(bytes);
    if key.len() != KEY_LEN {
        return Err(AppError::vault("The vault key in the OS keychain has the wrong length"));
    }
    Ok(key)
}

fn cipher(key: &[u8]) -> AppResult<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| AppError::vault("Invalid vault key"))
}

fn decrypt(key: &[u8], bytes: &[u8]) -> AppResult<Secrets> {
    let header_len = MAGIC.len() + NONCE_LEN;
    if bytes.len() < header_len || &bytes[..MAGIC.len()] != MAGIC {
        return Err(AppError::vault("The vault file is not in a known format"));
    }

    let mut nonce = XNonce::default();
    nonce.copy_from_slice(&bytes[MAGIC.len()..header_len]);

    let plaintext = Zeroizing::new(
        cipher(key)?
            .decrypt(
                &nonce,
                Payload {
                    msg: &bytes[header_len..],
                    aad: MAGIC,
                },
            )
            .map_err(|_| {
                AppError::vault("The vault file can't be decrypted with the key in the OS keychain")
            })?,
    );

    serde_json::from_slice(&plaintext)
        .map_err(|error| AppError::vault(format!("The vault contents are damaged: {error}")))
}

fn persist(path: &PathBuf, key: &[u8], secrets: &Secrets) -> AppResult<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(secrets)?);

    let mut nonce = XNonce::default();
    getrandom::fill(&mut nonce)
        .map_err(|error| AppError::vault(format!("No secure random source: {error}")))?;

    let ciphertext = cipher(key)?
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| AppError::vault("Encrypting the vault failed"))?;

    let mut file = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);

    write_atomic(path, &file)
        .map_err(|error| AppError::vault(format!("Vault file could not be written: {error}")))
}
