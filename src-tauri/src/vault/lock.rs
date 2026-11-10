use std::{fs, path::Path};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::json_store::write_atomic;

const MAGIC: &[u8; 8] = b"FRDBLCK1";
const VERSION: u32 = 1;
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;
const LANES: u32 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
pub const MIN_PASSWORD_LEN: usize = 8;

/// The vault key wrapped with a key derived from the app lock password. Replaces the keychain entry while the lock is on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockFile {
    version: u32,
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    salt: String,
    nonce: String,
    wrapped_key: String,
}

fn random<const N: usize>() -> AppResult<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|error| AppError::vault(format!("No secure random source: {error}")))?;
    Ok(bytes)
}

fn derive(password: &str, salt: &[u8], memory_kib: u32, passes: u32, lanes: u32) -> AppResult<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(memory_kib, passes, lanes, Some(KEY_LEN)).map_err(|error| AppError::vault(format!("Bad lock settings: {error}")))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| AppError::vault(format!("Deriving the lock key failed: {error}")))?;
    Ok(key)
}

// The settings are authenticated too, so a file edited to weaker ones doesn't open.
fn aad(memory_kib: u32, passes: u32, lanes: u32, salt: &[u8]) -> Vec<u8> {
    [MAGIC.as_slice(), &memory_kib.to_le_bytes(), &passes.to_le_bytes(), &lanes.to_le_bytes(), salt].concat()
}

pub fn check_password(password: &str) -> AppResult<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::general(format!("Use at least {MIN_PASSWORD_LEN} characters")));
    }
    Ok(())
}

pub fn wrap(key: &[u8], password: &str) -> AppResult<LockFile> {
    wrap_with(key, password, MEMORY_KIB, PASSES)
}

fn wrap_with(key: &[u8], password: &str, memory_kib: u32, passes: u32) -> AppResult<LockFile> {
    check_password(password)?;
    let salt = random::<SALT_LEN>()?;
    let nonce_bytes = random::<24>()?;
    let derived = derive(password, &salt, memory_kib, passes, LANES)?;
    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref()).map_err(|_| AppError::vault("Invalid lock key"))?;
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(&nonce_bytes);
    let wrapped = cipher
        .encrypt(&nonce, Payload { msg: key, aad: &aad(memory_kib, passes, LANES, &salt) })
        .map_err(|_| AppError::vault("Wrapping the vault key failed"))?;
    Ok(LockFile {
        version: VERSION,
        memory_kib,
        passes,
        lanes: LANES,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        wrapped_key: hex::encode(wrapped),
    })
}

pub fn unwrap(file: &LockFile, password: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    // Bounds first, so a damaged file can't ask for gigabytes before the check fails.
    if file.version != VERSION || !(8 * 1024..=1024 * 1024).contains(&file.memory_kib) || !(1..=10).contains(&file.passes) || !(1..=8).contains(&file.lanes) {
        return Err(AppError::vault("The app lock file isn't in a known format"));
    }
    let damaged = || AppError::vault("The app lock file is damaged");
    let salt = hex::decode(&file.salt).map_err(|_| damaged())?;
    let nonce_bytes = hex::decode(&file.nonce).map_err(|_| damaged())?;
    let wrapped = hex::decode(&file.wrapped_key).map_err(|_| damaged())?;
    if nonce_bytes.len() != 24 {
        return Err(damaged());
    }
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(&nonce_bytes);

    let derived = derive(password, &salt, file.memory_kib, file.passes, file.lanes)?;
    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref()).map_err(|_| AppError::vault("Invalid lock key"))?;
    let key = Zeroizing::new(
        cipher
            .decrypt(&nonce, Payload { msg: &wrapped, aad: &aad(file.memory_kib, file.passes, file.lanes, &salt) })
            .map_err(|_| AppError::general("That password isn't right"))?,
    );
    if key.len() != KEY_LEN {
        return Err(damaged());
    }
    Ok(key)
}

pub fn read(path: &Path) -> AppResult<LockFile> {
    let bytes = fs::read(path).map_err(|error| AppError::vault(format!("The app lock file can't be read: {error}")))?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::vault("The app lock file is damaged"))
}

pub fn write(path: &Path, file: &LockFile) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(file)?;
    write_atomic(path, &bytes).map_err(|error| AppError::vault(format!("The app lock file can't be written: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small settings, since 64 MiB passes are slow in a debug build.
    const TEST_MEMORY: u32 = 8 * 1024;

    #[test]
    fn wraps_and_unwraps() {
        let key = [5u8; KEY_LEN];
        let file = wrap_with(&key, "correct horse", TEST_MEMORY, 1).unwrap();
        assert_eq!(unwrap(&file, "correct horse").unwrap().as_slice(), &key);
        assert!(unwrap(&file, "wrong horse!").is_err());
    }

    #[test]
    fn edited_settings_fail() {
        let file = wrap_with(&[1u8; KEY_LEN], "correct horse", TEST_MEMORY, 2).unwrap();
        let weaker = LockFile { passes: 1, ..file.clone() };
        assert!(unwrap(&weaker, "correct horse").is_err());
        let huge = LockFile { memory_kib: u32::MAX, ..file };
        assert!(unwrap(&huge, "correct horse").is_err());
    }

    #[test]
    fn short_passwords_are_refused() {
        assert!(wrap_with(&[1u8; KEY_LEN], "short", TEST_MEMORY, 1).is_err());
    }

    #[test]
    fn default_settings_match_the_plan() {
        assert_eq!((MEMORY_KIB, PASSES), (65_536, 3));
    }
}
