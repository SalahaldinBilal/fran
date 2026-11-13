use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ring::hmac;
use sync_proto::{KEY_LEN, KdfParams};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

pub type Key = Zeroizing<[u8; KEY_LEN]>;

const NONCE_LEN: usize = 24;
const RECOVERY_BYTES: usize = 20;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// The server decides these, so a hostile one could ask for a KDF that is too weak or one that hangs the app.
const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_PASSES: u32 = 16;
const MAX_PARALLELISM: u32 = 16;
const MIN_SALT_LEN: usize = 8;

const DATA_KEY_AAD: &[u8] = b"fran-sync data key";

fn random<const N: usize>() -> AppResult<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|error| AppError::general(format!("No secure random source: {error}")))?;
    Ok(bytes)
}

fn derived(key: &[u8], label: &str) -> Key {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), label.as_bytes());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(tag.as_ref());
    out
}

fn cipher(key: &[u8]) -> AppResult<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| AppError::general("Invalid sync key"))
}

fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> AppResult<Vec<u8>> {
    let nonce_bytes = random::<NONCE_LEN>()?;
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(&nonce_bytes);
    let sealed = cipher(key)?
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| AppError::general("Couldn't encrypt for sync"))?;
    Ok([nonce_bytes.as_slice(), &sealed].concat())
}

fn open(key: &[u8], sealed: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(nonce_bytes);
    cipher(key).ok()?.decrypt(&nonce, Payload { msg: ciphertext, aad }).ok().map(Zeroizing::new)
}

/// What the password turns into. The auth key goes to the server, the master key never leaves this computer.
pub struct PasswordKeys {
    pub auth: Key,
    pub master: Key,
}

pub fn password_keys(password: &str, kdf: &KdfParams) -> AppResult<PasswordKeys> {
    let sane = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&kdf.memory_kib)
        && (1..=MAX_PASSES).contains(&kdf.passes)
        && (1..=MAX_PARALLELISM).contains(&kdf.parallelism)
        && kdf.salt.len() >= MIN_SALT_LEN;
    if !sane {
        return Err(AppError::general("The server asked for password settings this app won't use"));
    }
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.parallelism, Some(KEY_LEN * 2))
        .map_err(|error| AppError::general(format!("Bad password settings: {error}")))?;
    let mut both = Zeroizing::new([0u8; KEY_LEN * 2]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), kdf.salt.as_slice(), both.as_mut())
        .map_err(|error| AppError::general(format!("Couldn't derive the sync keys: {error}")))?;
    let mut keys = PasswordKeys { auth: Zeroizing::new([0u8; KEY_LEN]), master: Zeroizing::new([0u8; KEY_LEN]) };
    keys.auth.copy_from_slice(&both[..KEY_LEN]);
    keys.master.copy_from_slice(&both[KEY_LEN..]);
    Ok(keys)
}

pub fn new_data_key() -> AppResult<Key> {
    Ok(Zeroizing::new(random::<KEY_LEN>()?))
}

pub fn wrap_data_key(wrapping_key: &Key, data_key: &Key) -> AppResult<Vec<u8>> {
    seal(wrapping_key.as_slice(), data_key.as_slice(), DATA_KEY_AAD)
}

pub fn unwrap_data_key(wrapping_key: &Key, wrapped: &[u8]) -> AppResult<Key> {
    let opened = open(wrapping_key.as_slice(), wrapped, DATA_KEY_AAD).filter(|key| key.len() == KEY_LEN);
    let opened = opened.ok_or_else(|| AppError::general("That password or recovery key doesn't open this account's data"))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&opened);
    Ok(key)
}

/// Shown once, as 8 groups of 4 characters. It wraps the data key a second time.
pub struct RecoveryKey {
    bytes: Zeroizing<[u8; RECOVERY_BYTES]>,
}

impl RecoveryKey {
    pub fn generate() -> AppResult<Self> {
        Ok(Self { bytes: Zeroizing::new(random::<RECOVERY_BYTES>()?) })
    }

    /// Spaces, dashes and lower case are fine, people type these by hand.
    pub fn parse(text: &str) -> AppResult<Self> {
        let bad = || AppError::general("That isn't a recovery key. It has 32 letters and digits.");
        let mut bytes = Zeroizing::new([0u8; RECOVERY_BYTES]);
        let (mut buffer, mut bits, mut written, mut characters) = (0u32, 0, 0, 0);
        for character in text.chars().filter(|character| !matches!(character, '-' | ' ' | '\t' | '\n' | '\r')) {
            let value = BASE32.iter().position(|letter| *letter as char == character.to_ascii_uppercase()).ok_or_else(bad)?;
            characters += 1;
            buffer = (buffer << 5) | value as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                *bytes.get_mut(written).ok_or_else(bad)? = (buffer >> bits) as u8;
                written += 1;
            }
        }
        if characters != RECOVERY_BYTES * 8 / 5 {
            return Err(bad());
        }
        Ok(Self { bytes })
    }

    pub fn display(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::new());
        let (mut buffer, mut bits, mut count) = (0u32, 0, 0);
        for byte in self.bytes.iter() {
            buffer = (buffer << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if count > 0 && count % 4 == 0 {
                    text.push('-');
                }
                text.push(BASE32[((buffer >> bits) & 31) as usize] as char);
                count += 1;
            }
        }
        text
    }

    pub fn auth_key(&self) -> Key {
        derived(self.bytes.as_slice(), "fran-sync recovery auth")
    }

    pub fn wrapping_key(&self) -> Key {
        derived(self.bytes.as_slice(), "fran-sync recovery wrap")
    }
}

/// Encrypts and names records for one account. Two computers with the same data key get the same record id for the same item.
pub struct RecordKeys {
    ids: Key,
    records: Key,
}

impl RecordKeys {
    pub fn new(data_key: &Key) -> Self {
        Self { ids: derived(data_key.as_slice(), "fran-sync record id"), records: derived(data_key.as_slice(), "fran-sync record") }
    }

    pub fn record_id(&self, item_key: &str) -> String {
        hex::encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, self.ids.as_slice()), item_key.as_bytes()))
    }

    // The id and revision are bound in, so the server can't hand back another record or an older version as this one.
    fn aad(record_id: &str, revision: u64) -> Vec<u8> {
        format!("{record_id}:{revision}").into_bytes()
    }

    pub fn seal(&self, record_id: &str, revision: u64, plaintext: &[u8]) -> AppResult<Vec<u8>> {
        seal(self.records.as_slice(), plaintext, &Self::aad(record_id, revision))
    }

    pub fn open(&self, record_id: &str, revision: u64, ciphertext: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        open(self.records.as_slice(), ciphertext, &Self::aad(record_id, revision))
            .ok_or_else(|| AppError::general("A synced record couldn't be decrypted. It was changed on the server or belongs to another account."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> KdfParams {
        KdfParams { salt: vec![7u8; 16].into(), memory_kib: MIN_MEMORY_KIB, passes: 1, parallelism: 1 }
    }

    #[test]
    fn the_same_password_and_salt_give_the_same_keys_and_the_halves_differ() {
        let first = password_keys("correct horse", &kdf()).unwrap();
        let second = password_keys("correct horse", &kdf()).unwrap();
        let other = password_keys("correct horse!", &kdf()).unwrap();
        assert_eq!(*first.auth, *second.auth);
        assert_eq!(*first.master, *second.master);
        assert_ne!(*first.auth, *first.master);
        assert_ne!(*first.master, *other.master);
    }

    #[test]
    fn a_server_cant_talk_the_app_into_a_weak_or_endless_kdf() {
        let weak = KdfParams { memory_kib: 8, ..kdf() };
        let endless = KdfParams { memory_kib: u32::MAX, ..kdf() };
        let no_salt = KdfParams { salt: Vec::new().into(), ..kdf() };
        let too_many_passes = KdfParams { passes: 1000, ..kdf() };
        for params in [weak, endless, no_salt, too_many_passes] {
            assert!(password_keys("correct horse", &params).is_err());
        }
    }

    #[test]
    fn the_data_key_survives_a_password_change_and_the_old_password_stops_working() {
        let data_key = new_data_key().unwrap();
        let old = password_keys("old password", &kdf()).unwrap();
        let wrapped = wrap_data_key(&old.master, &data_key).unwrap();

        let unwrapped = unwrap_data_key(&old.master, &wrapped).unwrap();
        let new = password_keys("new password", &kdf()).unwrap();
        let rewrapped = wrap_data_key(&new.master, &unwrapped).unwrap();

        assert_eq!(*unwrap_data_key(&new.master, &rewrapped).unwrap(), *data_key);
        assert!(unwrap_data_key(&old.master, &rewrapped).is_err());
    }

    #[test]
    fn the_recovery_key_opens_the_data_key_however_it_is_typed() {
        let data_key = new_data_key().unwrap();
        let recovery = RecoveryKey::generate().unwrap();
        let wrapped = wrap_data_key(&recovery.wrapping_key(), &data_key).unwrap();
        let shown = recovery.display();
        assert_eq!(shown.len(), 39);
        assert_eq!(shown.split('-').map(str::len).collect::<Vec<_>>(), [4; 8]);

        let typed = RecoveryKey::parse(&format!("  {} ", shown.to_lowercase().replace('-', " "))).unwrap();
        assert_eq!(*unwrap_data_key(&typed.wrapping_key(), &wrapped).unwrap(), *data_key);
        assert_eq!(*typed.auth_key(), *recovery.auth_key());
        assert_ne!(*recovery.auth_key(), *recovery.wrapping_key());

        let another = RecoveryKey::generate().unwrap();
        assert!(unwrap_data_key(&another.wrapping_key(), &wrapped).is_err());
        for wrong in ["", "ABCD-EFGH", "0000-0000-0000-0000-0000-0000-0000-0000", &format!("{}A", *shown)] {
            assert!(RecoveryKey::parse(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn two_computers_get_the_same_record_id_and_other_accounts_get_another() {
        let data_key = new_data_key().unwrap();
        let laptop = RecordKeys::new(&data_key);
        let desktop = RecordKeys::new(&data_key);
        let stranger = RecordKeys::new(&new_data_key().unwrap());
        let id = laptop.record_id("connection:3f2a");

        assert_eq!(id, desktop.record_id("connection:3f2a"));
        assert!(sync_proto::is_record_id(&id));
        assert_ne!(id, laptop.record_id("connection:3f2b"));
        assert_ne!(id, stranger.record_id("connection:3f2a"));
        assert!(!id.contains("3f2a"));
    }

    #[test]
    fn a_record_only_opens_as_itself_at_its_own_revision() {
        let keys = RecordKeys::new(&new_data_key().unwrap());
        let (id, other_id) = (keys.record_id("connection:a"), keys.record_id("connection:b"));
        let sealed = keys.seal(&id, 3, b"{\"name\":\"prod\"}").unwrap();

        assert_eq!(keys.open(&id, 3, &sealed).unwrap().as_slice(), b"{\"name\":\"prod\"}");
        assert!(keys.open(&other_id, 3, &sealed).is_err());
        assert!(keys.open(&id, 2, &sealed).is_err());

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(keys.open(&id, 3, &tampered).is_err());
        assert!(keys.open(&id, 3, &sealed[..10]).is_err());
        assert!(RecordKeys::new(&new_data_key().unwrap()).open(&id, 3, &sealed).is_err());
        assert!(!sealed.windows(4).any(|window| window == b"prod"));
    }
}
