use std::{
    fs,
    io::{ErrorKind, Write},
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::vault::Vault;

pub const DAY_MS: u64 = 86_400_000;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
// What a sealed log keeps in memory until the app is unlocked again.
const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD` of a day counted from the Unix epoch, in UTC.
pub fn day_name(day: u64) -> String {
    let z = day as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn day_number(name: &str) -> Option<u64> {
    let mut parts = name.splitn(3, '-').map(|part| part.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

struct KeyState {
    key: Option<Zeroizing<Vec<u8>>>,
    /// The app is locked: records wait here as plaintext until the key is back.
    sealed: bool,
    pending: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pending_bytes: usize,
}

/// Records in one encrypted file per UTC day, appended one by one. The key is kept in the vault.
pub struct DayLog {
    dir: PathBuf,
    magic: &'static [u8; 8],
    key_id: &'static str,
    name: &'static str,
    state: Mutex<KeyState>,
}

impl DayLog {
    pub fn new(dir: PathBuf, magic: &'static [u8; 8], key_id: &'static str, name: &'static str) -> Self {
        Self {
            dir,
            magic,
            key_id,
            name,
            state: Mutex::new(KeyState { key: None, sealed: false, pending: Vec::new(), pending_bytes: 0 }),
        }
    }

    fn lock_state(&self) -> AppResult<std::sync::MutexGuard<'_, KeyState>> {
        self.state.lock().map_err(|_| AppError::general(format!("{} lock poisoned", self.name)))
    }

    /// Loads the key from the vault, making one the first time, and writes what waited while sealed.
    pub fn unlock(&self, vault: &Vault) -> AppResult<()> {
        let mut state = self.lock_state()?;
        if state.key.is_none() {
            let stored = match vault.get(self.key_id)? {
                Some(stored) => Zeroizing::new(
                    hex::decode(stored.as_str()).map_err(|_| AppError::vault(format!("The {} key is damaged", self.name)))?,
                ),
                None => {
                    let mut fresh = Zeroizing::new(vec![0u8; KEY_LEN]);
                    getrandom::fill(&mut fresh)
                        .map_err(|error| AppError::vault(format!("No secure random source: {error}")))?;
                    vault.set(self.key_id, &Zeroizing::new(hex::encode(fresh.as_slice())))?;
                    fresh
                }
            };
            if stored.len() != KEY_LEN {
                return Err(AppError::vault(format!("The {} key has the wrong length", self.name)));
            }
            state.key = Some(stored);
        }
        state.sealed = false;
        let pending = std::mem::take(&mut state.pending);
        state.pending_bytes = 0;
        let cipher = Self::cipher_from(&state, self.name)?;
        drop(state);
        for (at, plaintext) in pending {
            self.write(&cipher, at, &plaintext)?;
        }
        Ok(())
    }

    /// Drops the key for the app lock. Appends wait in memory until `unlock`.
    pub fn seal(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.key = None;
            state.sealed = true;
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.sealed)
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.key.is_some())
    }

    /// Drops the key and every file, for a vault reset that makes the log unreadable.
    pub fn forget(&self) -> AppResult<()> {
        if let Ok(mut state) = self.state.lock() {
            state.key = None;
            state.pending.clear();
            state.pending_bytes = 0;
        }
        self.clear()
    }

    fn cipher_from(state: &KeyState, name: &str) -> AppResult<XChaCha20Poly1305> {
        let key = state.key.as_ref().ok_or_else(|| AppError::vault(format!("The {name} is locked")))?;
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| AppError::vault(format!("Invalid {name} key")))
    }

    fn cipher(&self) -> AppResult<XChaCha20Poly1305> {
        let state = self.lock_state()?;
        Self::cipher_from(&state, self.name)
    }

    fn path(&self, day: &str) -> PathBuf {
        self.dir.join(format!("{day}.log"))
    }

    fn aad(&self, day: &str) -> Vec<u8> {
        [self.magic.as_slice(), day.as_bytes()].concat()
    }

    pub fn append<T: Serialize>(&self, at: u64, record: &T) -> AppResult<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(record)?);
        let cipher = {
            let mut state = self.lock_state()?;
            if state.key.is_none() && state.sealed {
                // Oldest first out, so a long lock keeps the latest records.
                state.pending_bytes += plaintext.len();
                state.pending.push((at, plaintext));
                while state.pending_bytes > MAX_PENDING_BYTES && !state.pending.is_empty() {
                    let (_, dropped) = state.pending.remove(0);
                    state.pending_bytes -= dropped.len();
                }
                return Ok(());
            }
            Self::cipher_from(&state, self.name)?
        };
        self.write(&cipher, at, &plaintext)
    }

    fn write(&self, cipher: &XChaCha20Poly1305, at: u64, plaintext: &[u8]) -> AppResult<()> {
        let day = day_name(at / DAY_MS);
        let mut nonce = XNonce::default();
        getrandom::fill(&mut nonce).map_err(|error| AppError::vault(format!("No secure random source: {error}")))?;
        let aad = self.aad(&day);
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| AppError::vault(format!("Encrypting the {} failed", self.name)))?;

        let length = u32::try_from(ciphertext.len()).map_err(|_| AppError::general("Log record too large"))?;
        let mut record = Vec::with_capacity(4 + NONCE_LEN + ciphertext.len());
        record.extend_from_slice(&length.to_le_bytes());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);

        fs::create_dir_all(&self.dir)?;
        let mut file = fs::OpenOptions::new().create(true).append(true).open(self.path(&day))?;
        file.write_all(&record)?;
        Ok(())
    }

    fn read_day_with<T: DeserializeOwned>(&self, cipher: &XChaCha20Poly1305, day: &str) -> AppResult<Vec<T>> {
        let bytes = match fs::read(self.path(day)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let aad = self.aad(day);

        let mut records = Vec::new();
        let mut offset = 0;
        // A record cut short by a crash is the last one in the file, so reading stops there.
        while offset + 4 + NONCE_LEN <= bytes.len() {
            let length = u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) as usize;
            let start = offset + 4 + NONCE_LEN;
            if start + length > bytes.len() {
                break;
            }
            let mut nonce = XNonce::default();
            nonce.copy_from_slice(&bytes[offset + 4..start]);
            let plaintext = Zeroizing::new(
                cipher
                    .decrypt(&nonce, Payload { msg: &bytes[start..start + length], aad: &aad })
                    .map_err(|_| AppError::vault(format!("The {} for {day} can't be decrypted", self.name)))?,
            );
            records.push(serde_json::from_slice(&plaintext)?);
            offset = start + length;
        }
        Ok(records)
    }

    /// Every record from the UTC days that `from` to `to` (Unix ms) touch.
    pub fn read_days<T: DeserializeOwned>(&self, from: u64, to: u64) -> AppResult<Vec<T>> {
        let cipher = self.cipher()?;
        let mut records = Vec::new();
        for day in from / DAY_MS..=to / DAY_MS {
            records.extend(self.read_day_with(&cipher, &day_name(day))?);
        }
        Ok(records)
    }

    pub fn prune(&self, keep_days: u32) -> AppResult<()> {
        let today = now_ms() / DAY_MS;
        let oldest = today.saturating_sub(u64::from(keep_days).saturating_sub(1));
        let listing = match fs::read_dir(&self.dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for item in listing.flatten() {
            let path = item.path();
            let day = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|_| path.extension().is_some_and(|extension| extension == "log"))
                .and_then(day_number);
            if day.is_some_and(|day| day < oldest) {
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }

    pub fn size(&self) -> AppResult<u64> {
        let listing = match fs::read_dir(&self.dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        Ok(listing
            .flatten()
            .filter_map(|item| item.metadata().ok())
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len())
            .sum())
    }

    pub fn clear(&self) -> AppResult<()> {
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(test)]
    pub fn set_test_key(&self, key: Vec<u8>) {
        if let Ok(mut state) = self.state.lock() {
            state.key = Some(Zeroizing::new(key));
        }
    }

    #[cfg(test)]
    pub fn test_path(&self, day: u64) -> PathBuf {
        self.path(&day_name(day))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_days() {
        assert_eq!(day_name(0), "1970-01-01");
        assert_eq!(day_name(20_752), "2026-10-26");
        assert_eq!(day_name(11_016), "2000-02-29");
        for day in [0, 59, 60, 11_016, 20_752, 30_000] {
            assert_eq!(day_number(&day_name(day)), Some(day));
        }
    }

    #[test]
    fn sealed_logs_keep_records_until_unlocked() {
        let dir = std::env::temp_dir().join(format!("fran-daylog-{}", uuid::Uuid::new_v4()));
        let log = DayLog::new(dir.clone(), b"FRDBTST1", "test:key", "test log");
        log.set_test_key(vec![3u8; KEY_LEN]);
        let day = 20_752 * DAY_MS;
        log.append(day, &"before").unwrap();

        log.seal();
        assert!(!log.is_unlocked());
        log.append(day + 1, &"while locked").unwrap();
        assert!(log.read_days::<String>(day, day).is_err());

        log.set_test_key(vec![3u8; KEY_LEN]);
        let cipher = log.cipher().unwrap();
        let pending = std::mem::take(&mut log.state.lock().unwrap().pending);
        for (at, plaintext) in pending {
            log.write(&cipher, at, &plaintext).unwrap();
        }
        let records: Vec<String> = log.read_days(day, day).unwrap();
        assert_eq!(records, ["before", "while locked"]);
        log.clear().unwrap();
    }

    #[test]
    fn unsealed_without_a_key_refuses() {
        let log = DayLog::new(std::env::temp_dir().join("fran-daylog-never"), b"FRDBTST1", "test:key", "test log");
        assert!(log.append(0, &"x").is_err());
    }
}
