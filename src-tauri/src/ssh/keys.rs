use std::{fs, path::Path};

use russh::keys::ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use russh::keys::ssh_key::{EcdsaCurve, LineEnding};
use russh::keys::{HashAlg, PrivateKey, PublicKey, decode_secret_key};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::config_import::expand_home;
use crate::error::{AppError, AppResult};

const RSA_BITS: usize = 4096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa4096,
}

fn key_error(error: impl std::fmt::Display) -> AppError {
    AppError::ssh(format!("Key error: {error}"))
}

pub fn generate(algorithm: KeyAlgorithm, comment: &str) -> AppResult<PrivateKey> {
    let mut rng = rand::rng();
    let data = match algorithm {
        KeyAlgorithm::Ed25519 => KeypairData::from(Ed25519Keypair::random(&mut rng)),
        KeyAlgorithm::EcdsaP256 => KeypairData::from(EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256).map_err(key_error)?),
        KeyAlgorithm::Rsa4096 => KeypairData::from(RsaKeypair::random(&mut rng, RSA_BITS).map_err(key_error)?),
    };
    PrivateKey::new(data, comment).map_err(key_error)
}

pub struct PublicInfo {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
}

pub fn algorithm_label(key: &PublicKey) -> String {
    match key.algorithm().as_str() {
        "ssh-ed25519" => "Ed25519".to_string(),
        "ecdsa-sha2-nistp256" => "ECDSA P-256".to_string(),
        "ecdsa-sha2-nistp384" => "ECDSA P-384".to_string(),
        "ecdsa-sha2-nistp521" => "ECDSA P-521".to_string(),
        "ssh-rsa" => "RSA".to_string(),
        other => other.to_string(),
    }
}

pub fn describe(key: &PublicKey) -> AppResult<PublicInfo> {
    Ok(PublicInfo {
        algorithm: algorithm_label(key),
        public_key: key.to_openssh().map_err(key_error)?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// Unencrypted OpenSSH text, for the vault. The vault itself is the encryption.
pub fn to_vault_text(key: &PrivateKey) -> AppResult<Zeroizing<String>> {
    key.to_openssh(LineEnding::LF).map_err(key_error)
}

pub fn from_vault_text(text: &str) -> AppResult<PrivateKey> {
    decode_secret_key(text, None).map_err(key_error)
}

fn read_text(path: &str) -> AppResult<Zeroizing<String>> {
    let expanded = expand_home(path);
    fs::read_to_string(&expanded)
        .map(Zeroizing::new)
        .map_err(|error| AppError::general(format!("Couldn't read {path}: {error}")))
}

/// The whole key, decrypted. OpenSSH, PKCS#8 and PKCS#1 files work.
pub fn read_private(path: &str, passphrase: Option<&str>) -> AppResult<PrivateKey> {
    parse_private(&read_text(path)?, passphrase, path)
}

/// A pasted private key, or a file's text. `what` names it in errors.
pub fn parse_private(text: &str, passphrase: Option<&str>, what: &str) -> AppResult<PrivateKey> {
    let text = text.trim();
    match decode_secret_key(text, passphrase.filter(|value| !value.is_empty())) {
        Ok(key) => Ok(key),
        Err(_) if passphrase.is_none_or(str::is_empty) && is_encrypted(text) => Err(AppError::general(
            "This key has a passphrase. Enter it to copy the key into the vault.",
        )),
        Err(error) => Err(AppError::general(format!("{what} isn't a private key Fran can read: {error}"))),
    }
}

fn is_encrypted(text: &str) -> bool {
    match PrivateKey::from_openssh(text) {
        Ok(key) => key.is_encrypted(),
        Err(_) => text.contains("ENCRYPTED"),
    }
}

/// The public half of a key file, without its passphrase. Falls back to the `.pub` file next to it.
pub fn read_public(path: &str) -> AppResult<PublicKey> {
    let text = read_text(path)?;
    if let Ok(key) = PrivateKey::from_openssh(text.as_str()) {
        return Ok(key.public_key().clone());
    }
    if let Ok(key) = decode_secret_key(&text, None) {
        return Ok(key.public_key().clone());
    }

    let public_path = format!("{}.pub", expand_home(path));
    match fs::read_to_string(Path::new(&public_path)) {
        Ok(public) => PublicKey::from_openssh(public.trim()).map_err(key_error),
        Err(_) => Err(AppError::general(format!(
            "{path} is encrypted in a format whose public half can't be read, and there's no {path}.pub next to it"
        ))),
    }
}

/// OpenSSH text protected with `passphrase`.
pub fn export(key: &PrivateKey, passphrase: &str) -> AppResult<Zeroizing<String>> {
    if passphrase.is_empty() {
        return Err(AppError::general("Choose a passphrase for the exported key"));
    }
    let encrypted = key.encrypt(&mut rand::rng(), passphrase).map_err(key_error)?;
    encrypted.to_openssh(LineEnding::LF).map_err(key_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_the_vault_text() {
        for algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP256] {
            let key = generate(algorithm, "test@fran").unwrap();
            let text = to_vault_text(&key).unwrap();
            let back = from_vault_text(&text).unwrap();
            assert_eq!(back.public_key().fingerprint(HashAlg::Sha256), key.public_key().fingerprint(HashAlg::Sha256));
            let info = describe(key.public_key()).unwrap();
            assert!(info.public_key.ends_with("test@fran"), "{}", info.public_key);
            assert!(info.fingerprint.starts_with("SHA256:"));
        }
    }

    #[test]
    fn exported_keys_need_the_passphrase() {
        let key = generate(KeyAlgorithm::Ed25519, "export").unwrap();
        assert!(export(&key, "").is_err());

        let text = export(&key, "correct horse").unwrap();
        let dir = std::env::temp_dir().join(format!("fran-key-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id_test");
        fs::write(&path, text.as_bytes()).unwrap();
        let path = path.to_string_lossy().to_string();

        assert!(read_private(&path, None).unwrap_err().message.contains("passphrase"));
        assert!(read_private(&path, Some("wrong")).is_err());
        let opened = read_private(&path, Some("correct horse")).unwrap();
        assert_eq!(opened.public_key().fingerprint(HashAlg::Sha256), key.public_key().fingerprint(HashAlg::Sha256));
        assert_eq!(read_public(&path).unwrap().fingerprint(HashAlg::Sha256), key.public_key().fingerprint(HashAlg::Sha256));
        fs::remove_dir_all(dir).unwrap();
    }
}
