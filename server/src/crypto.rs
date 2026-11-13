use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use sync_proto::KEY_LEN;

pub const KDF_SALT_LEN: usize = 16;
pub const AUTH_SALT_LEN: usize = 16;
pub const TOTP_SECRET_LEN: usize = 20;
pub const TOTP_STEP_SECS: i64 = 30;
const TOTP_DIGITS: u32 = 6;
const NONCE_LEN: usize = 24;

// The auth key already comes out of Argon2id on the client, so this pass only has to make a stolen table useless.
const AUTH_MEMORY_KIB: u32 = 19 * 1024;
const AUTH_PASSES: u32 = 2;

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes).expect("the OS random source failed");
    bytes
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, data))
}

pub fn new_token() -> String {
    hex::encode(random::<32>())
}

pub fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

pub fn hash_auth_key(key: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(AUTH_MEMORY_KIB, AUTH_PASSES, 1, Some(KEY_LEN)).map_err(|error| error.to_string())?;
    let mut hash = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(key, salt, &mut hash)
        .map_err(|error| error.to_string())?;
    Ok(hash)
}

fn subkey(server_key: &[u8; KEY_LEN], label: &str, data: &[u8]) -> [u8; KEY_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, server_key);
    let mut context = hmac::Context::with_key(&key);
    context.update(label.as_bytes());
    context.update(&[0]);
    context.update(data);
    context.sign().as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
}

// The same email always gets the same salt, so asking for it doesn't show whether the account exists.
pub fn kdf_salt(server_key: &[u8; KEY_LEN], email: &str) -> [u8; KDF_SALT_LEN] {
    subkey(server_key, "kdf-salt", email.as_bytes())[..KDF_SALT_LEN].try_into().expect("16 of 32 bytes")
}

pub fn seal_totp(server_key: &[u8; KEY_LEN], user_id: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(&subkey(server_key, "totp", &[])).map_err(|error| error.to_string())?;
    let nonce_bytes = random::<NONCE_LEN>();
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(&nonce_bytes);
    let sealed = cipher
        .encrypt(&nonce, Payload { msg: secret, aad: user_id.as_bytes() })
        .map_err(|_| "Couldn't protect the two-step secret".to_string())?;
    Ok([nonce_bytes.as_slice(), &sealed].concat())
}

pub fn open_totp(server_key: &[u8; KEY_LEN], user_id: &str, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(&subkey(server_key, "totp", &[])).ok()?;
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(nonce_bytes);
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: user_id.as_bytes() }).ok()
}

pub fn totp_code(secret: &[u8], step: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &(step as u64).to_be_bytes());
    let bytes = tag.as_ref();
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let number = u32::from_be_bytes([bytes[offset] & 0x7f, bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
    format!("{:0width$}", number % 10u32.pow(TOTP_DIGITS), width = TOTP_DIGITS as usize)
}

// One step either side covers a clock that is a little off.
pub fn totp_matching_step(secret: &[u8], code: &str, now: i64) -> Option<i64> {
    let code = code.trim();
    let current = now / TOTP_STEP_SECS;
    (current - 1..=current + 1).find(|step| constant_eq(totp_code(secret, *step).as_bytes(), code.as_bytes()))
}

pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut text = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        text.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    text
}

pub fn invite_code() -> String {
    base32(&random::<20>())
}

pub fn invite_hash(code: &str) -> String {
    sha256_hex(code.trim().to_uppercase().as_bytes())
}

// No 0, O, 1, I or L, so it can be read off a log and typed without guessing.
const SETUP_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const SETUP_LEN: usize = 12;

pub fn setup_code() -> String {
    let mut code = String::new();
    let mut picked = 0;
    while picked < SETUP_LEN {
        // Bytes past the largest multiple of the alphabet's size are dropped, so every character is equally likely.
        let byte = random::<1>()[0];
        if usize::from(byte) >= 256 - 256 % SETUP_ALPHABET.len() {
            continue;
        }
        if picked > 0 && picked % 4 == 0 {
            code.push('-');
        }
        code.push(SETUP_ALPHABET[usize::from(byte) % SETUP_ALPHABET.len()] as char);
        picked += 1;
    }
    code
}

pub fn same_setup_code(typed: &str, code: &str) -> bool {
    let plain = |text: &str| text.chars().filter(|character| !matches!(character, '-' | ' ')).collect::<String>().to_uppercase();
    constant_eq(plain(typed).as_bytes(), plain(code).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_the_rfc_6238_vectors() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / 30), "287082");
        assert_eq!(totp_code(secret, 1111111109 / 30), "081804");
        assert_eq!(totp_code(secret, 20000000000 / 30), "353130");
    }

    #[test]
    fn a_code_from_the_step_before_is_taken_and_an_old_one_is_not() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000;
        let step = now / TOTP_STEP_SECS;
        assert_eq!(totp_matching_step(secret, &totp_code(secret, step - 1), now), Some(step - 1));
        assert_eq!(totp_matching_step(secret, &totp_code(secret, step - 3), now), None);
    }

    #[test]
    fn a_setup_code_is_typed_back_with_any_case_spaces_or_dashes() {
        let code = setup_code();
        assert_eq!(code.len(), 14);
        assert!(code.chars().all(|character| character == '-' || SETUP_ALPHABET.contains(&(character as u8))));
        let typed = code.replace('-', " ").to_lowercase();
        assert!(same_setup_code(&typed, &code));
        assert!(!same_setup_code(&code[..12], &code));
    }

    #[test]
    fn base32_matches_rfc_4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"fo"), "MZXQ");
    }

    #[test]
    fn a_sealed_totp_secret_only_opens_for_its_own_account() {
        let key = [7u8; KEY_LEN];
        let sealed = seal_totp(&key, "user-a", b"secret").unwrap();
        assert_eq!(open_totp(&key, "user-a", &sealed).as_deref(), Some(b"secret".as_slice()));
        assert_eq!(open_totp(&key, "user-b", &sealed), None);
        assert_eq!(open_totp(&[8u8; KEY_LEN], "user-a", &sealed), None);
    }
}
