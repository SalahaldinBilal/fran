use base64ct::{Base64, Encoding};
use ring::{
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, RsaEncoding, RsaKeyPair,
    },
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

const MAX_PEM: usize = 256 * 1024;
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
#[cfg(test)]
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

pub struct PemBlock {
    pub label: String,
    pub encrypted: bool,
    pub der: Zeroizing<Vec<u8>>,
}

/// Every PEM block in `text`. Anything outside the blocks is skipped.
pub fn pem_blocks(text: &str) -> AppResult<Vec<PemBlock>> {
    if text.len() > MAX_PEM {
        return Err(AppError::general("That PEM text is too long"));
    }
    let mut blocks = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|rest| rest.strip_suffix("-----")) else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut body = Zeroizing::new(String::new());
        let mut encrypted = false;
        let mut closed = false;
        for line in lines.by_ref() {
            if line == end {
                closed = true;
                break;
            }
            if line.contains(':') {
                encrypted |= line.contains("ENCRYPTED");
                continue;
            }
            body.push_str(line);
        }
        if !closed {
            return Err(AppError::general(format!("The {label} block isn't closed")));
        }
        let der = Base64::decode_vec(&body).map_err(|_| AppError::general(format!("The {label} block isn't valid base64")))?;
        blocks.push(PemBlock { label: label.to_string(), encrypted, der: Zeroizing::new(der) });
    }
    Ok(blocks)
}

pub fn to_pem(label: &str, der: &[u8]) -> String {
    let encoded = Zeroizing::new(Base64::encode_string(der));
    let mut text = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        text.push('\n');
    }
    text.push_str(&format!("-----END {label}-----\n"));
    text
}

/// Certificates re-encoded from their DER, so the text can't carry anything else.
pub fn clean_certificates(text: &str, what: &str) -> AppResult<String> {
    let blocks = pem_blocks(text)?;
    let certs: Vec<_> = blocks.iter().filter(|block| block.label == "CERTIFICATE").collect();
    if certs.is_empty() {
        return Err(AppError::general(format!("The {what} has no certificate in it")));
    }
    for cert in &certs {
        certificate_summary(&cert.der).map_err(|_| AppError::general(format!("The {what} isn't a certificate Fran can read")))?;
    }
    Ok(certs.iter().map(|cert| to_pem("CERTIFICATE", &cert.der)).collect())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertSummary {
    pub subject: String,
    /// As written in the certificate, `YYYY-MM-DD`.
    pub not_after: String,
}

pub fn certificate_summaries(text: &str) -> Vec<CertSummary> {
    pem_blocks(text)
        .unwrap_or_default()
        .iter()
        .filter(|block| block.label == "CERTIFICATE")
        .filter_map(|block| certificate_summary(&block.der).ok())
        .collect()
}

pub fn certificate_summary(der: &[u8]) -> Result<CertSummary, ()> {
    let mut outer = Der::new(der);
    let mut cert = Der::new(outer.expect(0x30)?);
    let mut tbs = Der::new(cert.expect(0x30)?);
    if tbs.peek() == Some(0xa0) {
        tbs.read()?;
    }
    tbs.expect(0x02)?;
    tbs.expect(0x30)?;
    tbs.expect(0x30)?;
    let mut validity = Der::new(tbs.expect(0x30)?);
    validity.read()?;
    let (tag, not_after) = validity.read()?;
    let subject = common_name(tbs.expect(0x30)?).unwrap_or_else(|| "no common name".to_string());
    Ok(CertSummary { subject, not_after: der_date(tag, not_after).ok_or(())? })
}

fn common_name(name: &[u8]) -> Option<String> {
    let mut sets = Der::new(name);
    while let Ok((_, set)) = sets.read() {
        let mut set = Der::new(set);
        while let Ok((_, pair)) = set.read() {
            let mut pair = Der::new(pair);
            let oid = pair.expect(0x06).ok()?;
            let (_, value) = pair.read().ok()?;
            if oid == OID_COMMON_NAME {
                return Some(String::from_utf8_lossy(value).to_string());
            }
        }
    }
    None
}

fn der_date(tag: u8, value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let short: u32 = text.get(0..2)?.parse().ok()?;
            (if short >= 50 { 1900 + short } else { 2000 + short }, text.get(2..)?)
        }
        0x18 => (text.get(0..4)?.parse().ok()?, text.get(4..)?),
        _ => return None,
    };
    Some(format!("{year:04}-{}-{}", rest.get(0..2)?, rest.get(2..4)?))
}

struct Der<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn read(&mut self) -> Result<(u8, &'a [u8]), ()> {
        let tag = *self.bytes.get(self.pos).ok_or(())?;
        let first = *self.bytes.get(self.pos + 1).ok_or(())?;
        let mut at = self.pos + 2;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(());
            }
            let mut len = 0usize;
            for _ in 0..count {
                len = (len << 8) | usize::from(*self.bytes.get(at).ok_or(())?);
                at += 1;
            }
            len
        };
        let end = at.checked_add(len).filter(|end| *end <= self.bytes.len()).ok_or(())?;
        self.pos = end;
        Ok((tag, &self.bytes[at..end]))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8], ()> {
        match self.read()? {
            (found, content) if found == tag => Ok(content),
            _ => Err(()),
        }
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|byte| *byte == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// SEC1 `EC PRIVATE KEY` wrapped as PKCS#8, which is all ring reads.
fn sec1_to_pkcs8(sec1: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
    let bad = || AppError::general("The EC key can't be read");
    let mut outer = Der::new(sec1);
    let mut key = Der::new(outer.expect(0x30).map_err(|_| bad())?);
    key.expect(0x02).map_err(|_| bad())?;
    key.expect(0x04).map_err(|_| bad())?;
    let mut curve = None;
    while let Ok((tag, content)) = key.read() {
        if tag == 0xa0 {
            curve = Der::new(content).expect(0x06).ok();
        }
    }
    let curve = curve.ok_or_else(|| AppError::general("The EC key doesn't say which curve it's on"))?;

    let mut algorithm = der_tlv(0x06, OID_EC_PUBLIC_KEY);
    algorithm.extend(der_tlv(0x06, curve));
    let mut body = der_tlv(0x02, &[0]);
    body.extend(der_tlv(0x30, &algorithm));
    body.extend(der_tlv(0x04, sec1));
    Ok(Zeroizing::new(der_tlv(0x30, &body)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

pub enum ClientKey {
    Rsa(RsaKeyPair),
    Ec { pkcs8: Zeroizing<Vec<u8>>, curve: Curve },
    /// OpenVPN 3 asks for these as `ED25519` with the whole message, like the installed OpenVPN does.
    Ed25519(Zeroizing<Vec<u8>>),
}

impl ClientKey {
    pub fn kind(&self) -> String {
        match self {
            Self::Rsa(key) => format!("RSA {}", key.public().modulus_len() * 8),
            Self::Ec { curve: Curve::P256, .. } => "EC P-256".to_string(),
            Self::Ec { curve: Curve::P384, .. } => "EC P-384".to_string(),
            Self::Ed25519(_) => ED25519.to_string(),
        }
    }
}

pub const ED25519: &str = "Ed25519";

fn from_pkcs8(der: &[u8]) -> AppResult<ClientKey> {
    let rng = SystemRandom::new();
    if let Ok(key) = RsaKeyPair::from_pkcs8(der) {
        return Ok(ClientKey::Rsa(key));
    }
    if EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der, &rng).is_ok() {
        return Ok(ClientKey::Ec { pkcs8: Zeroizing::new(der.to_vec()), curve: Curve::P256 });
    }
    if EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, der, &rng).is_ok() {
        return Ok(ClientKey::Ec { pkcs8: Zeroizing::new(der.to_vec()), curve: Curve::P384 });
    }
    if Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).is_ok() {
        return Ok(ClientKey::Ed25519(Zeroizing::new(der.to_vec())));
    }
    Err(AppError::general("The client key isn't RSA, EC P-256, EC P-384 or Ed25519"))
}

/// Reads the one private key in `text`, and returns it with a re-encoded PEM to keep in the vault.
pub fn read_client_key(text: &str) -> AppResult<(ClientKey, Zeroizing<String>)> {
    let blocks = pem_blocks(text)?;
    let mut keys = blocks.iter().filter(|block| block.label.ends_with("PRIVATE KEY"));
    let block = keys.next().ok_or_else(|| AppError::general("There's no private key in it"))?;
    if keys.next().is_some() {
        return Err(AppError::general("There's more than one private key in it"));
    }
    if block.encrypted || block.label == "ENCRYPTED PRIVATE KEY" {
        return Err(AppError::general(
            "The client key is encrypted, and Fran can't read encrypted keys yet. Decrypt it with `openssl pkey -in client.key -out client-plain.key` and paste that.",
        ));
    }
    let pkcs8 = match block.label.as_str() {
        "PRIVATE KEY" => Zeroizing::new(block.der.to_vec()),
        "EC PRIVATE KEY" => sec1_to_pkcs8(&block.der)?,
        "RSA PRIVATE KEY" => {
            let key = RsaKeyPair::from_der(&block.der).map_err(|error| AppError::general(format!("The RSA key can't be read: {error}")))?;
            return Ok((ClientKey::Rsa(key), Zeroizing::new(to_pem("RSA PRIVATE KEY", &block.der))));
        }
        other => return Err(AppError::general(format!("Fran can't read a {other}"))),
    };
    let key = from_pkcs8(&pkcs8)?;
    Ok((key, Zeroizing::new(to_pem("PRIVATE KEY", &pkcs8))))
}

/// What a PKCS#12 file holds: the client key (to the vault), its certificate, and any other certificates in it.
pub struct Pkcs12Bundle {
    pub key: ClientKey,
    pub pem: Zeroizing<String>,
    pub leaf: String,
    pub others: String,
}

pub fn read_pkcs12(bytes: &[u8], password: &str) -> AppResult<Pkcs12Bundle> {
    let store = p12_keystore::KeyStore::from_pkcs12(bytes, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(|_| AppError::general("The PKCS#12 file can't be opened. Check its password."))?;
    let (_, chain) = store.private_key_chain().ok_or_else(|| AppError::general("The PKCS#12 file has no private key in it"))?;
    let der = Zeroizing::new(chain.key().as_der().to_vec());
    let (key, pem) = read_client_key(&Zeroizing::new(to_pem("PRIVATE KEY", &der)))?;
    let mut certs = chain.certs().iter();
    let leaf = certs
        .next()
        .map(|cert| to_pem("CERTIFICATE", cert.as_der()))
        .ok_or_else(|| AppError::general("The PKCS#12 file has no certificate for its key"))?;
    let others = certs.map(|cert| to_pem("CERTIFICATE", cert.as_der())).collect();
    Ok(Pkcs12Bundle { key, pem, leaf, others })
}

fn rsa_sign(key: &RsaKeyPair, padding: &'static dyn RsaEncoding, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(padding, &SystemRandom::new(), data, &mut signature).map_err(|_| "RSA signing failed".to_string())?;
    Ok(signature)
}

/// Answers one of Core's sign requests. `data` is the message itself, Core asks for the hash to apply.
pub fn sign(key: &ClientKey, data_base64: &str, algorithm: &str, hash: &str, salt_len: &str) -> Result<String, String> {
    let data = Zeroizing::new(Base64::decode_vec(data_base64).map_err(|_| "OpenVPN sent data that isn't base64".to_string())?);
    let unsupported = || format!("Fran can't sign {algorithm} with {} and hash '{hash}'", key.kind());
    let rng = SystemRandom::new();
    let signature = match (key, algorithm, hash) {
        (ClientKey::Ec { pkcs8, curve }, "ECDSA", _) => {
            let scheme = match (curve, hash) {
                (Curve::P256, "SHA256") => &ECDSA_P256_SHA256_ASN1_SIGNING,
                (Curve::P384, "SHA384") => &ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => return Err(unsupported()),
            };
            let pair = EcdsaKeyPair::from_pkcs8(scheme, pkcs8, &rng).map_err(|_| "The EC key can't be read".to_string())?;
            pair.sign(&rng, &data).map_err(|_| "ECDSA signing failed".to_string())?.as_ref().to_vec()
        }
        (ClientKey::Rsa(pair), "RSA_PKCS1_PADDING", _) => {
            let padding: &'static dyn RsaEncoding = match hash {
                "SHA256" => &RSA_PKCS1_SHA256,
                "SHA384" => &RSA_PKCS1_SHA384,
                "SHA512" => &RSA_PKCS1_SHA512,
                _ => return Err(unsupported()),
            };
            rsa_sign(pair, padding, &data)?
        }
        (ClientKey::Rsa(pair), "RSA_PKCS1_PSS_PADDING", _) if matches!(salt_len, "" | "digest" | "-1") => {
            let padding: &'static dyn RsaEncoding = match hash {
                "SHA256" => &RSA_PSS_SHA256,
                "SHA384" => &RSA_PSS_SHA384,
                "SHA512" => &RSA_PSS_SHA512,
                _ => return Err(unsupported()),
            };
            rsa_sign(pair, padding, &data)?
        }
        (ClientKey::Ed25519(pkcs8), "ED25519", _) => {
            let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8).map_err(|_| "The Ed25519 key can't be read".to_string())?;
            pair.sign(&data).as_ref().to_vec()
        }
        _ => return Err(unsupported()),
    };
    Ok(Base64::encode_string(&signature))
}

/// An OpenVPN static key or tls-crypt-v2 client key, re-written from its hex or base64 lines.
pub fn clean_tls_key(text: &str, v2: bool) -> AppResult<Zeroizing<String>> {
    let label = if v2 { "OpenVPN tls-crypt-v2 client key" } else { "OpenVPN Static key V1" };
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut lines = text.lines().map(str::trim).skip_while(|line| *line != begin);
    if lines.next().is_none() {
        return Err(AppError::general(format!("That isn't an {label}")));
    }
    let mut body = Zeroizing::new(String::new());
    for line in lines {
        if line == end {
            if body.is_empty() {
                break;
            }
            let mut out = Zeroizing::new(format!("{begin}\n"));
            out.push_str(&body);
            out.push_str(&end);
            out.push('\n');
            return Ok(out);
        }
        let allowed = if v2 {
            line.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '='))
        } else {
            line.chars().all(|character| character.is_ascii_hexdigit())
        };
        if !allowed {
            return Err(AppError::general(format!("The {label} has a line Fran doesn't expect")));
        }
        body.push_str(line);
        body.push('\n');
    }
    Err(AppError::general(format!("The {label} isn't closed")))
}

/// A certificate shaped DER with only the fields Fran reads, unsigned.
#[cfg(test)]
pub fn test_certificate(common_name: &str) -> String {
    let name = der_tlv(0x30, &der_tlv(0x31, &{
        let mut pair = der_tlv(0x06, OID_COMMON_NAME);
        pair.extend(der_tlv(0x0c, common_name.as_bytes()));
        der_tlv(0x30, &pair)
    }));
    let mut validity = der_tlv(0x17, b"250101000000Z");
    validity.extend(der_tlv(0x17, b"350101000000Z"));
    let mut tbs = der_tlv(0xa0, &der_tlv(0x02, &[2]));
    tbs.extend(der_tlv(0x02, &[1]));
    tbs.extend(der_tlv(0x30, &der_tlv(0x06, OID_EC_PUBLIC_KEY)));
    tbs.extend(name.clone());
    tbs.extend(der_tlv(0x30, &validity));
    tbs.extend(name);
    let mut cert = der_tlv(0x30, &tbs);
    cert.extend(der_tlv(0x30, &der_tlv(0x06, OID_EC_PUBLIC_KEY)));
    cert.extend(der_tlv(0x03, &[0]));
    to_pem("CERTIFICATE", &der_tlv(0x30, &cert))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_ASN1, KeyPair, UnparsedPublicKey};

    #[test]
    fn certificate_summary_reads_name_and_expiry() {
        let summaries = certificate_summaries(&test_certificate("vpn.example"));
        assert_eq!(summaries, vec![CertSummary { subject: "vpn.example".to_string(), not_after: "2035-01-01".to_string() }]);
    }

    fn ec_pkcs8() -> Vec<u8> {
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new()).unwrap().as_ref().to_vec()
    }

    #[test]
    fn ec_key_signs_what_core_asks_for() {
        let der = ec_pkcs8();
        let (key, pem) = read_client_key(&to_pem("PRIVATE KEY", &der)).unwrap();
        assert_eq!(key.kind(), "EC P-256");
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));

        let message = b"tls handshake bytes";
        let signature = sign(&key, &Base64::encode_string(message), "ECDSA", "SHA256", "").unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &SystemRandom::new()).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pair.public_key().as_ref())
            .verify(message, &Base64::decode_vec(&signature).unwrap())
            .unwrap();
        assert!(sign(&key, &Base64::encode_string(message), "ECDSA", "SHA384", "").is_err());
        assert!(sign(&key, &Base64::encode_string(message), "RSA_PKCS1_PADDING", "SHA256", "").is_err());
    }

    #[test]
    fn sec1_keys_are_wrapped() {
        let der = ec_pkcs8();
        let mut outer = Der::new(&der);
        let mut body = Der::new(outer.expect(0x30).unwrap());
        body.read().unwrap();
        body.read().unwrap();
        let sec1 = body.expect(0x04).unwrap().to_vec();
        // ring's own PKCS#8 leaves the curve out of the inner key, so add it as OpenSSL writes it.
        let mut inner = Der::new(&sec1);
        let mut fields = Der::new(inner.expect(0x30).unwrap());
        let mut rebuilt = Vec::new();
        while let Ok((tag, content)) = fields.read() {
            rebuilt.extend(der_tlv(tag, content));
            if tag == 0x04 {
                rebuilt.extend(der_tlv(0xa0, &der_tlv(0x06, OID_P256)));
            }
        }
        let openssl_sec1 = der_tlv(0x30, &rebuilt);
        let (key, _) = read_client_key(&to_pem("EC PRIVATE KEY", &openssl_sec1)).unwrap();
        assert_eq!(key.kind(), "EC P-256");
    }

    #[test]
    fn encrypted_and_missing_keys_are_refused() {
        let encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(read_client_key(encrypted).err().unwrap().message.contains("encrypted"));
        assert!(read_client_key("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----").is_err());
        assert!(read_client_key("nothing here").is_err());
    }

    #[test]
    fn ed25519_is_recognized() {
        let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let (key, _) = read_client_key(&to_pem("PRIVATE KEY", der.as_ref())).unwrap();
        assert_eq!(key.kind(), ED25519);
        assert!(sign(&key, "AAAA", "ECDSA", "SHA256", "").is_err());

        let message = b"tls handshake bytes";
        let signature = sign(&key, &Base64::encode_string(message), "ED25519", "", "").unwrap();
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.as_ref()).unwrap();
        UnparsedPublicKey::new(&ring::signature::ED25519, pair.public_key().as_ref())
            .verify(message, &Base64::decode_vec(&signature).unwrap())
            .unwrap();
    }

    #[test]
    fn tls_keys_are_rewritten() {
        let text = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n0123abcd\nef456789\n-----END OpenVPN Static key V1-----\n";
        let clean = clean_tls_key(text, false).unwrap();
        assert_eq!(clean.as_str(), "-----BEGIN OpenVPN Static key V1-----\n0123abcd\nef456789\n-----END OpenVPN Static key V1-----\n");
        assert!(clean_tls_key("-----BEGIN OpenVPN Static key V1-----\n</tls-auth>\nup /bin/sh\n-----END OpenVPN Static key V1-----", false).is_err());
        assert!(clean_tls_key(text, true).is_err());
    }

    #[test]
    fn dates_and_lengths() {
        assert_eq!(der_date(0x17, b"270301120000Z").as_deref(), Some("2027-03-01"));
        assert_eq!(der_date(0x18, b"20510101000000Z").as_deref(), Some("2051-01-01"));
        assert_eq!(der_tlv(0x04, &[0; 200])[..3], [0x04, 0x81, 200]);
        assert!(clean_certificates("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "CA").is_err());
    }
}
