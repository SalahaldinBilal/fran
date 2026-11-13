pub mod commands;

use serde::{Deserialize, Serialize};

use crate::connections::PASSWORD_SLOT;
use crate::error::{AppError, AppResult};
use crate::json_store::JsonStore;
use crate::secrets::{SecretRefs, fill::RefRules};

pub const VPN_FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VpnKind {
    #[default]
    OpenVpn,
    WireGuard,
}

/// A WireGuard profile's one peer and its interface. Addresses keep their prefix, like "10.64.0.2/32".
/// The private key and the preshared key are in the vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct WireGuardSettings {
    /// Worked out from the private key in the vault. None while no key is saved.
    pub public_key: Option<String>,
    pub peer_public_key: String,
    pub allowed_ips: Vec<String>,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub search_domains: Vec<String>,
    pub mtu: Option<u16>,
    pub keepalive_secs: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VpnProto {
    #[default]
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnRemote {
    pub host: String,
    pub port: u16,
    pub proto: VpnProto,
}

impl Default for VpnRemote {
    fn default() -> Self {
        Self { host: String::new(), port: 1194, proto: VpnProto::Udp }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VpnAuth {
    #[default]
    Cert,
    UserPass,
    CertAndUserPass,
}

impl VpnAuth {
    pub fn uses_cert(self) -> bool {
        matches!(self, Self::Cert | Self::CertAndUserPass)
    }

    pub fn uses_password(self) -> bool {
        matches!(self, Self::UserPass | Self::CertAndUserPass)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum VpnChallenge {
    #[default]
    None,
    /// A code asked for with the password on every connect, like a TOTP.
    Static { echo: bool, text: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TlsWrap {
    #[default]
    None,
    Auth { direction: Option<u8> },
    Crypt,
    CryptV2,
}

impl TlsWrap {
    pub fn needs_key(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn tag(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Auth { .. } => Some("tls-auth"),
            Self::Crypt => Some("tls-crypt"),
            Self::CryptV2 => Some("tls-crypt-v2"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteAll {
    #[default]
    FollowServer,
    VpnNetworksOnly,
}

/// Only framing that never compresses. Anything else is refused (VORACLE).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Compress {
    #[default]
    Off,
    LzoNo,
    Stub,
    StubV2,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VerifyNameKind {
    #[default]
    Subject,
    Name,
    NamePrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyName {
    pub name: String,
    pub kind: VerifyNameKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportNote {
    pub option: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ImportInfo {
    pub file_name: String,
    pub used: Vec<String>,
    pub ignored: Vec<ImportNote>,
    pub dropped: Vec<ImportNote>,
    /// Options from the file that only the installed OpenVPN can run.
    pub system_only: Vec<ImportNote>,
    /// Unix milliseconds.
    pub imported_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnProfile {
    pub id: String,
    pub label: String,
    pub group: Option<String>,
    pub color: Option<String>,
    /// Profiles saved before WireGuard have no kind and are OpenVPN.
    pub kind: VpnKind,
    /// The endpoint for WireGuard, always one and UDP.
    pub remotes: Vec<VpnRemote>,
    pub remote_random: bool,
    pub auth: VpnAuth,
    pub user: String,
    pub challenge: VpnChallenge,
    /// Public PEM. The client key is in the vault.
    pub ca: String,
    pub cert: String,
    /// What the client key in the vault is, like "EC P-256". None means no key is saved.
    pub key_kind: Option<String>,
    pub verify_name: Option<VerifyName>,
    pub peer_fingerprints: Vec<String>,
    pub require_server_cert: bool,
    pub tls_wrap: TlsWrap,
    pub ciphers: Vec<String>,
    pub fallback_cipher: Option<String>,
    pub auth_digest: Option<String>,
    pub tls_version_min: Option<String>,
    pub reneg_sec: Option<u32>,
    pub compress: Compress,
    pub route_all: RouteAll,
    pub use_vpn_dns: bool,
    /// Why this profile only works while it's on for the computer. Empty means an own tunnel can run it.
    pub needs_system: Vec<String>,
    /// Options from the import that only the installed OpenVPN gets, each as its name and arguments.
    pub system_options: Vec<Vec<String>>,
    /// The smartcard library, picked in the editor and never taken from a file, since it runs inside OpenVPN as admin.
    pub pkcs11_provider: Option<String>,
    pub imported: Option<ImportInfo>,
    pub wire_guard: WireGuardSettings,
    #[serde(skip_serializing_if = "SecretRefs::is_empty")]
    pub secret_refs: SecretRefs,
}

fn remote_field(path: &str) -> bool {
    let mut parts = path.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("remotes"), Some(index), Some("host" | "port"), None) if index.parse::<usize>().is_ok()
    )
}

/// The server and the login name. Certificates, keys and ciphers have formats a save has to check.
pub const SECRET_RULES: RefRules = RefRules { field: |path| path == "user" || remote_field(path), slot: |slot| slot == PASSWORD_SLOT };

impl Default for VpnProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            label: String::new(),
            group: None,
            color: None,
            kind: VpnKind::OpenVpn,
            remotes: Vec::new(),
            remote_random: false,
            auth: VpnAuth::Cert,
            user: String::new(),
            challenge: VpnChallenge::None,
            ca: String::new(),
            cert: String::new(),
            key_kind: None,
            verify_name: None,
            peer_fingerprints: Vec::new(),
            require_server_cert: true,
            tls_wrap: TlsWrap::None,
            ciphers: Vec::new(),
            fallback_cipher: None,
            auth_digest: None,
            tls_version_min: None,
            reneg_sec: None,
            compress: Compress::Off,
            route_all: RouteAll::FollowServer,
            use_vpn_dns: true,
            needs_system: Vec::new(),
            system_options: Vec::new(),
            pkcs11_provider: None,
            imported: None,
            wire_guard: WireGuardSettings::default(),
            secret_refs: SecretRefs::new(),
        }
    }
}

impl VpnProfile {
    pub fn is_wireguard(&self) -> bool {
        self.kind == VpnKind::WireGuard
    }

    pub fn server_label(&self) -> String {
        match self.remotes.first() {
            Some(remote) => format!("{}:{}", remote.host, remote.port),
            None => "no server".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnFile {
    pub version: u32,
    pub profiles: Vec<VpnProfile>,
    /// Profile groups in Home's order. Groups missing here come after, by name.
    pub group_order: Vec<String>,
}

impl Default for VpnFile {
    fn default() -> Self {
        Self { version: VPN_FILE_VERSION, profiles: Vec::new(), group_order: Vec::new() }
    }
}

impl VpnFile {
    pub fn profile(&self, id: &str) -> Option<&VpnProfile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }
}

pub type VpnStore = JsonStore<VpnFile>;

/// The reasons come from the import notes, worked out again on read so profiles saved under older rules
/// (an Ed25519 key once needed system mode) follow the current ones.
fn current(mut profile: VpnProfile) -> VpnProfile {
    profile.needs_system = crate::vpn::config::system_reasons(&profile);
    profile
}

impl VpnStore {
    pub fn snapshot(&self) -> AppResult<VpnFile> {
        let mut file = self.read(Clone::clone)?;
        file.profiles = file.profiles.into_iter().map(current).collect();
        Ok(file)
    }

    pub fn find(&self, id: &str) -> AppResult<VpnProfile> {
        self.read(|file| file.profile(id).cloned())?
            .map(current)
            .ok_or_else(|| AppError::not_found("That VPN was deleted"))
    }
}
