pub mod commands;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::json_store::JsonStore;

pub const SSH_FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshHost {
    pub id: String,
    pub label: String,
    pub group: Option<String>,
    pub color: Option<String>,
    pub host: String,
    pub port: u16,
    pub identity_id: Option<String>,
    /// Saved hosts this one is reached through, outermost first.
    pub jumps: Vec<String>,
    pub proxy_id: Option<String>,
    /// Carries the first hop only. Like the proxy, a host without one takes its first jump's.
    pub vpn_id: Option<String>,
    /// 0 turns keepalives off.
    pub keepalive_secs: u32,
    /// Lets the server use the local SSH agent while a terminal is open.
    pub agent_forwarding: bool,
    /// Lets the server write to the clipboard with OSC 52. It can never read it.
    pub clipboard_write: bool,
    /// Typed at the prompt after login, without pressing Enter.
    pub startup_snippet_id: Option<String>,
}

impl Default for SshHost {
    fn default() -> Self {
        Self {
            id: String::new(),
            label: String::new(),
            group: None,
            color: None,
            host: String::new(),
            port: 22,
            identity_id: None,
            jumps: Vec::new(),
            proxy_id: None,
            vpn_id: None,
            keepalive_secs: 30,
            agent_forwarding: false,
            clipboard_write: false,
            startup_snippet_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ForwardKind {
    /// A port on this computer to a host the server can reach.
    Local,
    /// A port on the server back to a host this computer can reach.
    Remote,
    /// A SOCKS5 proxy on this computer whose connections leave from the server.
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ForwardRule {
    pub id: String,
    pub label: String,
    pub kind: ForwardKind,
    pub host_id: String,
    /// Local and dynamic: the port on this computer. Remote: the port the server listens on.
    pub listen_port: u16,
    /// Local and dynamic listen on 0.0.0.0 instead of 127.0.0.1.
    pub all_networks: bool,
    /// Remote only: the address the server listens on.
    pub remote_bind: String,
    /// Local: as the server sees it. Remote: as this computer sees it. Unused for dynamic.
    pub target_host: String,
    pub target_port: u16,
}

impl Default for ForwardRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            label: String::new(),
            kind: ForwardKind::Local,
            host_id: String::new(),
            listen_port: 0,
            all_networks: false,
            remote_bind: "localhost".to_string(),
            target_host: String::new(),
            target_port: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum IdentityAuth {
    Password,
    #[serde(rename_all = "camelCase")]
    Key { key_id: String },
    /// An empty socket means the usual agent for the OS.
    Agent { socket: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default)]
    pub id: String,
    pub label: String,
    pub user: String,
    pub auth: IdentityAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum KeyStorage {
    /// The private key is in the vault as OpenSSH text, without a passphrase.
    Vault,
    /// Read from disk on each connect.
    File { path: String },
}

/// Only the public half. Private key material is never in this file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyMeta {
    pub id: String,
    pub label: String,
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub storage: KeyStorage,
    /// Unix milliseconds.
    pub created: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProxyKind {
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proxy {
    #[serde(default)]
    pub id: String,
    pub label: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// Empty means the proxy takes no login.
    #[serde(default)]
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshFile {
    pub version: u32,
    pub hosts: Vec<SshHost>,
    pub identities: Vec<Identity>,
    pub keys: Vec<KeyMeta>,
    pub proxies: Vec<Proxy>,
    pub forwards: Vec<ForwardRule>,
    /// Host groups in the order Home shows them. Groups missing here come after, by name.
    pub group_order: Vec<String>,
}

impl Default for SshFile {
    fn default() -> Self {
        Self {
            version: SSH_FILE_VERSION,
            hosts: Vec::new(),
            identities: Vec::new(),
            keys: Vec::new(),
            proxies: Vec::new(),
            forwards: Vec::new(),
            group_order: Vec::new(),
        }
    }
}

impl SshFile {
    pub fn host(&self, id: &str) -> Option<&SshHost> {
        self.hosts.iter().find(|host| host.id == id)
    }

    pub fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.iter().find(|identity| identity.id == id)
    }

    pub fn key(&self, id: &str) -> Option<&KeyMeta> {
        self.keys.iter().find(|key| key.id == id)
    }

    pub fn proxy(&self, id: &str) -> Option<&Proxy> {
        self.proxies.iter().find(|proxy| proxy.id == id)
    }

    pub fn forward(&self, id: &str) -> Option<&ForwardRule> {
        self.forwards.iter().find(|forward| forward.id == id)
    }

    pub fn host_label(&self, id: &str) -> String {
        self.host(id).map(|host| host.label.clone()).unwrap_or_else(|| "a deleted host".to_string())
    }

    /// Hosts that list `id` as a jump host.
    pub fn hosts_jumping_through(&self, id: &str) -> Vec<&SshHost> {
        self.hosts.iter().filter(|host| host.jumps.iter().any(|jump| jump == id)).collect()
    }
}

pub type SshStore = JsonStore<SshFile>;

impl SshStore {
    pub fn snapshot(&self) -> AppResult<SshFile> {
        self.read(Clone::clone)
    }

    pub fn find_host(&self, id: &str) -> AppResult<SshHost> {
        self.read(|file| file.host(id).cloned())?
            .ok_or_else(|| AppError::not_found("That SSH host was deleted"))
    }
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}
