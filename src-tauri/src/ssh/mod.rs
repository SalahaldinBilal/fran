pub mod config_import;
pub mod forwards;
pub mod keys;
pub mod known_hosts;
pub mod policy;
pub mod proxy;
pub mod route;
pub mod sftp;
pub mod socks;
pub mod terminal;
pub mod terminal_log;

use std::{
    borrow::Cow,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::connections::SecretSlot;
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::forward::LocalForward;
use crate::vpn::{
    VpnRelay,
    manager::{self as vpn_manager, VpnLease, VpnLeg},
};
use known_hosts::KnownHosts;
use policy::ChannelPolicy;
use route::{Hop, HopAuth, SshRoute};

pub const SSH_PASSWORD_SLOT: &str = "sshPassword";
pub const SSH_PASSPHRASE_SLOT: &str = "sshKeyPassphrase";

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SshAuthMethod {
    #[default]
    Password,
    PublicKey,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshOptions {
    /// A saved SSH host. When set, its route and identity are used and the fields below are ignored.
    /// An empty id means saved-host mode with no host picked yet.
    pub host_id: Option<String>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuthMethod,
    pub key_file: String,
    /// A Unix socket or Windows pipe for the agent. Empty means the usual one for the OS.
    pub agent_socket: String,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            host_id: None,
            host: String::new(),
            port: 22,
            user: String::new(),
            auth: SshAuthMethod::Password,
            key_file: String::new(),
            agent_socket: String::new(),
        }
    }
}

impl SshOptions {
    pub fn password_slot() -> SecretSlot {
        SecretSlot::new(SSH_PASSWORD_SLOT, "SSH password")
    }

    pub fn passphrase_slot() -> SecretSlot {
        SecretSlot::new(SSH_PASSPHRASE_SLOT, "SSH key passphrase")
    }

    pub fn uses_saved_host(&self) -> bool {
        self.host_id.is_some()
    }

    /// A saved host's secrets belong to its identity, key and proxy, so the connection asks for none.
    pub fn required_secrets(&self) -> Vec<SecretSlot> {
        match self.auth {
            _ if self.uses_saved_host() => Vec::new(),
            SshAuthMethod::Password => vec![Self::password_slot()],
            SshAuthMethod::PublicKey | SshAuthMethod::Agent => Vec::new(),
        }
    }

    /// The passphrase is only asked for once the key turns out to be encrypted.
    pub fn optional_secrets(&self) -> Vec<SecretSlot> {
        match self.auth {
            _ if self.uses_saved_host() => Vec::new(),
            SshAuthMethod::Password | SshAuthMethod::Agent => Vec::new(),
            SshAuthMethod::PublicKey => vec![Self::passphrase_slot()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// When the key was trusted, Unix milliseconds. Missing on keys trusted before this was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<i64>,
}

/// Which hop of a longer route a host key prompt is about.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HopPosition {
    pub index: usize,
    pub total: usize,
    pub label: String,
    pub target: String,
}

/// What a driver needs to reach its server: the trusted keys, the SSH route and the VPN resolved for this connect.
pub struct SshAccess<'a> {
    pub known_hosts: &'a KnownHosts,
    pub route: Option<&'a SshRoute>,
    /// For a direct TCP connection. A route carries its own.
    pub vpn: Option<&'a VpnLeg>,
}

impl<'a> SshAccess<'a> {
    pub fn direct(known_hosts: &'a KnownHosts) -> Self {
        Self { known_hosts, route: None, vpn: None }
    }

    pub async fn tunnel(&self, target_host: &str, target_port: u16, timeout: Duration) -> AppResult<SshTunnel> {
        let route = self.route.ok_or_else(|| AppError::ssh("This connection has no SSH route"))?;
        SshTunnel::open(route, self.known_hosts, target_host, target_port, 0, timeout).await
    }

    /// A local port into the VPN for a direct TCP connection, or None when it doesn't use one.
    pub async fn vpn_relay(&self, host: &str, port: u16, timeout: Duration) -> AppResult<Option<VpnRelay>> {
        match self.vpn {
            Some(leg) => Ok(Some(VpnRelay::open(leg, host, port, timeout).await?)),
            None => Ok(None),
        }
    }
}

const WEAK_KEX: &[&str] = &["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"];
const WEAK_HOST_KEYS: &[&str] = &["ssh-rsa", "ssh-dss"];

fn weak_cipher(name: &str) -> bool {
    name.contains("cbc") || name.contains("3des") || name.contains("arcfour") || name == "none"
}

/// russh's defaults without SHA-1 key exchange, SHA-1 RSA signatures, DSA or CBC ciphers.
pub fn preferred() -> russh::Preferred {
    let base = russh::Preferred::default();
    russh::Preferred {
        kex: Cow::Owned(base.kex.iter().filter(|name| !WEAK_KEX.contains(&name.as_ref())).cloned().collect()),
        key: Cow::Owned(base.key.iter().filter(|algorithm| !WEAK_HOST_KEYS.contains(&algorithm.as_str())).cloned().collect()),
        cipher: Cow::Owned(base.cipher.iter().filter(|name| !weak_cipher(name.as_ref())).cloned().collect()),
        ..base
    }
}

pub struct HostKeyCheck {
    host: String,
    port: u16,
    known: Option<HostKeyInfo>,
    position: Option<HopPosition>,
    rejection: Arc<Mutex<Option<AppError>>>,
    policy: Arc<ChannelPolicy>,
}

fn disconnect_message(reason: &client::DisconnectReason<russh::Error>) -> Option<String> {
    match reason {
        client::DisconnectReason::ReceivedDisconnect(info) if info.message.trim().is_empty() => None,
        client::DisconnectReason::ReceivedDisconnect(info) => Some(format!("The server closed the connection: {}", info.message.trim())),
        client::DisconnectReason::Error(russh::Error::KeepaliveTimeout) => Some("The server stopped answering keepalives".to_string()),
        client::DisconnectReason::Error(error) => Some(format!("The connection dropped: {error}")),
    }
}

// russh accepts every channel a server opens by default. Only the ones this connection asked for are let through.
impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.policy.open_forwarded(channel, connected_port, reply);
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.policy.open_agent(channel, reply);
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _socket_path: &str,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _socket_path: &str,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn disconnected(&mut self, reason: client::DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        self.policy.mark_closed(disconnect_message(&reason));
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            client::DisconnectReason::Error(error) => Err(error),
        }
    }

    async fn check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let public_key = server_public_key.public_key();
        let key = HostKeyInfo {
            host: self.host.clone(),
            port: self.port,
            algorithm: public_key.algorithm().to_string(),
            fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
            added: None,
        };

        let rejection = match &self.known {
            Some(known) if known.fingerprint == key.fingerprint => return Ok(true),
            Some(known) => AppError::new(
                format!(
                    "The SSH host key for {}:{} changed. This can mean someone is intercepting the connection.",
                    key.host, key.port
                ),
                ErrorDetail::HostKeyChanged {
                    known_fingerprint: known.fingerprint.clone(),
                    known_algorithm: known.algorithm.clone(),
                    known_added: known.added,
                    key,
                    hop: self.position.clone(),
                },
            ),
            None => AppError::new(
                format!("The SSH host {}:{} is not trusted yet", key.host, key.port),
                ErrorDetail::UnknownHostKey {
                    openssh_trusted: known_hosts::openssh_trusts(&key.host, key.port, &key.fingerprint),
                    key,
                    hop: self.position.clone(),
                },
            ),
        };

        if let Ok(mut slot) = self.rejection.lock() {
            *slot = Some(rejection);
        }
        Ok(false)
    }
}

pub type SshHandle = client::Handle<HostKeyCheck>;

/// Every hop of a route, outermost first. Dropping it disconnects them, innermost first.
pub struct SshConnection {
    handles: Vec<Arc<SshHandle>>,
    policy: Arc<ChannelPolicy>,
    vpn: Option<VpnLease>,
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        let handles: Vec<_> = self.handles.drain(..).rev().collect();
        let vpn = self.vpn.take();
        if handles.is_empty() {
            return;
        }
        tauri::async_runtime::spawn(async move {
            for handle in handles {
                let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
            }
            drop(vpn);
        });
    }
}

impl SshConnection {
    pub async fn open(route: &SshRoute, known_hosts: &KnownHosts, timeout: Duration) -> AppResult<Self> {
        Self::open_with(route, known_hosts, timeout, Arc::new(ChannelPolicy::default())).await
    }

    /// The policy applies to the last hop. Jump hosts refuse every channel their server opens.
    pub async fn open_with(route: &SshRoute, known_hosts: &KnownHosts, timeout: Duration, policy: Arc<ChannelPolicy>) -> AppResult<Self> {
        // The VPN has its own connect timeout, so a slow VPN doesn't use up the SSH one.
        let lease = match &route.vpn {
            Some(leg) => Some(leg.acquire().await?),
            None => None,
        };
        match tokio::time::timeout(timeout, Self::open_hops(route, known_hosts, policy, lease)).await {
            Ok(result) => result,
            Err(_) => Err(AppError::ssh("Timed out connecting to the SSH server")),
        }
    }

    async fn open_hops(route: &SshRoute, known_hosts: &KnownHosts, policy: Arc<ChannelPolicy>, mut lease: Option<VpnLease>) -> AppResult<Self> {
        if route.hops.is_empty() {
            return Err(AppError::ssh("The SSH route is empty"));
        }

        let total = route.hops.len();
        let target = route.hops[total - 1].label.clone();
        let mut connection = Self { handles: Vec::with_capacity(total), policy: policy.clone(), vpn: None };

        for (index, hop) in route.hops.iter().enumerate() {
            let position = (total > 1).then(|| HopPosition {
                index: index + 1,
                total,
                label: hop.label.clone(),
                target: target.clone(),
            });
            let hop_policy = if index + 1 == total { policy.clone() } else { Arc::new(ChannelPolicy::default()) };

            let handle = match connection.handles.last() {
                None if route.vpn.is_some() => {
                    let leg = route.vpn.as_ref().unwrap();
                    let lease = lease.take().unwrap();
                    // A proxy on hop 1 is reached through the VPN too.
                    let (host, port) = match &route.proxy {
                        Some(proxy) => (proxy.host.as_str(), proxy.port),
                        None => (hop.host.as_str(), hop.port),
                    };
                    let mut stream = lease
                        .connect(host, port, vpn_manager::connect_timeout())
                        .await
                        .map_err(|error| AppError::ssh(format!("Couldn't reach {host}:{port} through VPN {}: {error}", leg.label)))?;
                    if let Some(proxy) = &route.proxy {
                        proxy::handshake(&mut stream, proxy, &hop.host, hop.port).await?;
                    }
                    connection.vpn = Some(lease);
                    connect_hop(stream, hop, position, known_hosts, hop_policy).await?
                }
                None => {
                    let stream = match &route.proxy {
                        Some(proxy) => proxy::connect(proxy, &hop.host, hop.port).await?,
                        None => {
                            let stream = TcpStream::connect((hop.host.as_str(), hop.port)).await.map_err(|error| {
                                AppError::ssh(format!("Couldn't reach {}:{}: {error}", hop.host, hop.port))
                            })?;
                            stream.set_nodelay(true)?;
                            stream
                        }
                    };
                    connect_hop(stream, hop, position, known_hosts, hop_policy).await?
                }
                Some(previous) => {
                    let channel = previous
                        .channel_open_direct_tcpip(hop.host.clone(), u32::from(hop.port), "127.0.0.1", 0)
                        .await
                        .map_err(|error| {
                            AppError::ssh(format!(
                                "{} couldn't open a connection to {}:{}: {error}",
                                route.hops[index - 1].label,
                                hop.host,
                                hop.port
                            ))
                        })?;
                    connect_hop(channel.into_stream(), hop, position, known_hosts, hop_policy).await?
                }
            };
            connection.handles.push(Arc::new(handle));
        }
        Ok(connection)
    }

    pub fn target(&self) -> Arc<SshHandle> {
        self.handles[self.handles.len() - 1].clone()
    }

    pub fn policy(&self) -> &Arc<ChannelPolicy> {
        &self.policy
    }

    pub fn is_closed(&self) -> bool {
        self.policy.is_closed() || self.handles.iter().any(|handle| handle.is_closed())
    }
}

async fn connect_hop<S>(
    stream: S,
    hop: &Hop,
    position: Option<HopPosition>,
    known_hosts: &KnownHosts,
    policy: Arc<ChannelPolicy>,
) -> AppResult<SshHandle>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let rejection = Arc::new(Mutex::new(None));
    let handler = HostKeyCheck {
        host: hop.host.clone(),
        port: hop.port,
        known: known_hosts.find(&hop.host, hop.port)?,
        position,
        rejection: rejection.clone(),
        policy,
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: (hop.keepalive_secs > 0).then(|| Duration::from_secs(u64::from(hop.keepalive_secs))),
        nodelay: true,
        preferred: preferred(),
        ..Default::default()
    });

    let mut handle = client::connect_stream(config, stream, handler).await.map_err(|error| {
        rejection
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .unwrap_or_else(|| AppError::ssh(format!("SSH connection to {} failed: {error}", hop.label)))
    })?;

    if !authenticate(&mut handle, hop).await? {
        return Err(AppError::ssh(match hop.auth {
            HopAuth::Agent { .. } => format!("{} didn't accept any of the agent's keys for {}", hop.label, hop.user),
            _ => format!("{} rejected the login for {}", hop.label, hop.user),
        }));
    }
    Ok(handle)
}

async fn authenticate(handle: &mut SshHandle, hop: &Hop) -> AppResult<bool> {
    match &hop.auth {
        HopAuth::Password(password) => Ok(handle
            .authenticate_password(&hop.user, password.as_str())
            .await
            .map_err(auth_failed)?
            .success()),
        HopAuth::Key(key) => {
            let hash = rsa_hash(handle).await?;
            Ok(handle
                .authenticate_publickey(&hop.user, PrivateKeyWithHashAlg::new(key.clone(), hash))
                .await
                .map_err(auth_failed)?
                .success())
        }
        HopAuth::Agent { socket } => authenticate_with_agent(handle, &hop.user, socket).await,
    }
}

/// Logs in to a saved host along its route. Missing secrets come back as `secretsRequired` for the prompt.
pub async fn connect_saved_host(
    host_id: &str,
    provided: std::collections::HashMap<String, String>,
    vault: &crate::vault::Vault,
    ssh_store: &crate::ssh_store::SshStore,
    known_hosts: &KnownHosts,
    policy: Arc<ChannelPolicy>,
    timeout: Duration,
) -> AppResult<SshConnection> {
    let filler = crate::secrets::fill::Filler::new(vault, &provided)?;
    let plan = route::RoutePlan::for_host(host_id, ssh_store, &filler)?;
    let secrets =
        crate::connections::prepare::resolve_slots(&filler, vault, None, ssh_store, provided, plan.required_secrets(), plan.optional_secrets())?;
    let route = plan.resolve(&secrets, vault)?;
    SshConnection::open_with(&route, known_hosts, timeout, policy).await.map_err(|error| filler.scrub(error))
}

/// A local port forwarded through SSH to `target_host:target_port`. Dropping it stops the forward.
pub struct SshTunnel {
    forward: LocalForward,
    _connection: SshConnection,
}

impl SshTunnel {
    pub fn local_port(&self) -> u16 {
        self.forward.port
    }

    pub async fn open(
        route: &SshRoute,
        known_hosts: &KnownHosts,
        target_host: &str,
        target_port: u16,
        local_port: u16,
        timeout: Duration,
    ) -> AppResult<Self> {
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, local_port));
        Self::open_on(route, known_hosts, target_host, target_port, listen, timeout).await
    }

    pub async fn open_on(
        route: &SshRoute,
        known_hosts: &KnownHosts,
        target_host: &str,
        target_port: u16,
        listen: SocketAddr,
        timeout: Duration,
    ) -> AppResult<Self> {
        let connection = SshConnection::open(route, known_hosts, timeout).await?;
        let forward = forward_local(connection.target(), target_host, target_port, listen).await?;
        Ok(Self {
            forward,
            _connection: connection,
        })
    }
}

/// Listens on `listen` and sends each connection through a `direct-tcpip` channel to `target_host:target_port`.
pub async fn forward_local(handle: Arc<SshHandle>, target_host: &str, target_port: u16, listen: SocketAddr) -> AppResult<LocalForward> {
    let target_host = target_host.to_string();
    Ok(LocalForward::start_on(listen, move |peer| {
        let handle = handle.clone();
        let target_host = target_host.clone();
        async move {
            let channel = handle
                .channel_open_direct_tcpip(target_host, u32::from(target_port), peer.ip().to_string(), u32::from(peer.port()))
                .await
                .map_err(std::io::Error::other)?;
            Ok(channel.into_stream())
        }
    })
    .await?)
}

fn auth_failed(error: impl std::fmt::Display) -> AppError {
    AppError::ssh(format!("SSH authentication failed: {error}"))
}

async fn rsa_hash(handle: &mut SshHandle) -> AppResult<Option<HashAlg>> {
    Ok(handle
        .best_supported_rsa_hash()
        .await
        .map_err(|error| AppError::ssh(error.to_string()))?
        .flatten())
}

type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

#[cfg(unix)]
async fn connect_agent(socket: &str) -> AppResult<Agent> {
    let path = match socket.trim() {
        "" => std::env::var("SSH_AUTH_SOCK").map_err(|_| {
            AppError::ssh("No SSH agent found: SSH_AUTH_SOCK isn't set. Start ssh-agent, or enter the agent's socket path.")
        })?,
        path => path.to_string(),
    };
    AgentClient::connect_uds(&path)
        .await
        .map(AgentClient::dynamic)
        .map_err(|error| AppError::ssh(format!("Couldn't reach the SSH agent at {path}: {error}")))
}

#[cfg(windows)]
const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Without a pipe name this uses the OpenSSH agent, and Pageant when that isn't running.
#[cfg(windows)]
async fn connect_agent(socket: &str) -> AppResult<Agent> {
    let pipe = socket.trim();
    if !pipe.is_empty() {
        return AgentClient::connect_named_pipe(pipe)
            .await
            .map(AgentClient::dynamic)
            .map_err(|error| AppError::ssh(format!("Couldn't reach the SSH agent at {pipe}: {error}")));
    }

    match AgentClient::connect_named_pipe(OPENSSH_AGENT_PIPE).await {
        Ok(agent) => Ok(agent.dynamic()),
        Err(_) => AgentClient::connect_pageant().await.map(AgentClient::dynamic).map_err(|_| {
            AppError::ssh("No SSH agent is running. Start the OpenSSH Authentication Agent service or Pageant.")
        }),
    }
}

/// Offers each of the agent's keys in turn, like OpenSSH does.
async fn authenticate_with_agent(handle: &mut SshHandle, user: &str, socket: &str) -> AppResult<bool> {
    let mut agent = connect_agent(socket).await?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|error| AppError::ssh(format!("Couldn't read the keys from the SSH agent: {error}")))?;
    if identities.is_empty() {
        return Err(AppError::ssh("The SSH agent has no keys. Add one with ssh-add."));
    }

    let rsa = rsa_hash(handle).await?;
    for identity in identities {
        let hash = if identity.public_key().algorithm().is_rsa() { rsa } else { None };
        let result = match identity {
            AgentIdentity::PublicKey { key, .. } => handle.authenticate_publickey_with(user, key, hash, &mut agent).await,
            AgentIdentity::Certificate { certificate, .. } => {
                handle.authenticate_certificate_with(user, certificate, hash, &mut agent).await
            }
        }
        .map_err(auth_failed)?;

        if result.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_algorithms_are_off() {
        let preferred = preferred();
        for name in preferred.kex.iter() {
            assert!(!WEAK_KEX.contains(&name.as_ref()), "{}", name.as_ref());
            assert!(!name.as_ref().ends_with("-sha1"), "{}", name.as_ref());
        }
        for algorithm in preferred.key.iter() {
            assert!(!WEAK_HOST_KEYS.contains(&algorithm.as_str()), "{}", algorithm.as_str());
        }
        for name in preferred.cipher.iter() {
            assert!(!weak_cipher(name.as_ref()), "{}", name.as_ref());
        }
        assert!(!preferred.kex.is_empty() && !preferred.key.is_empty() && !preferred.cipher.is_empty());
    }

    #[test]
    fn saved_hosts_ask_for_no_connection_secrets() {
        let inline = SshOptions::default();
        assert_eq!(inline.required_secrets(), vec![SshOptions::password_slot()]);

        let saved = SshOptions {
            host_id: Some("h1".to_string()),
            ..Default::default()
        };
        assert!(saved.required_secrets().is_empty());
        assert!(saved.optional_secrets().is_empty());

        let unpicked = SshOptions {
            host_id: Some(String::new()),
            ..Default::default()
        };
        assert!(unpicked.required_secrets().is_empty());
    }
}
