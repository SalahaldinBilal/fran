use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use super::{
    SshConnection, SshTunnel, connect_saved_host, forward_local, known_hosts::KnownHosts, policy::ChannelPolicy,
    route::RoutePlan, socks::SocksServer,
};
use crate::connections::{ConnectionStore, resolve_secrets};
use crate::error::{AppError, AppResult};
use crate::forward::LocalForward;
use crate::ssh_store::{ForwardKind, ForwardRule, SshStore, now_millis};
use crate::vault::Vault;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForwardInfo {
    pub connection_id: String,
    pub all_networks: bool,
    pub local_port: u16,
    pub host: String,
    pub port: u16,
}

#[derive(Default)]
pub struct PortForwards {
    active: Mutex<HashMap<String, (PortForwardInfo, SshTunnel)>>,
}

impl PortForwards {
    fn list(&self) -> Vec<PortForwardInfo> {
        match self.active.lock() {
            Ok(active) => active.values().map(|(info, _)| info.clone()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[tauri::command]
pub async fn start_port_forward(
    store: State<'_, Arc<ConnectionStore>>,
    vault: State<'_, Arc<Vault>>,
    known_hosts: State<'_, Arc<KnownHosts>>,
    ssh_store: State<'_, Arc<SshStore>>,
    forwards: State<'_, PortForwards>,
    connection_id: String,
    local_port: u16,
    all_networks: bool,
    secrets: HashMap<String, String>,
) -> AppResult<PortForwardInfo> {
    if local_port == 0 {
        return Err(AppError::general("Choose a local port"));
    }
    let profile = store.find(&connection_id)?;
    let (ssh, host, port) = profile.driver.ssh_target().ok_or_else(|| {
        AppError::general("Port forwarding needs a connection that uses an SSH tunnel")
    })?;
    let plan = RoutePlan::for_options(ssh, &ssh_store, profile.vpn_id.as_deref())?;
    let mut required = ssh.required_secrets();
    required.extend(plan.required_secrets());
    let mut optional = ssh.optional_secrets();
    optional.extend(plan.optional_secrets());
    let bag = resolve_secrets(&vault, Some(&profile.id), secrets, &required, &optional)?;
    let route = plan.resolve(&bag, &vault)?;

    let address = if all_networks { Ipv4Addr::UNSPECIFIED } else { Ipv4Addr::LOCALHOST };
    let tunnel = SshTunnel::open_on(
        &route,
        &known_hosts,
        host,
        port,
        SocketAddr::from((address, local_port)),
        CONNECT_TIMEOUT,
    )
    .await?;
    let info = PortForwardInfo {
        connection_id: profile.id.clone(),
        all_networks,
        local_port,
        host: host.to_string(),
        port,
    };
    forwards
        .active
        .lock()
        .map_err(|_| AppError::general("Forward lock poisoned"))?
        .insert(profile.id, (info.clone(), tunnel));
    Ok(info)
}

#[tauri::command]
pub fn stop_port_forward(
    forwards: State<'_, PortForwards>,
    connection_id: String,
) -> AppResult<()> {
    forwards
        .active
        .lock()
        .map_err(|_| AppError::general("Forward lock poisoned"))?
        .remove(&connection_id);
    Ok(())
}

#[tauri::command]
pub fn list_port_forwards(forwards: State<'_, PortForwards>) -> Vec<PortForwardInfo> {
    forwards.list()
}

impl PortForwards {
    pub fn stop_all(&self) {
        if let Ok(mut active) = self.active.lock() {
            active.clear();
        }
    }
}

pub const RULE_STOPPED_EVENT: &str = "forward-rule-stopped";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleForwardInfo {
    pub rule_id: String,
    /// Where it listens, as the user would type it. Remote forwards listen on the server.
    pub listen: String,
    pub started: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleStopped {
    rule_id: String,
    reason: Option<String>,
}

// Held only so dropping the rule stops listening.
enum RuleListener {
    Local { _forward: LocalForward },
    Socks { _server: SocksServer },
    Remote,
}

struct RunningRule {
    instance: String,
    info: RuleForwardInfo,
    _listener: RuleListener,
    _connection: SshConnection,
}

/// Saved forward rules that are running. Each has its own SSH connection, so terminals can come and go.
#[derive(Default)]
pub struct RuleForwards {
    running: Mutex<HashMap<String, RunningRule>>,
}

impl RuleForwards {
    fn is_running(&self, rule_id: &str) -> bool {
        self.running.lock().map(|running| running.contains_key(rule_id)).unwrap_or(false)
    }

    pub fn stop_all(&self) {
        if let Ok(mut running) = self.running.lock() {
            running.clear();
        }
    }
}

fn listen_address(all_networks: bool, port: u16) -> SocketAddr {
    SocketAddr::from((if all_networks { Ipv4Addr::UNSPECIFIED } else { Ipv4Addr::LOCALHOST }, port))
}

fn check_rule(rule: &ForwardRule) -> AppResult<()> {
    if rule.listen_port == 0 {
        return Err(AppError::general("Choose the port to listen on"));
    }
    if rule.kind != ForwardKind::Dynamic && (rule.target_host.is_empty() || rule.target_port == 0) {
        return Err(AppError::general("Enter where the forward goes, a host and a port"));
    }
    if rule.kind == ForwardKind::Remote && rule.remote_bind.is_empty() {
        return Err(AppError::general("Enter the address the server listens on"));
    }
    Ok(())
}

#[tauri::command]
pub async fn save_forward_rule(
    ssh_store: State<'_, Arc<SshStore>>,
    rules: State<'_, RuleForwards>,
    mut rule: ForwardRule,
) -> AppResult<ForwardRule> {
    rule.label = rule.label.trim().to_string();
    rule.target_host = rule.target_host.trim().to_string();
    rule.remote_bind = rule.remote_bind.trim().to_string();
    if rule.kind != ForwardKind::Remote {
        rule.remote_bind = "localhost".to_string();
    }
    if rule.kind == ForwardKind::Remote {
        rule.all_networks = false;
    }
    if rule.kind == ForwardKind::Dynamic {
        rule.target_host.clear();
        rule.target_port = 0;
    }
    check_rule(&rule)?;
    if rule.label.is_empty() {
        rule.label = match rule.kind {
            ForwardKind::Dynamic => format!("SOCKS on {}", rule.listen_port),
            _ => format!("{}:{}", rule.target_host, rule.target_port),
        };
    }
    if rule.id.is_empty() {
        rule.id = uuid::Uuid::new_v4().to_string();
    } else if rules.is_running(&rule.id) {
        return Err(AppError::general("Stop this forward before changing it"));
    }

    let saved = rule.clone();
    ssh_store.update(move |file| {
        if file.host(&rule.host_id).is_none() {
            return Err(AppError::not_found("Pick the SSH host the forward goes through"));
        }
        match file.forwards.iter_mut().find(|existing| existing.id == rule.id) {
            Some(existing) => *existing = rule,
            None => file.forwards.push(rule),
        }
        Ok(())
    })?;
    Ok(saved)
}

#[tauri::command]
pub async fn delete_forward_rule(ssh_store: State<'_, Arc<SshStore>>, rules: State<'_, RuleForwards>, id: String) -> AppResult<()> {
    if let Ok(mut running) = rules.running.lock() {
        running.remove(&id);
    }
    ssh_store.update(move |file| {
        file.forwards.retain(|forward| forward.id != id);
        Ok(())
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn start_forward_rule(
    app: AppHandle,
    vault: State<'_, Arc<Vault>>,
    known_hosts: State<'_, Arc<KnownHosts>>,
    ssh_store: State<'_, Arc<SshStore>>,
    rules: State<'_, RuleForwards>,
    id: String,
    secrets: HashMap<String, String>,
) -> AppResult<RuleForwardInfo> {
    let rule = ssh_store.read(|file| file.forward(&id).cloned())?.ok_or_else(|| AppError::not_found("That forward was deleted"))?;
    check_rule(&rule)?;
    if rules.is_running(&rule.id) {
        return Err(AppError::general(format!("{} is already running", rule.label)));
    }

    let policy = Arc::new(ChannelPolicy::default());
    if rule.kind == ForwardKind::Remote {
        policy.add_remote_target(u32::from(rule.listen_port), rule.target_host.clone(), rule.target_port);
    }
    let connection =
        connect_saved_host(&rule.host_id, secrets, &vault, &ssh_store, &known_hosts, policy.clone(), CONNECT_TIMEOUT).await?;

    let (listener, listen) = match rule.kind {
        ForwardKind::Local => {
            let address = listen_address(rule.all_networks, rule.listen_port);
            let forward = forward_local(connection.target(), &rule.target_host, rule.target_port, address).await?;
            (RuleListener::Local { _forward: forward }, address.to_string())
        }
        ForwardKind::Dynamic => {
            let address = listen_address(rule.all_networks, rule.listen_port);
            let server = SocksServer::start(address, connection.target()).await?;
            (RuleListener::Socks { _server: server }, address.to_string())
        }
        ForwardKind::Remote => {
            connection
                .target()
                .tcpip_forward(rule.remote_bind.clone(), u32::from(rule.listen_port))
                .await
                .map_err(|error| {
                    AppError::ssh(format!("The server refused to listen on {}:{}: {error}", rule.remote_bind, rule.listen_port))
                })?;
            (RuleListener::Remote, format!("{}:{}", rule.remote_bind, rule.listen_port))
        }
    };

    let instance = uuid::Uuid::new_v4().to_string();
    let info = RuleForwardInfo { rule_id: rule.id.clone(), listen, started: now_millis() };
    rules.running.lock().map_err(|_| AppError::general("Forward lock poisoned"))?.insert(
        rule.id.clone(),
        RunningRule { instance: instance.clone(), info: info.clone(), _listener: listener, _connection: connection },
    );

    let rule_id = rule.id;
    tauri::async_runtime::spawn(async move {
        policy.wait_closed().await;
        let removed = app.state::<RuleForwards>().running.lock().ok().and_then(|mut running| {
            match running.get(&rule_id) {
                Some(current) if current.instance == instance => running.remove(&rule_id),
                _ => None,
            }
        });
        if removed.is_some() {
            let _ = app.emit(RULE_STOPPED_EVENT, RuleStopped { rule_id, reason: policy.close_reason() });
        }
    });
    Ok(info)
}

#[tauri::command]
pub fn stop_forward_rule(rules: State<'_, RuleForwards>, id: String) -> AppResult<()> {
    rules.running.lock().map_err(|_| AppError::general("Forward lock poisoned"))?.remove(&id);
    Ok(())
}

#[tauri::command]
pub fn list_running_forward_rules(rules: State<'_, RuleForwards>) -> Vec<RuleForwardInfo> {
    match rules.running.lock() {
        Ok(running) => running.values().map(|rule| rule.info.clone()).collect(),
        Err(_) => Vec::new(),
    }
}
