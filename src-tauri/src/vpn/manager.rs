use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use tauri::ipc::Channel;
use zeroize::Zeroizing;

use super::VpnConn;
use super::config;
use super::frames::{AdapterOptions, Login};
use super::keys::{self, ClientKey};
use super::system::{
    PromptSlots, SystemStart, SystemStream, SystemVpn, VpnPrompt,
    service::{ServiceStart, ServiceVpn},
};
use super::frames::WireGuardStart;
use super::tunnel::{Phase, Tunnel, TunnelStart, TunnelState, WorkerStart};
use super::wireguard;
use crate::vpn_store::RouteAll;
use crate::connections::{PASSWORD_SLOT, PRESHARED_KEY_SLOT, PRIVATE_KEY_SLOT, SecretBag, SecretOwner, SecretSlot, TLS_KEY_SLOT};
use crate::error::{AppError, AppResult};
use crate::secrets::fill::Filler;
use crate::vault::Vault;
use crate::vpn_store::{TlsWrap, VpnChallenge, VpnProfile, VpnStore};

const DEFAULT_IDLE_CLOSE_SECS: u64 = 30;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

static MANAGER: OnceLock<Arc<VpnManager>> = OnceLock::new();

/// Set once at start. Routes and drivers reach tunnels through it without every caller passing it along.
pub fn install(manager: Arc<VpnManager>) {
    let _ = MANAGER.set(manager);
}

pub fn manager() -> AppResult<Arc<VpnManager>> {
    MANAGER.get().cloned().ok_or_else(|| AppError::general("The VPN client isn't running"))
}

/// How long a connect waits for a VPN to come up, from Settings > VPN.
pub fn connect_timeout() -> Duration {
    let secs = MANAGER.get().map(|manager| manager.connect_timeout_secs.load(Ordering::Relaxed)).unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VpnPhase {
    Connecting,
    Up,
    Reconnecting,
    Down,
}

impl From<Phase> for VpnPhase {
    fn from(phase: Phase) -> Self {
        match phase {
            Phase::Connecting => Self::Connecting,
            Phase::Up => Self::Up,
            Phase::Reconnecting => Self::Reconnecting,
            Phase::Down => Self::Down,
        }
    }
}

/// What runs a VPN that's on for the whole computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SystemBackend {
    /// Fran's own VPN service.
    Fran,
    /// The installed OpenVPN 2.6 or newer.
    Openvpn,
}

/// A VPN on for the whole computer, through either backend. Leases, switching and waits treat both the same.
#[derive(Clone)]
pub enum ComputerVpn {
    Installed(Arc<SystemVpn>),
    Fran(Arc<ServiceVpn>),
}

impl ComputerVpn {
    pub fn backend(&self) -> SystemBackend {
        match self {
            Self::Installed(_) => SystemBackend::Openvpn,
            Self::Fran(_) => SystemBackend::Fran,
        }
    }

    pub fn alive(&self) -> bool {
        match self {
            Self::Installed(vpn) => vpn.alive(),
            Self::Fran(vpn) => vpn.alive(),
        }
    }

    pub fn state(&self) -> TunnelState {
        match self {
            Self::Installed(vpn) => vpn.state(),
            Self::Fran(vpn) => vpn.state(),
        }
    }

    pub fn prompt(&self) -> Option<VpnPrompt> {
        match self {
            Self::Installed(vpn) => vpn.prompt(),
            Self::Fran(vpn) => vpn.prompt(),
        }
    }

    pub fn submit(&self, values: HashMap<String, Zeroizing<String>>) {
        match self {
            Self::Installed(vpn) => vpn.submit(values),
            Self::Fran(vpn) => vpn.submit(values),
        }
    }

    pub async fn wait_up(&self, timeout: Duration) -> Result<(), String> {
        match self {
            Self::Installed(vpn) => vpn.wait_up(timeout).await,
            Self::Fran(vpn) => vpn.wait_up(timeout).await,
        }
    }

    pub async fn wait_up_with_prompts(&self, timeout: Duration) -> Result<(), String> {
        match self {
            Self::Installed(vpn) => vpn.wait_up_with_prompts(timeout).await,
            Self::Fran(vpn) => vpn.wait_up_with_prompts(timeout).await,
        }
    }

    pub async fn stop(&self) {
        match self {
            Self::Installed(vpn) => vpn.stop().await,
            Self::Fran(vpn) => vpn.stop().await,
        }
    }

    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<SystemStream> {
        match self {
            Self::Installed(vpn) => vpn.connect(host, port, timeout).await,
            Self::Fran(vpn) => vpn.connect(host, port, timeout).await,
        }
    }

    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Installed(a), Self::Installed(b)) => Arc::ptr_eq(a, b),
            (Self::Fran(a), Self::Fran(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// How to turn a VPN on for the computer, worked out by `VpnLeg::computer_start`.
pub enum ComputerStart {
    Installed(SystemStart),
    Fran(ServiceStart),
}

impl ComputerStart {
    fn label(&self) -> &str {
        match self {
            Self::Installed(start) => &start.label,
            Self::Fran(start) => &start.label,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatus {
    pub profile_id: String,
    pub phase: VpnPhase,
    /// On for the whole computer. Otherwise Fran's own tunnel.
    pub system: bool,
    /// Which program runs it while it's on for the computer.
    pub with: Option<SystemBackend>,
    /// Connections and terminals using this VPN right now.
    pub users: usize,
    pub address: Option<String>,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub last_error: Option<String>,
    /// Something to type in while it's on for the computer, like a new one-time code.
    pub prompt: Option<VpnPrompt>,
}

#[derive(Default)]
struct Slot {
    tunnel: Mutex<Option<Arc<Tunnel>>>,
    system: Mutex<Option<ComputerVpn>>,
    /// While the admin prompt is up and OpenVPN starts, before there's a system VPN to report.
    turning_on: AtomicBool,
    turning_on_with: Mutex<Option<SystemBackend>>,
    starting: tokio::sync::Mutex<()>,
    users: AtomicUsize,
    generation: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// The last login a user brought, so the own tunnel can come back as soon as the computer's VPN is turned off.
    leg: Mutex<Option<VpnLeg>>,
}

impl Slot {
    /// The computer's VPN while it's on, also while it reconnects. New connections wait for it then, so the server never sees two logins.
    fn system_on(&self) -> Option<ComputerVpn> {
        self.system.lock().ok()?.clone().filter(|system| system.alive())
    }

    fn own(&self) -> Option<Arc<Tunnel>> {
        self.tunnel.lock().ok()?.clone().filter(|tunnel| tunnel.alive())
    }

    fn set_error(&self, error: Option<String>) {
        if let Ok(mut last) = self.last_error.lock() {
            *last = error;
        }
    }
}

pub struct VpnManager {
    store: Arc<VpnStore>,
    vault: Arc<Vault>,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    watchers: Mutex<Vec<Channel<Vec<VpnStatus>>>>,
    idle_close_secs: AtomicU64,
    connect_timeout_secs: AtomicU64,
    me: Weak<VpnManager>,
}

fn status_from(profile_id: &str, state: TunnelState, with: Option<SystemBackend>, users: usize, last_error: Option<String>) -> VpnStatus {
    VpnStatus {
        profile_id: profile_id.to_string(),
        phase: state.phase.into(),
        system: with.is_some(),
        with,
        users,
        address: state.address,
        bytes_in: state.bytes_in,
        bytes_out: state.bytes_out,
        last_error: state.error.or(last_error),
        prompt: None,
    }
}

impl VpnManager {
    pub fn new(store: Arc<VpnStore>, vault: Arc<Vault>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            store,
            vault,
            slots: Mutex::new(HashMap::new()),
            watchers: Mutex::new(Vec::new()),
            idle_close_secs: AtomicU64::new(DEFAULT_IDLE_CLOSE_SECS),
            connect_timeout_secs: AtomicU64::new(DEFAULT_CONNECT_TIMEOUT_SECS),
            me: me.clone(),
        })
    }

    pub fn set_options(&self, idle_close_secs: u64, connect_timeout_secs: u64) {
        self.idle_close_secs.store(idle_close_secs.clamp(5, 3600), Ordering::Relaxed);
        self.connect_timeout_secs.store(connect_timeout_secs.clamp(5, 300), Ordering::Relaxed);
    }

    fn slot(&self, profile_id: &str) -> Arc<Slot> {
        let mut slots = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        slots.entry(profile_id.to_string()).or_default().clone()
    }

    fn existing_slot(&self, profile_id: &str) -> Option<Arc<Slot>> {
        self.slots.lock().ok()?.get(profile_id).cloned()
    }

    /// Up or on its way up, own tunnel or for the computer, so a connect won't need the login again.
    pub fn is_running(&self, profile_id: &str) -> bool {
        self.existing_slot(profile_id).is_some_and(|slot| slot.own().is_some() || slot.system_on().is_some())
    }

    pub fn statuses(&self) -> Vec<VpnStatus> {
        let Ok(slots) = self.slots.lock() else {
            return Vec::new();
        };
        slots
            .iter()
            .filter_map(|(id, slot)| {
                let users = slot.users.load(Ordering::SeqCst);
                let system = slot.system.lock().ok()?.clone();
                if let Some(system) = system {
                    if system.alive() {
                        let last_error = slot.last_error.lock().ok()?.clone();
                        let mut status = status_from(id, system.state(), Some(system.backend()), users, last_error);
                        status.prompt = system.prompt();
                        return Some(status);
                    }
                    // It ended on its own. Keep why, and let connects use an own tunnel again.
                    slot.set_error(system.state().error);
                    if let Ok(mut current) = slot.system.lock() {
                        current.take();
                    }
                }
                let last_error = slot.last_error.lock().ok()?.clone();
                let tunnel = slot.tunnel.lock().ok()?.clone();
                let turning_on = slot.turning_on.load(Ordering::SeqCst);
                let turning_on_with = if turning_on { slot.turning_on_with.lock().ok().and_then(|with| *with) } else { None };
                Some(match tunnel {
                    Some(tunnel) if !turning_on => status_from(id, tunnel.state(), None, users, last_error),
                    _ => VpnStatus {
                        profile_id: id.clone(),
                        phase: if turning_on { VpnPhase::Connecting } else { VpnPhase::Down },
                        system: turning_on,
                        with: turning_on_with,
                        users,
                        address: None,
                        bytes_in: 0,
                        bytes_out: 0,
                        last_error: if turning_on { None } else { last_error },
                        prompt: None,
                    },
                })
            })
            .collect()
    }

    pub fn watch(&self, channel: Channel<Vec<VpnStatus>>) {
        let _ = channel.send(self.statuses());
        if let Ok(mut watchers) = self.watchers.lock() {
            watchers.push(channel);
        }
    }

    fn notify(&self) {
        let statuses = self.statuses();
        if let Ok(mut watchers) = self.watchers.lock() {
            watchers.retain(|channel| channel.send(statuses.clone()).is_ok());
        }
    }

    fn change_hook(&self) -> Arc<dyn Fn() + Send + Sync> {
        let me = self.me.clone();
        Arc::new(move || {
            if let Some(manager) = me.upgrade() {
                manager.notify();
            }
        })
    }

    /// The own tunnel, opened when nothing has it up yet.
    async fn own_tunnel(&self, slot: &Arc<Slot>, leg: &VpnLeg) -> AppResult<Arc<Tunnel>> {
        let tunnel = {
            let _starting = slot.starting.lock().await;
            match slot.own() {
                Some(tunnel) => tunnel,
                None => {
                    if !leg.profile.needs_system.is_empty() {
                        return Err(AppError::general(format!(
                            "VPN {} only works while it's on for this computer, through the installed OpenVPN ({}). Turn it on from the VPN panel.",
                            leg.label,
                            leg.profile.needs_system.join(", ")
                        )));
                    }
                    let start = leg.build()?;
                    let tunnel = Tunnel::spawn(start, self.change_hook()).map_err(|error| AppError::general(error.to_string()))?;
                    if let Ok(mut current) = slot.tunnel.lock() {
                        *current = Some(tunnel.clone());
                    }
                    self.notify();
                    tunnel
                }
            }
        };

        if let Err(error) = tunnel.wait_up(connect_timeout()).await {
            slot.set_error(Some(error.clone()));
            if !tunnel.alive() || tunnel.state().phase == Phase::Connecting {
                tunnel.stop().await;
                if let Ok(mut current) = slot.tunnel.lock() {
                    if current.as_ref().is_some_and(|current| Arc::ptr_eq(current, &tunnel)) {
                        *current = None;
                    }
                }
            }
            self.notify();
            return Err(AppError::general(format!("VPN {}: {error}", leg.label)));
        }
        slot.set_error(None);
        self.notify();
        Ok(tunnel)
    }

    /// A user of the VPN. It goes through the computer's VPN while that's on, else through the own tunnel.
    pub async fn acquire(&self, leg: &VpnLeg) -> AppResult<VpnLease> {
        let slot = self.slot(&leg.profile_id);
        slot.generation.fetch_add(1, Ordering::SeqCst);
        slot.users.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut last) = slot.leg.lock() {
            *last = Some(leg.clone());
        }
        let lease = VpnLease { manager: self.me.clone(), leg: leg.clone(), slot: slot.clone() };

        match slot.system_on() {
            Some(system) => system.wait_up(connect_timeout()).await.map_err(|error| AppError::general(format!("VPN {}: {error}", leg.label)))?,
            None => drop(self.own_tunnel(&slot, leg).await?),
        }
        self.notify();
        Ok(lease)
    }

    /// Closes the own tunnel now. Whatever was using it loses its connections.
    pub async fn disconnect(&self, profile_id: &str) {
        let tunnel = self.existing_slot(profile_id).and_then(|slot| {
            slot.generation.fetch_add(1, Ordering::SeqCst);
            slot.tunnel.lock().ok().and_then(|mut current| current.take())
        });
        if let Some(tunnel) = tunnel {
            tunnel.stop().await;
        }
        self.notify();
    }

    /// Starts Fran's service or the installed OpenVPN for the profile. Once it's connected, users move over and the
    /// own tunnel closes, which frees its login on the server.
    pub async fn turn_on_system(&self, profile_id: &str, start: ComputerStart) -> AppResult<()> {
        let slot = self.slot(profile_id);
        let _starting = slot.starting.lock().await;
        if slot.system_on().is_some() {
            return Ok(());
        }
        let label = start.label().to_string();
        let backend = match &start {
            ComputerStart::Installed(_) => SystemBackend::Openvpn,
            ComputerStart::Fran(_) => SystemBackend::Fran,
        };
        if let Ok(mut with) = slot.turning_on_with.lock() {
            *with = Some(backend);
        }
        slot.turning_on.store(true, Ordering::SeqCst);
        self.notify();
        let started = match start {
            ComputerStart::Installed(start) => SystemVpn::start(start, self.change_hook()).await.map(ComputerVpn::Installed),
            ComputerStart::Fran(start) => ServiceVpn::start(start, self.change_hook()).await.map(ComputerVpn::Fran).map_err(AppError::general),
        };
        slot.turning_on.store(false, Ordering::SeqCst);
        let system = match started {
            Ok(system) => system,
            Err(error) => {
                slot.set_error(Some(error.message.clone()));
                self.notify();
                return Err(error);
            }
        };
        if let Ok(mut current) = slot.system.lock() {
            *current = Some(system.clone());
        }
        self.notify();

        if let Err(error) = system.wait_up_with_prompts(connect_timeout()).await {
            system.stop().await;
            if let Ok(mut current) = slot.system.lock() {
                if current.as_ref().is_some_and(|current| current.same(&system)) {
                    *current = None;
                }
            }
            slot.set_error(Some(error.clone()));
            self.notify();
            return Err(AppError::general(format!("VPN {label}: {error}")));
        }

        let own = slot.tunnel.lock().ok().and_then(|mut current| current.take());
        if let Some(own) = own {
            own.stop().await;
        }
        slot.set_error(None);
        self.notify();
        Ok(())
    }

    /// Stops the installed OpenVPN first, so the server never sees two logins, then opens the own tunnel again
    /// while something still uses the VPN. A one-time code can't be used twice, so with one the own tunnel waits
    /// for the next connect, which asks for a new code.
    pub async fn turn_off_system(&self, profile_id: &str) {
        let Some(slot) = self.existing_slot(profile_id) else {
            return;
        };
        let system = slot.system.lock().ok().and_then(|mut current| current.take());
        let Some(system) = system else {
            return;
        };
        system.stop().await;
        self.notify();

        let leg = slot.leg.lock().ok().and_then(|leg| leg.clone());
        let reusable = leg.filter(|leg| leg.profile.needs_system.is_empty() && !matches!(leg.profile.challenge, VpnChallenge::Static { .. }));
        if let Some(leg) = reusable.filter(|_| slot.users.load(Ordering::SeqCst) > 0) {
            let _ = self.own_tunnel(&slot, &leg).await;
        }
    }

    /// Opens the own tunnel with a fresh login, for users left after the computer's VPN was turned off.
    pub async fn open_own(&self, leg: &VpnLeg) -> AppResult<()> {
        let slot = self.slot(&leg.profile_id);
        if slot.system_on().is_some() {
            return Ok(());
        }
        if let Ok(mut last) = slot.leg.lock() {
            *last = Some(leg.clone());
        }
        self.own_tunnel(&slot, leg).await.map(drop)
    }

    /// What the window answered to a VPN's prompt.
    pub fn answer_prompt(&self, profile_id: &str, values: HashMap<String, Zeroizing<String>>) -> AppResult<()> {
        let system = self.existing_slot(profile_id).and_then(|slot| slot.system_on()).ok_or_else(|| AppError::general("That VPN isn't on any more"))?;
        system.submit(values);
        Ok(())
    }

    pub async fn stop_systems(&self) {
        let systems: Vec<ComputerVpn> = self
            .slots
            .lock()
            .map(|slots| slots.values().filter_map(|slot| slot.system.lock().ok().and_then(|mut current| current.take())).collect())
            .unwrap_or_default();
        for system in systems {
            system.stop().await;
        }
        self.notify();
    }

    /// Turns off the VPNs one backend runs for the computer.
    pub async fn stop_backend(&self, backend: SystemBackend) {
        let systems: Vec<ComputerVpn> = self
            .slots
            .lock()
            .map(|slots| {
                slots
                    .values()
                    .filter_map(|slot| {
                        let mut current = slot.system.lock().ok()?;
                        if current.as_ref().is_some_and(|system| system.backend() == backend) { current.take() } else { None }
                    })
                    .collect()
            })
            .unwrap_or_default();
        for system in systems {
            system.stop().await;
        }
        self.notify();
    }

    pub async fn stop_all(&self) {
        self.stop_systems().await;
        let tunnels: Vec<Arc<Tunnel>> = self
            .slots
            .lock()
            .map(|slots| slots.values().filter_map(|slot| slot.tunnel.lock().ok().and_then(|mut current| current.take())).collect())
            .unwrap_or_default();
        for tunnel in tunnels {
            tunnel.stop().await;
        }
    }

    fn released(&self, slot: Arc<Slot>) {
        if slot.users.fetch_sub(1, Ordering::SeqCst) != 1 {
            self.notify();
            return;
        }
        let generation = slot.generation.load(Ordering::SeqCst);
        let me = self.me.clone();
        let idle = Duration::from_secs(self.idle_close_secs.load(Ordering::Relaxed));
        self.notify();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(idle).await;
            if slot.users.load(Ordering::SeqCst) != 0 || slot.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            let tunnel = slot.tunnel.lock().ok().and_then(|mut current| current.take());
            if let Some(tunnel) = tunnel {
                tunnel.stop().await;
            }
            if let Some(manager) = me.upgrade() {
                manager.notify();
            }
        });
    }

    pub fn store(&self) -> &VpnStore {
        &self.store
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }
}

/// One user of a VPN. An own tunnel closes a while after the last lease is dropped.
pub struct VpnLease {
    manager: Weak<VpnManager>,
    leg: VpnLeg,
    slot: Arc<Slot>,
}

impl VpnLease {
    pub fn profile_id(&self) -> &str {
        &self.leg.profile_id
    }

    /// Asks which way is current on every call, so turning the computer's VPN on or off only changes where new connections go.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<VpnConn> {
        if let Some(system) = self.slot.system_on() {
            return system.connect(host, port, timeout).await.map(VpnConn::System);
        }
        let manager = self.manager.upgrade().ok_or_else(|| io::Error::other("The VPN client stopped"))?;
        let tunnel = manager.own_tunnel(&self.slot, &self.leg).await.map_err(|error| io::Error::other(error.message))?;
        tunnel.connect(host, port, timeout).await.map(VpnConn::Own)
    }
}

impl Drop for VpnLease {
    fn drop(&mut self) {
        match self.manager.upgrade() {
            Some(manager) => manager.released(self.slot.clone()),
            None => {
                self.slot.users.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

/// A profile picked for a connect, before its secrets are looked up.
pub struct VpnPlan {
    profile: VpnProfile,
}

pub fn password_slot(profile: &VpnProfile) -> SecretSlot {
    SecretSlot::owned(
        SecretOwner::Vpn(profile.id.clone()),
        PASSWORD_SLOT,
        format!("VPN password for {} on {}", profile.user, profile.label),
    )
}

pub fn code_slot(profile: &VpnProfile) -> SecretSlot {
    let label = match &profile.challenge {
        VpnChallenge::Static { text, .. } if !text.trim().is_empty() => format!("{} (VPN {})", text.trim(), profile.label),
        _ => format!("One-time code for VPN {}", profile.label),
    };
    SecretSlot::one_time(format!("vpn:{}:code", profile.id), label)
}

impl VpnPlan {
    pub fn for_profile(id: &str, filler: &Filler) -> AppResult<Self> {
        let saved = manager()?.store().find(id)?;
        let mut profile = filler.fill(&saved, &saved.secret_refs, &format!("VPN {}", saved.label))?;
        // What a save checks, again for the parts that came from secrets.
        profile.user = profile.user.trim().to_string();
        if profile.is_wireguard() {
            if let Some(remote) = profile.remotes.first_mut() {
                *remote = wireguard::clean_endpoint(remote)?;
            }
        } else {
            for remote in &mut profile.remotes {
                remote.host = remote.host.trim().to_string();
                if remote.host.is_empty() || remote.host.contains(char::is_whitespace) || remote.port == 0 {
                    return Err(AppError::general(format!("A server of VPN {} has no usable address or port", profile.label)));
                }
            }
        }
        Ok(Self { profile })
    }

    /// What a new login needs. Turning a VPN on for the computer always logs in again.
    pub fn login_slots(&self) -> Vec<SecretSlot> {
        let mut slots = Vec::new();
        if self.profile.auth.uses_password() {
            slots.push(password_slot(&self.profile));
        }
        if matches!(self.profile.challenge, VpnChallenge::Static { .. }) {
            slots.push(code_slot(&self.profile));
        }
        slots
    }

    /// Nothing is asked for while the VPN is already running.
    pub fn required_secrets(&self) -> Vec<SecretSlot> {
        match manager() {
            Ok(manager) if manager.is_running(&self.profile.id) => Vec::new(),
            _ => self.login_slots(),
        }
    }

    pub fn resolve(&self, secrets: &SecretBag) -> VpnLeg {
        let login = self.profile.auth.uses_password().then(|| {
            let password = secrets.get(&password_slot(&self.profile).id).map(str::to_string);
            let response = match self.profile.challenge {
                VpnChallenge::Static { .. } => secrets.get(&code_slot(&self.profile).id).map(str::to_string),
                VpnChallenge::None => Some(String::new()),
            };
            password.zip(response)
        });
        VpnLeg {
            profile_id: self.profile.id.clone(),
            label: self.profile.label.clone(),
            profile: self.profile.clone(),
            login: login.map(|login| login.map(|(password, response)| (Zeroizing::new(password), Zeroizing::new(response)))),
            slots: self.login_slots(),
        }
    }
}

/// A VPN resolved for one connect. It only starts a tunnel when none is running.
#[derive(Clone)]
pub struct VpnLeg {
    pub profile_id: String,
    pub label: String,
    profile: VpnProfile,
    /// None when the profile has no password login, Some(None) when it has one that wasn't given.
    login: Option<Option<(Zeroizing<String>, Zeroizing<String>)>>,
    slots: Vec<SecretSlot>,
}

impl VpnLeg {
    pub async fn acquire(&self) -> AppResult<VpnLease> {
        manager()?.acquire(self).await
    }

    fn login(&self) -> AppResult<Option<Login>> {
        match &self.login {
            None => Ok(None),
            Some(None) => Err(AppError::secrets_required(self.slots.clone())),
            Some(Some((password, response))) => {
                if self.profile.user.trim().is_empty() {
                    return Err(AppError::general(format!("Enter the user name for VPN {} in its settings", self.label)));
                }
                Ok(Some(Login {
                    username: self.profile.user.trim().to_string(),
                    password: password.to_string(),
                    response: response.to_string(),
                    dynamic_cookie: String::new(),
                }))
            }
        }
    }

    /// The client certificate, the rest of its chain, and the key from the vault.
    fn client_key(&self, vault: &Vault) -> AppResult<(String, String, Option<Arc<ClientKey>>)> {
        if !self.profile.auth.uses_cert() || config::key_outside_fran(&self.profile) {
            return Ok((String::new(), String::new(), None));
        }
        let owner = SecretOwner::Vpn(self.profile_id.clone());
        let text = vault
            .get(&owner.secret_id(PRIVATE_KEY_SLOT))?
            .ok_or_else(|| AppError::general(format!("VPN {} has no client key. Add one in its settings.", self.label)))?;
        let (key, _) = keys::read_client_key(&text)?;
        let mut certs = keys::pem_blocks(&self.profile.cert)?.into_iter().filter(|block| block.label == "CERTIFICATE");
        let cert = certs.next().ok_or_else(|| AppError::general(format!("VPN {} has no client certificate", self.label)))?;
        let chain: String = certs.map(|block| keys::to_pem("CERTIFICATE", &block.der)).collect();
        Ok((keys::to_pem("CERTIFICATE", &cert.der), chain, Some(Arc::new(key))))
    }

    fn tls_key(&self, vault: &Vault) -> AppResult<Option<Zeroizing<String>>> {
        match self.profile.tls_wrap {
            TlsWrap::None => Ok(None),
            _ => Ok(Some(
                vault
                    .get(&SecretOwner::Vpn(self.profile_id.clone()).secret_id(TLS_KEY_SLOT))?
                    .ok_or_else(|| AppError::general(format!("The TLS key of VPN {} is missing from the vault", self.label)))?,
            )),
        }
    }

    /// The keys come from the vault on every start, so nothing keeps them between connects.
    fn wireguard(&self, vault: &Vault) -> AppResult<WireGuardStart> {
        let owner = SecretOwner::Vpn(self.profile_id.clone());
        let private_key = vault
            .get(&owner.secret_id(PRIVATE_KEY_SLOT))?
            .ok_or_else(|| AppError::general(format!("VPN {} has no private key. Add or generate one in its settings.", self.label)))?;
        let preshared_key = vault.get(&owner.secret_id(PRESHARED_KEY_SLOT))?;
        wireguard::start(&self.profile, &private_key, preshared_key.as_deref().map(|key| key.as_str()))
    }

    fn worker_start(&self) -> AppResult<WorkerStart> {
        let vault = manager()?.vault.clone();
        if self.profile.is_wireguard() {
            return Ok(WorkerStart::WireGuard(self.wireguard(&vault)?));
        }
        let login = self.login()?;
        let (cert, chain, key) = self.client_key(&vault)?;
        let tls_key = self.tls_key(&vault)?;
        let config = config::core_profile(&self.profile, tls_key.as_deref().map(|key| key.as_str()))?;
        Ok(WorkerStart::OpenVpn { config, cert, chain, key, login })
    }

    fn build(&self) -> AppResult<TunnelStart> {
        Ok(TunnelStart { profile_id: self.profile_id.clone(), label: self.label.clone(), worker: self.worker_start()?, timeout: connect_timeout() })
    }

    pub fn is_wireguard(&self) -> bool {
        self.profile.is_wireguard()
    }

    /// What Core can't run (TAP, legacy ciphers, `fragment`, proxies), and keys OpenVPN signs with itself (the Windows
    /// certificate store, smartcards), go to the installed OpenVPN whichever way is picked.
    pub fn needs_installed(&self) -> bool {
        !self.profile.needs_system.is_empty() || config::key_outside_fran(&self.profile)
    }

    fn prompt_slots(&self) -> PromptSlots {
        PromptSlots {
            password: self.profile.auth.uses_password().then(|| password_slot(&self.profile)),
            code: matches!(self.profile.challenge, VpnChallenge::Static { .. }).then(|| code_slot(&self.profile)),
            challenge_id: format!("vpn:{}:challenge", self.profile_id),
            pin_id: format!("vpn:{}:pin", self.profile_id),
        }
    }

    /// For Fran's service. It runs the same profile and login an own tunnel gets, on a real adapter.
    pub fn service_start(&self) -> AppResult<ServiceStart> {
        Ok(ServiceStart {
            label: self.label.clone(),
            worker: self.worker_start()?,
            options: AdapterOptions { route_all: self.profile.route_all == RouteAll::FollowServer, use_vpn_dns: self.profile.use_vpn_dns },
            prompts: self.prompt_slots(),
            timeout: connect_timeout(),
        })
    }

    /// `program` is the OpenVPN path from Settings > VPN, if one is set.
    pub fn system_start(&self, program: Option<String>) -> AppResult<SystemStart> {
        if self.profile.is_wireguard() {
            return Err(AppError::general(format!("VPN {} is WireGuard, which turns on for this computer with Fran's VPN service", self.label)));
        }
        let imported_system_only = self.profile.imported.as_ref().is_some_and(|info| !info.system_only.is_empty());
        if imported_system_only && self.profile.system_options.is_empty() {
            let file = self.profile.imported.as_ref().map(|info| info.file_name.as_str()).unwrap_or("its .ovpn");
            return Err(AppError::general(format!(
                "VPN {} was imported before Fran kept the options only the installed OpenVPN runs. Import {file} again.",
                self.label
            )));
        }
        let uses_store = self.profile.system_options.iter().any(|option| option.first().is_some_and(|name| name == "cryptoapicert"));
        if uses_store && !cfg!(windows) {
            return Err(AppError::general(format!("VPN {} uses the Windows certificate store, so it only works on Windows", self.label)));
        }
        let login = self.login()?;
        let vault = manager()?.vault.clone();
        let (_, _, key) = self.client_key(&vault)?;
        let tls_key = self.tls_key(&vault)?;
        let config = config::system_profile(&self.profile, tls_key.as_deref().map(|key| key.as_str()))?;
        let prompts = self.prompt_slots();
        // The admin password prompt on macOS and Linux counts toward this, so it gets more than a connect.
        let management_wait = if cfg!(windows) { connect_timeout() } else { connect_timeout() + Duration::from_secs(120) };
        Ok(SystemStart { label: self.label.clone(), config, key, login, program, use_vpn_dns: self.profile.use_vpn_dns, prompts, management_wait })
    }
}
