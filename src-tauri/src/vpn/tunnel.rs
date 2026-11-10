use std::{
    io,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::{mpsc, watch},
};
use zeroize::Zeroize;

use vpn_proto::{PROTOCOL_VERSION, WORKER_ARG};

use super::frames::{self, Frame, FromWorker, Login, ToWorker, WireGuardStart};
use super::keys::{self, ClientKey};
use super::net::{NetStack, VpnStream};

const STOP_GRACE: Duration = Duration::from_secs(3);

/// What the worker or the service runs. An OpenVPN key stays in Fran, which signs for it. WireGuard has no such
/// hook, so its key goes along and is wiped once used.
pub enum WorkerStart {
    OpenVpn { config: String, cert: String, chain: String, key: Option<Arc<ClientKey>>, login: Option<Login> },
    WireGuard(WireGuardStart),
}

impl WorkerStart {
    pub fn key(&self) -> Option<&Arc<ClientKey>> {
        match self {
            Self::OpenVpn { key, .. } => key.as_ref(),
            Self::WireGuard(_) => None,
        }
    }
}

/// Everything a worker needs to open one tunnel.
pub struct TunnelStart {
    pub profile_id: String,
    pub label: String,
    pub worker: WorkerStart,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    Up,
    Reconnecting,
    Down,
}

#[derive(Debug, Clone)]
pub struct TunnelState {
    pub phase: Phase,
    pub error: Option<String>,
    pub address: Option<String>,
    pub bytes_in: i64,
    pub bytes_out: i64,
}

pub type ChangeHook = Arc<dyn Fn() + Send + Sync>;

pub struct Tunnel {
    pub profile_id: String,
    pub label: String,
    state: watch::Sender<TunnelState>,
    stack: Mutex<Option<Arc<NetStack>>>,
    to_worker: mpsc::UnboundedSender<Vec<u8>>,
    child: Mutex<Option<Child>>,
    on_change: ChangeHook,
}

/// What Core's events mean for someone looking at the VPN.
pub(crate) fn describe(name: &str, info: &str) -> String {
    let detail = if info.trim().is_empty() { String::new() } else { format!(" ({})", info.trim()) };
    match name {
        "AUTH_FAILED" => format!("The VPN server refused the login{detail}"),
        "CERT_VERIFY_FAIL" => format!("The VPN server's certificate didn't pass the check{detail}"),
        "TLS_VERSION_MIN" => "The VPN server only speaks a TLS version older than 1.2".to_string(),
        "CONNECTION_TIMEOUT" => "The VPN server didn't answer in time".to_string(),
        "EPKI_ERROR" | "EPKI_INVALID_ALIAS" => format!("Signing with the client key failed{detail}"),
        "COMPRESS_ERROR" => "The VPN server wants compression, which Fran refuses".to_string(),
        "NEED_CREDS" => "The VPN needs a user name and password".to_string(),
        "HANDSHAKE_TIMEOUT" => format!("No answer from the WireGuard server{detail}. Check the endpoint and both keys."),
        _ => format!("{name}{detail}"),
    }
}

fn worker_exe() -> io::Result<std::path::PathBuf> {
    // The e2e tests run inside a test binary, so they point at the built fran-vpn instead.
    #[cfg(feature = "e2e")]
    if let Some(path) = std::env::var_os("FRAN_VPN_WORKER") {
        return Ok(path.into());
    }
    super::sidecar()
}

fn worker_command() -> io::Result<Command> {
    let exe = worker_exe()?;
    let mut command = Command::new(exe);
    command.arg(WORKER_ARG).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    Ok(command)
}

impl Tunnel {
    pub fn spawn(start: TunnelStart, on_change: ChangeHook) -> io::Result<Arc<Self>> {
        let mut child = worker_command()?.spawn().map_err(|error| io::Error::other(format!("The VPN worker didn't start: {error}")))?;
        let mut stdin = child.stdin.take().ok_or_else(|| io::Error::other("The VPN worker has no input"))?;
        let mut stdout = child.stdout.take().ok_or_else(|| io::Error::other("The VPN worker has no output"))?;
        let (to_worker, mut outbox) = mpsc::unbounded_channel::<Vec<u8>>();
        let (state, _) = watch::channel(TunnelState { phase: Phase::Connecting, error: None, address: None, bytes_in: 0, bytes_out: 0 });

        let tunnel = Arc::new(Self {
            profile_id: start.profile_id.clone(),
            label: start.label.clone(),
            state,
            stack: Mutex::new(None),
            to_worker,
            child: Mutex::new(Some(child)),
            on_change,
        });

        tokio::spawn(async move {
            while let Some(mut bytes) = outbox.recv().await {
                let written = stdin.write_all(&bytes).await.and(stdin.flush().await);
                // Some of these carry the login.
                bytes.zeroize();
                if written.is_err() {
                    break;
                }
            }
        });

        let TunnelStart { worker, timeout, .. } = start;
        tunnel.send(frames::encode_message(&ToWorker::Hello { version: PROTOCOL_VERSION })?);
        let (message, key) = match worker {
            WorkerStart::OpenVpn { config, cert, chain, key, login } => (
                ToWorker::Start {
                    profile: config,
                    cert,
                    chain,
                    gui_version: format!("Fran {}", env!("CARGO_PKG_VERSION")),
                    timeout_secs: timeout.as_secs().min(i32::MAX as u64) as i32,
                    login,
                    adapter: None,
                },
                key,
            ),
            WorkerStart::WireGuard(config) => (ToWorker::StartWireGuard { config, adapter: None }, None),
        };
        tunnel.send(frames::encode_message(&message)?);
        drop(message);

        let reader = tunnel.clone();
        tokio::spawn(async move {
            let ended = loop {
                match frames::read_frame_async::<FromWorker>(&mut stdout).await {
                    Ok(Some(frame)) => {
                        if let Some(ended) = reader.handle(frame, key.as_ref()) {
                            break ended;
                        }
                    }
                    Ok(None) => break Some("The VPN worker stopped".to_string()),
                    Err(error) => break Some(format!("The VPN worker sent something broken: {error}")),
                }
            };
            reader.finish(ended);
        });
        Ok(tunnel)
    }

    fn send(&self, bytes: Vec<u8>) {
        let _ = self.to_worker.send(bytes);
    }

    fn update(&self, change: impl FnOnce(&mut TunnelState)) {
        self.state.send_modify(change);
        (self.on_change)();
    }

    /// Some(reason) when the session is over.
    fn handle(self: &Arc<Self>, frame: Frame<FromWorker>, key: Option<&Arc<ClientKey>>) -> Option<Option<String>> {
        let message = match frame {
            Frame::Packet(packet) => {
                if let Some(stack) = self.current_stack() {
                    stack.receive(packet);
                }
                return None;
            }
            Frame::Message(message) => message,
        };
        match message {
            FromWorker::Hello { version, .. } if version != PROTOCOL_VERSION => {
                return Some(Some("Fran's VPN worker doesn't match this version of Fran. Reinstall Fran.".to_string()));
            }
            FromWorker::Hello { .. } | FromWorker::Evaluated { .. } | FromWorker::Log { .. } => {}
            FromWorker::Refused { message } => return Some(Some(message)),
            FromWorker::AdapterUp { .. } => return Some(Some("Fran's VPN worker set up an adapter for an own tunnel".to_string())),
            FromWorker::EvalFailed { message } => return Some(Some(format!("OpenVPN refused the profile: {message}"))),
            FromWorker::Event { name, info, fatal, error } => {
                if fatal || error {
                    let text = describe(&name, &info);
                    self.update(|state| state.error = Some(text));
                }
                if name == "RECONNECTING" {
                    self.update(|state| {
                        if state.phase == Phase::Up {
                            state.phase = Phase::Reconnecting;
                        }
                    });
                }
            }
            FromWorker::Sign { id, data, algorithm, hash, salt_len } => {
                let reply = match key {
                    Some(key) => keys::sign(key, &data, &algorithm, &hash, &salt_len),
                    None => Err("This VPN has no client key in Fran".to_string()),
                };
                let (signature, error) = match reply {
                    Ok(signature) => (Some(signature), None),
                    Err(error) => (None, Some(error)),
                };
                if let Ok(bytes) = frames::encode_message(&ToWorker::SignReply { id, signature, error }) {
                    self.send(bytes);
                }
            }
            FromWorker::TunUp { settings } => {
                let sender = self.to_worker.clone();
                let sink = Arc::new(move |packet: Vec<u8>| {
                    if let Ok(bytes) = frames::encode_packet(&packet) {
                        let _ = sender.send(bytes);
                    }
                });
                match NetStack::new(settings, sink) {
                    Ok(stack) => {
                        let address = stack.settings().addr4.map(|(addr, _)| addr.to_string()).or_else(|| stack.settings().addr6.map(|(addr, _)| addr.to_string()));
                        if let Some(old) = self.stack.lock().ok().and_then(|mut slot| slot.replace(Arc::new(stack))) {
                            old.shutdown();
                        }
                        self.update(|state| {
                            state.phase = Phase::Up;
                            state.error = None;
                            state.address = address;
                        });
                    }
                    Err(error) => return Some(Some(error.to_string())),
                }
            }
            FromWorker::Handshake => self.update(|state| {
                if state.phase == Phase::Reconnecting {
                    state.phase = Phase::Up;
                    state.error = None;
                }
            }),
            FromWorker::TunFailed { message } => return Some(Some(format!("The tunnel couldn't be set up: {message}"))),
            FromWorker::TunDown => {
                self.drop_stack();
                self.update(|state| {
                    if state.phase == Phase::Up {
                        state.phase = Phase::Reconnecting;
                    }
                });
            }
            FromWorker::Stats { bytes_in, bytes_out } => {
                self.state.send_modify(|state| {
                    state.bytes_in = bytes_in;
                    state.bytes_out = bytes_out;
                });
            }
            FromWorker::Ended { error } => return Some(error),
        }
        None
    }

    fn drop_stack(&self) {
        if let Some(stack) = self.stack.lock().ok().and_then(|mut slot| slot.take()) {
            stack.shutdown();
        }
    }

    fn finish(&self, reason: Option<String>) {
        self.drop_stack();
        self.update(|state| {
            if state.error.is_none() {
                state.error = reason;
            }
            state.phase = Phase::Down;
        });
        if let Ok(mut child) = self.child.lock() {
            child.take();
        }
    }

    fn current_stack(&self) -> Option<Arc<NetStack>> {
        self.stack.lock().ok().and_then(|slot| slot.clone())
    }

    pub fn state(&self) -> TunnelState {
        self.state.borrow().clone()
    }

    pub fn alive(&self) -> bool {
        self.state.borrow().phase != Phase::Down
    }

    /// Waits for the tunnel to be up, and gives the reason when it ends instead.
    pub async fn wait_up(&self, timeout: Duration) -> Result<(), String> {
        let mut changes = self.state.subscribe();
        let waiting = async {
            loop {
                let state = changes.borrow_and_update().clone();
                match state.phase {
                    Phase::Up => return Ok(()),
                    Phase::Down => return Err(state.error.unwrap_or_else(|| format!("VPN {} closed", self.label))),
                    Phase::Connecting | Phase::Reconnecting => {}
                }
                if changes.changed().await.is_err() {
                    return Err(format!("VPN {} closed", self.label));
                }
            }
        };
        match tokio::time::timeout(timeout, waiting).await {
            Ok(result) => result,
            Err(_) => Err(self.state().error.unwrap_or_else(|| format!("VPN {} didn't connect in time", self.label))),
        }
    }

    /// A TCP connection through the tunnel. Names are looked up with the VPN's own DNS.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<VpnStream> {
        self.wait_up(timeout).await.map_err(io::Error::other)?;
        let stack = self.current_stack().ok_or_else(|| io::Error::other(format!("VPN {} is reconnecting", self.label)))?;
        let addresses = stack.resolve(host, port).await?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"));
        for address in addresses {
            match stack.connect(address, timeout).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Asks OpenVPN to say goodbye to the server, then makes sure the worker is gone.
    pub async fn stop(&self) {
        if !self.alive() {
            return;
        }
        if let Ok(bytes) = frames::encode_message(&ToWorker::Stop) {
            self.send(bytes);
        }
        let mut changes = self.state.subscribe();
        let ended = async {
            while changes.borrow_and_update().phase != Phase::Down {
                if changes.changed().await.is_err() {
                    break;
                }
            }
        };
        if tokio::time::timeout(STOP_GRACE, ended).await.is_err() {
            self.finish(None);
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.drop_stack();
    }
}
