//! A VPN on for the whole computer, run by Fran's own VPN service (`fran-vpn --service`) instead of the installed
//! OpenVPN. One connection to the service is one tunnel, and it ends when the connection does. An OpenVPN key stays in
//! Fran: the service asks Fran to sign, the same way an own tunnel's worker does. A WireGuard key is sent along, since
//! WireGuard has nothing to sign with, and the service only keeps it in memory.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
};
use tokio_util::sync::CancellationToken;
use vpn_proto::{
    PROTOCOL_VERSION,
    frames::{self, AdapterOptions, Frame, FromWorker, ServiceInfo, ToWorker},
};
use zeroize::Zeroizing;

use super::adapter::{Adapter, SystemStream};
use super::management::{self, DynamicChallenge};
use super::{PromptSlots, VpnPrompt};
use crate::connections::SecretSlot;
use crate::vpn::frames::Login;
use crate::vpn::keys;
use crate::vpn::tunnel::{ChangeHook, Phase, TunnelState, WorkerStart, describe};

const STOP_GRACE: Duration = Duration::from_secs(5);
const CONNECT_WAIT: Duration = Duration::from_secs(3);

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
pub type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// Everything needed to turn a VPN on with Fran's service.
pub struct ServiceStart {
    pub label: String,
    pub worker: WorkerStart,
    pub options: AdapterOptions,
    pub prompts: PromptSlots,
    pub timeout: Duration,
}

/// Why the service didn't take a connection.
pub enum Unreachable {
    /// Nothing listens, or the one listening isn't the service.
    NotRunning(String),
    /// It answered, but doesn't let this account in. Its hello still says how it's set up.
    Refused(ServiceInfo),
    OtherVersion(String),
}

impl Unreachable {
    pub fn message(self) -> String {
        match self {
            Self::NotRunning(message) | Self::OtherVersion(message) => message,
            Self::Refused(info) => info.refused.unwrap_or_else(|| "Fran's VPN service doesn't take your account".to_string()),
        }
    }
}

/// The connection alone, before any hello.
#[cfg(unix)]
pub async fn connect_raw() -> io::Result<(Reader, Writer)> {
    let stream = tokio::net::UnixStream::connect(vpn_proto::SERVICE_SOCKET).await?;
    // The socket's folder is root's, so nothing else can take its place. Checking the other end costs nothing.
    if stream.peer_cred()?.uid() != 0 {
        return Err(io::Error::other("Something other than Fran's VPN service listens on its socket"));
    }
    let (reader, writer) = stream.into_split();
    Ok((Box::new(reader), Box::new(writer)))
}

#[cfg(windows)]
pub async fn connect_raw() -> io::Result<(Reader, Writer)> {
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new().open(vpn_proto::SERVICE_PIPE)?;
    super::setup::check_pipe_server(&pipe)?;
    let (reader, writer) = tokio::io::split(pipe);
    Ok((Box::new(reader), Box::new(writer)))
}

pub async fn send(writer: &mut Writer, message: &ToWorker) -> io::Result<()> {
    let bytes = frames::encode_message(message)?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

/// Connects and says hello. The service answers with its build, who may use it, and whether that's this account.
pub async fn open() -> Result<(Reader, Writer, ServiceInfo), Unreachable> {
    let (mut reader, mut writer) = match tokio::time::timeout(CONNECT_WAIT, connect_raw()).await {
        Ok(Ok(halves)) => halves,
        Ok(Err(error)) => return Err(Unreachable::NotRunning(error.to_string())),
        Err(_) => return Err(Unreachable::NotRunning("Fran's VPN service didn't answer".to_string())),
    };
    let not_running = |error: io::Error| Unreachable::NotRunning(format!("Fran's VPN service didn't answer: {error}"));
    send(&mut writer, &ToWorker::Hello { version: PROTOCOL_VERSION }).await.map_err(not_running)?;
    let reply = tokio::time::timeout(CONNECT_WAIT, frames::read_frame_async::<FromWorker>(&mut reader))
        .await
        .map_err(|_| Unreachable::NotRunning("Fran's VPN service didn't answer".to_string()))?
        .map_err(not_running)?;
    match reply {
        Some(Frame::Message(FromWorker::Hello { version, service: Some(info) })) if version == PROTOCOL_VERSION => {
            if info.allowed { Ok((reader, writer, info)) } else { Err(Unreachable::Refused(info)) }
        }
        Some(Frame::Message(FromWorker::Refused { message })) => Err(Unreachable::OtherVersion(message)),
        Some(Frame::Message(FromWorker::Hello { .. })) => Err(Unreachable::OtherVersion("Fran's VPN service doesn't match this version of Fran".to_string())),
        _ => Err(Unreachable::NotRunning("Fran's VPN service sent something unexpected".to_string())),
    }
}

/// What ended one session with the service.
enum Outcome {
    Stopped,
    Failed(String),
    /// The server refused the login. Asked for again when the profile has a password.
    AuthFailed,
    /// The server asked a second question after the password (CRV1), answered on a fresh session.
    Challenge(DynamicChallenge, String),
}

pub struct ServiceVpn {
    pub label: String,
    state: watch::Sender<TunnelState>,
    adapter: Adapter,
    prompt: Mutex<Option<VpnPrompt>>,
    answers: mpsc::UnboundedSender<HashMap<String, Zeroizing<String>>>,
    stop: CancellationToken,
    on_change: ChangeHook,
}

impl ServiceVpn {
    /// Fails right away when the service can't be reached or won't take this account. After that, problems end
    /// up in the state, like with the installed OpenVPN.
    pub async fn start(start: ServiceStart, on_change: ChangeHook) -> Result<Arc<Self>, String> {
        let (reader, writer, _) = open().await.map_err(Unreachable::message)?;
        let (answers, inbox) = mpsc::unbounded_channel();
        let (state, _) = watch::channel(TunnelState { phase: Phase::Connecting, error: None, address: None, bytes_in: 0, bytes_out: 0 });
        let vpn = Arc::new(Self {
            label: start.label.clone(),
            state,
            adapter: Adapter::new(start.label.clone(), start.options.use_vpn_dns),
            prompt: Mutex::new(None),
            answers,
            stop: CancellationToken::new(),
            on_change,
        });
        let runner = vpn.clone();
        tokio::spawn(async move { runner.run(start, reader, writer, inbox).await });
        Ok(vpn)
    }

    fn update(&self, change: impl FnOnce(&mut TunnelState)) {
        self.state.send_modify(change);
        (self.on_change)();
    }

    fn ask(&self, prompt: VpnPrompt) {
        if let Ok(mut current) = self.prompt.lock() {
            *current = Some(prompt);
        }
        (self.on_change)();
    }

    fn clear_prompt(&self) {
        if let Ok(mut current) = self.prompt.lock() {
            current.take();
        }
        (self.on_change)();
    }

    pub fn prompt(&self) -> Option<VpnPrompt> {
        self.prompt.lock().ok()?.clone()
    }

    pub fn submit(&self, values: HashMap<String, Zeroizing<String>>) {
        let _ = self.answers.send(values);
    }

    /// Waits for the window's answer to a prompt. None when the VPN is turned off meanwhile.
    async fn answer(&self, prompt: VpnPrompt, inbox: &mut mpsc::UnboundedReceiver<HashMap<String, Zeroizing<String>>>) -> Option<HashMap<String, Zeroizing<String>>> {
        self.ask(prompt);
        let values = tokio::select! {
            values = inbox.recv() => values,
            _ = self.stop.cancelled() => None,
        };
        self.clear_prompt();
        values
    }

    async fn run(self: Arc<Self>, start: ServiceStart, reader: Reader, writer: Writer, mut inbox: mpsc::UnboundedReceiver<HashMap<String, Zeroizing<String>>>) {
        let mut login = match &start.worker {
            WorkerStart::OpenVpn { login, .. } => login.clone(),
            WorkerStart::WireGuard(_) => None,
        };
        let mut connection = Some((reader, writer));
        let reason = loop {
            let (reader, writer) = match connection.take() {
                Some(halves) => halves,
                None => match open().await {
                    Ok((reader, writer, _)) => (reader, writer),
                    Err(error) => break Some(error.message()),
                },
            };
            match self.session(&start, login.clone(), reader, writer).await {
                Outcome::Stopped => break None,
                Outcome::Failed(reason) => break Some(reason),
                Outcome::AuthFailed => {
                    let (Some(password), Some(current)) = (start.prompts.password.clone(), login.as_mut()) else {
                        break Some("The VPN server refused the login".to_string());
                    };
                    let mut slots = vec![password.clone()];
                    slots.extend(start.prompts.code.clone());
                    let title = format!("The VPN server refused the login for {}. Try again.", self.label);
                    let Some(values) = self.answer(VpnPrompt { title, slots }, &mut inbox).await else { break None };
                    if let Some(value) = values.get(&password.id) {
                        current.password = value.to_string();
                    }
                    if let Some(value) = start.prompts.code.as_ref().and_then(|slot| values.get(&slot.id)) {
                        current.response = value.to_string();
                    }
                    current.dynamic_cookie.clear();
                }
                Outcome::Challenge(challenge, cookie) => {
                    let label = if challenge.text.trim().is_empty() { "Code".to_string() } else { challenge.text.clone() };
                    let slot = SecretSlot::one_time(start.prompts.challenge_id.clone(), label);
                    let title = format!("VPN {} asks for one more sign-in step", self.label);
                    let Some(values) = self.answer(VpnPrompt { title, slots: vec![slot] }, &mut inbox).await else { break None };
                    let response = values.get(&start.prompts.challenge_id).map(|value| value.to_string()).unwrap_or_default();
                    // The answer goes with the server's cookie instead of the password, on a fresh session.
                    login = Some(Login { username: challenge.username.clone(), password: String::new(), response, dynamic_cookie: cookie });
                }
            }
        };
        self.finish(reason);
    }

    async fn session(&self, start: &ServiceStart, login: Option<Login>, mut reader: Reader, mut writer: Writer) -> Outcome {
        let message = match &start.worker {
            WorkerStart::OpenVpn { config, cert, chain, .. } => ToWorker::Start {
                profile: config.clone(),
                cert: cert.clone(),
                chain: chain.clone(),
                gui_version: format!("Fran {}", env!("CARGO_PKG_VERSION")),
                timeout_secs: start.timeout.as_secs().min(i32::MAX as u64) as i32,
                login,
                adapter: Some(start.options),
            },
            WorkerStart::WireGuard(config) => ToWorker::StartWireGuard { config: config.clone(), adapter: Some(start.options) },
        };
        if let Err(error) = send(&mut writer, &message).await {
            return Outcome::Failed(format!("Fran's VPN service stopped answering: {error}"));
        }
        drop(message);

        let mut pending: Option<Outcome> = None;
        loop {
            let frame = tokio::select! {
                frame = frames::read_frame_async::<FromWorker>(&mut reader) => frame,
                _ = self.stop.cancelled() => {
                    let _ = send(&mut writer, &ToWorker::Stop).await;
                    let ended = async {
                        while let Ok(Some(frame)) = frames::read_frame_async::<FromWorker>(&mut reader).await {
                            if matches!(frame, Frame::Message(FromWorker::Ended { .. })) {
                                break;
                            }
                        }
                    };
                    let _ = tokio::time::timeout(STOP_GRACE, ended).await;
                    return Outcome::Stopped;
                }
            };
            let message = match frame {
                Ok(Some(Frame::Message(message))) => message,
                Ok(Some(Frame::Packet(_))) => return Outcome::Failed("Fran's VPN service sent packets, which it shouldn't".to_string()),
                Ok(None) => return pending.unwrap_or_else(|| Outcome::Failed("Fran's VPN service closed the connection".to_string())),
                Err(error) => return Outcome::Failed(format!("Fran's VPN service sent something broken: {error}")),
            };
            match message {
                FromWorker::Event { name, info, fatal, error } => match name.as_str() {
                    "DYNAMIC_CHALLENGE" => {
                        if let Some(challenge) = management::dynamic_challenge(&info) {
                            pending = Some(Outcome::Challenge(challenge, info));
                        }
                    }
                    "AUTH_FAILED" => pending = Some(Outcome::AuthFailed),
                    "RECONNECTING" => self.update(|state| {
                        if state.phase == Phase::Up {
                            state.phase = Phase::Reconnecting;
                        }
                    }),
                    _ if fatal || error => {
                        let text = describe(&name, &info);
                        self.update(|state| state.error = Some(text));
                    }
                    _ => {}
                },
                FromWorker::Sign { id, data, algorithm, hash, salt_len } => {
                    let reply = match start.worker.key() {
                        Some(key) => keys::sign(key, &data, &algorithm, &hash, &salt_len),
                        None => Err("This VPN has no client key in Fran".to_string()),
                    };
                    let (signature, error) = match reply {
                        Ok(signature) => (Some(signature), None),
                        Err(error) => (None, Some(error)),
                    };
                    if send(&mut writer, &ToWorker::SignReply { id, signature, error }).await.is_err() {
                        return Outcome::Failed("Fran's VPN service stopped answering".to_string());
                    }
                }
                FromWorker::AdapterUp { adapter } => {
                    self.adapter.set_addresses(adapter.addr4.map(|(addr, _)| addr), adapter.addr6.map(|(addr, _)| addr));
                    self.adapter.set_dns(adapter.dns);
                    let address = adapter.addr4.map(|(addr, _)| addr.to_string()).or_else(|| adapter.addr6.map(|(addr, _)| addr.to_string()));
                    self.update(|state| {
                        state.phase = Phase::Up;
                        state.error = None;
                        state.address = address;
                    });
                }
                FromWorker::Handshake => self.update(|state| {
                    if state.phase == Phase::Reconnecting {
                        state.phase = Phase::Up;
                        state.error = None;
                    }
                }),
                FromWorker::TunDown => {
                    self.adapter.cut();
                    self.update(|state| {
                        if state.phase == Phase::Up {
                            state.phase = Phase::Reconnecting;
                        }
                    });
                }
                FromWorker::Stats { bytes_in, bytes_out } => self.state.send_modify(|state| {
                    state.bytes_in = bytes_in;
                    state.bytes_out = bytes_out;
                }),
                FromWorker::TunFailed { message } => return Outcome::Failed(message),
                FromWorker::Refused { message } => return Outcome::Failed(message),
                FromWorker::EvalFailed { message } => return Outcome::Failed(format!("OpenVPN refused the profile: {message}")),
                FromWorker::Ended { error } => {
                    self.adapter.cut();
                    return pending.unwrap_or_else(|| match error {
                        Some(error) => Outcome::Failed(error),
                        None => Outcome::Stopped,
                    });
                }
                FromWorker::Hello { .. } | FromWorker::Evaluated { .. } | FromWorker::Log { .. } | FromWorker::TunUp { .. } => {}
            }
        }
    }

    fn finish(&self, reason: Option<String>) {
        self.adapter.cut();
        if let Ok(mut current) = self.prompt.lock() {
            current.take();
        }
        self.update(|state| {
            state.error = state.error.take().or(reason);
            state.phase = Phase::Down;
        });
    }

    pub fn state(&self) -> TunnelState {
        self.state.borrow().clone()
    }

    pub fn alive(&self) -> bool {
        self.state.borrow().phase != Phase::Down
    }

    pub async fn wait_up(&self, timeout: Duration) -> Result<(), String> {
        let mut changes = self.state.subscribe();
        let waiting = async {
            loop {
                let state = changes.borrow_and_update().clone();
                match state.phase {
                    Phase::Up => return Ok(()),
                    Phase::Down => return Err(state.error.unwrap_or_else(|| format!("VPN {} was turned off", self.label))),
                    Phase::Connecting | Phase::Reconnecting => {}
                }
                if changes.changed().await.is_err() {
                    return Err(format!("VPN {} was turned off", self.label));
                }
            }
        };
        match tokio::time::timeout(timeout, waiting).await {
            Ok(result) => result,
            Err(_) => Err(self.state().error.unwrap_or_else(|| format!("VPN {} didn't connect in time", self.label))),
        }
    }

    /// Waits while a prompt is open in the window, since the login can't finish without it.
    pub async fn wait_up_with_prompts(&self, timeout: Duration) -> Result<(), String> {
        loop {
            match self.wait_up(timeout).await {
                Err(_) if self.alive() && self.prompt().is_some() => continue,
                result => return result,
            }
        }
    }

    pub async fn stop(&self) {
        if !self.alive() {
            return;
        }
        self.stop.cancel();
        let mut changes = self.state.subscribe();
        let ended = async {
            while changes.borrow_and_update().phase != Phase::Down {
                if changes.changed().await.is_err() {
                    break;
                }
            }
        };
        if tokio::time::timeout(STOP_GRACE * 2, ended).await.is_err() {
            self.finish(None);
        }
    }

    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<SystemStream> {
        self.wait_up(timeout).await.map_err(io::Error::other)?;
        self.adapter.connect(host, port, timeout).await
    }
}
