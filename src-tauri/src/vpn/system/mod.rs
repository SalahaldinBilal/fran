pub mod adapter;
pub mod launch;
pub mod management;
pub mod service;
pub mod setup;
#[cfg(windows)]
pub mod win;

use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{mpsc, watch},
};
use zeroize::Zeroizing;

pub use adapter::SystemStream;
use adapter::Adapter;

use super::frames::Login;
use super::keys::{self, ClientKey};
use super::tunnel::{ChangeHook, Phase, TunnelState};
use crate::connections::SecretSlot;
use crate::error::{AppError, AppResult};
use management::{DynamicChallenge, Event};

const MIN_VERSION: (u32, u32) = (2, 6);
const STOP_GRACE: Duration = Duration::from_secs(5);

/// The slots a prompt in the window can ask for while the VPN is on.
#[derive(Clone)]
pub struct PromptSlots {
    pub password: Option<SecretSlot>,
    pub code: Option<SecretSlot>,
    pub challenge_id: String,
    pub pin_id: String,
}

/// Everything needed to turn a VPN on for the computer. The key stays in Fran and signs over the management connection.
pub struct SystemStart {
    pub label: String,
    pub config: String,
    pub key: Option<Arc<ClientKey>>,
    pub login: Option<Login>,
    pub program: Option<String>,
    pub use_vpn_dns: bool,
    pub prompts: PromptSlots,
    /// How long OpenVPN gets to connect to Fran. The admin password prompt on macOS and Linux happens inside it.
    pub management_wait: Duration,
}

/// Something the VPN needs typed in while it's on, like a new one-time code.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnPrompt {
    pub title: String,
    pub slots: Vec<SecretSlot>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnProgram {
    pub path: String,
    pub version: String,
}

fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(windows)]
    for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(var) {
            out.push(PathBuf::from(dir).join("OpenVPN").join("bin").join("openvpn.exe"));
        }
    }
    #[cfg(target_os = "macos")]
    out.extend(["/opt/homebrew/sbin/openvpn", "/usr/local/sbin/openvpn", "/opt/local/sbin/openvpn"].map(PathBuf::from));
    #[cfg(target_os = "linux")]
    out.extend(["/usr/sbin/openvpn", "/usr/bin/openvpn", "/usr/local/sbin/openvpn"].map(PathBuf::from));
    let name = if cfg!(windows) { "openvpn.exe" } else { "openvpn" };
    if let Some(path) = std::env::var_os("PATH") {
        out.extend(std::env::split_paths(&path).map(|dir| dir.join(name)));
    }
    out
}

/// "2.6.12" from `OpenVPN 2.6.12 x86_64-w64-mingw32 [SSL (OpenSSL)] ...`.
fn read_version(text: &str) -> Option<String> {
    let mut words = text.split_whitespace();
    words.find(|word| *word == "OpenVPN")?;
    let version = words.next()?;
    version.split('.').next()?.parse::<u32>().ok()?;
    Some(version.to_string())
}

fn new_enough(version: &str) -> bool {
    let mut parts = version.split(['.', '_', '-']).map(|part| part.parse::<u32>().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0)) >= MIN_VERSION
}

pub(crate) fn quiet_command(program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

async fn program_version(path: &Path) -> AppResult<String> {
    let output = tokio::time::timeout(Duration::from_secs(5), quiet_command(path).arg("--version").output())
        .await
        .map_err(|_| AppError::general(format!("{} didn't answer --version", path.display())))?
        .map_err(|error| AppError::general(format!("Couldn't run {}: {error}", path.display())))?;
    read_version(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| AppError::general(format!("{} doesn't look like OpenVPN", path.display())))
}

/// On Windows the service's own program, which is the one that runs. Elsewhere the configured program, else
/// the usual install folders and PATH. Anything older than 2.6 is refused.
pub async fn find_program(configured: Option<&str>) -> AppResult<OpenVpnProgram> {
    #[cfg(windows)]
    let (configured, service) = {
        let _ = configured;
        (None::<&str>, win::service_program().await)
    };
    #[cfg(not(windows))]
    let (configured, service) = (configured.map(str::trim).filter(|path| !path.is_empty()), None::<PathBuf>);
    let paths = match (service, configured) {
        (Some(path), _) => vec![path],
        (None, Some(path)) => vec![PathBuf::from(path)],
        (None, None) => candidates(),
    };
    let Some(path) = paths.into_iter().find(|path| path.is_file()) else {
        return Err(AppError::general(match configured {
            Some(path) => format!("There's no OpenVPN at {path}"),
            None => "OpenVPN isn't installed. Install OpenVPN 2.6 or newer.".to_string(),
        }));
    };
    let version = program_version(&path).await?;
    if !new_enough(&version) {
        return Err(AppError::general(format!("OpenVPN {version} is too old. Fran needs 2.6 or newer.")));
    }
    Ok(OpenVpnProgram { path: path.to_string_lossy().to_string(), version })
}

/// Short, since a Unix socket path inside it has to stay under 104 bytes on macOS.
fn private_dir() -> AppResult<PathBuf> {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let dir = std::env::temp_dir().join(format!("fran-vpn-{}", &id[..16]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

fn write_private(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// Where OpenVPN connects to Fran. Fran holds it before OpenVPN starts, so nothing else can take its place,
/// and checks who connects before saying anything.
enum Management {
    #[cfg(windows)]
    Tcp { listener: tokio::net::TcpListener, port: u16 },
    #[cfg(unix)]
    Unix { listener: tokio::net::UnixListener, path: PathBuf },
}

impl Management {
    fn open(dir: &Path) -> AppResult<Self> {
        #[cfg(windows)]
        {
            let _ = dir;
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let port = listener.local_addr()?.port();
            Ok(Self::Tcp { listener: tokio::net::TcpListener::from_std(listener)?, port })
        }
        #[cfg(unix)]
        {
            let path = dir.join("m.sock");
            Ok(Self::Unix { listener: tokio::net::UnixListener::bind(&path)?, path })
        }
    }

    /// What follows `--management`.
    fn args(&self) -> Vec<String> {
        match self {
            #[cfg(windows)]
            Self::Tcp { port, .. } => vec!["127.0.0.1".to_string(), port.to_string()],
            #[cfg(unix)]
            Self::Unix { path, .. } => vec![path.to_string_lossy().to_string(), "unix".to_string()],
        }
    }

    /// The first connection from the OpenVPN Fran started. Anything else is dropped.
    async fn accept(&self, process: &mut launch::Process, wait: Duration) -> AppResult<(Reader, Writer)> {
        let started = Instant::now();
        loop {
            if let Some(reason) = process.ended() {
                return Err(AppError::general(reason));
            }
            if started.elapsed() > wait {
                let detail = process.last_output().map(|line| format!(": {line}")).unwrap_or_default();
                return Err(AppError::general(format!("OpenVPN didn't connect to Fran in time{detail}")));
            }
            match self {
                #[cfg(windows)]
                Self::Tcp { listener, port } => {
                    let Ok(Ok((stream, peer))) = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await else {
                        continue;
                    };
                    // The service gave us the pid. Another program on this computer can't pass as it.
                    if win::owner_pid(peer.port(), *port) == Some(process.pid) {
                        let (read, write) = stream.into_split();
                        return Ok((Box::new(read), Box::new(write)));
                    }
                }
                #[cfg(unix)]
                Self::Unix { listener, .. } => {
                    let Ok(Ok((stream, _))) = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await else {
                        continue;
                    };
                    // OpenVPN runs as root here. The socket sits in a folder only this user can open.
                    if stream.peer_cred().is_ok_and(|cred| cred.uid() == 0) {
                        let (read, write) = stream.into_split();
                        return Ok((Box::new(read), Box::new(write)));
                    }
                }
            }
        }
    }
}

/// A VPN on for the whole computer, run by the installed OpenVPN.
pub struct SystemVpn {
    pub label: String,
    state: watch::Sender<TunnelState>,
    commands: mpsc::UnboundedSender<Zeroizing<String>>,
    answers: mpsc::UnboundedSender<HashMap<String, Zeroizing<String>>>,
    prompt: Mutex<Option<VpnPrompt>>,
    adapter: Adapter,
    dir: PathBuf,
    process: Mutex<Option<launch::Process>>,
    on_change: ChangeHook,
}

struct Session {
    login: Option<Login>,
    key: Option<Arc<ClientKey>>,
    slots: PromptSlots,
    code_used: bool,
    /// The server refused the login and a new one was asked for in the window.
    retry_password: bool,
    /// OpenVPN asked for the login and waits for an answer from the window. Whether it asked with a static challenge.
    waiting: Option<bool>,
    dynamic: Option<DynamicChallenge>,
    dynamic_answer: Option<(DynamicChallenge, Zeroizing<String>)>,
    /// What OpenVPN called the secret it asked for with `Need '...' password`, like a smartcard PIN.
    pin_for: Option<String>,
    last_log_error: Option<String>,
}

impl SystemVpn {
    pub async fn start(start: SystemStart, on_change: ChangeHook) -> AppResult<Arc<Self>> {
        let program = find_program(start.program.as_deref()).await?;
        let dir = private_dir()?;
        let started = Self::launch(start, Path::new(&program.path), dir.clone(), on_change).await;
        if started.is_err() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        started
    }

    async fn launch(start: SystemStart, program: &Path, dir: PathBuf, on_change: ChangeHook) -> AppResult<Arc<Self>> {
        let config = dir.join("profile.ovpn");
        write_private(&config, start.config.as_bytes())?;
        let management = Management::open(&dir)?;
        let mut process = launch::start(program, &dir, &config, &management.args()).await?;
        let (reader, mut writer) = match management.accept(&mut process, start.management_wait).await {
            Ok(halves) => halves,
            Err(error) => {
                process.kill();
                return Err(error);
            }
        };

        let (commands, mut outbox) = mpsc::unbounded_channel::<Zeroizing<String>>();
        let (answers, mut inbox) = mpsc::unbounded_channel();
        let (state, _) = watch::channel(TunnelState { phase: Phase::Connecting, error: None, address: None, bytes_in: 0, bytes_out: 0 });
        let vpn = Arc::new(Self {
            label: start.label.clone(),
            state,
            commands,
            answers,
            prompt: Mutex::new(None),
            adapter: Adapter::new(start.label.clone(), start.use_vpn_dns),
            dir,
            process: Mutex::new(Some(process)),
            on_change,
        });

        tokio::spawn(async move {
            while let Some(command) = outbox.recv().await {
                if writer.write_all(command.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                    break;
                }
            }
        });
        for command in ["version 3", "log on", "state on", "bytecount 2", "hold release"] {
            vpn.send(format!("{command}\n"));
        }

        let session_vpn = vpn.clone();
        let mut session = Session {
            login: start.login,
            key: start.key,
            slots: start.prompts,
            code_used: false,
            retry_password: false,
            waiting: None,
            dynamic: None,
            dynamic_answer: None,
            pin_for: None,
            last_log_error: None,
        };
        tokio::spawn(async move {
            let _keep = management;
            let mut lines = BufReader::new(reader).lines();
            let reason = loop {
                tokio::select! {
                    line = lines.next_line() => match line {
                        Ok(Some(line)) if line.len() <= management::MAX_LINE => session_vpn.handle(management::parse_line(line.trim_end()), &mut session),
                        Ok(Some(_)) => {}
                        Ok(None) => break None,
                        Err(error) => break Some(format!("The connection to OpenVPN broke: {error}")),
                    },
                    Some(values) = inbox.recv() => session_vpn.answer(values, &mut session),
                }
            };
            session_vpn.finish(reason.or(session.last_log_error.take()));
        });
        Ok(vpn)
    }

    fn send(&self, command: String) {
        let _ = self.commands.send(Zeroizing::new(command));
    }

    fn update(&self, change: impl FnOnce(&mut TunnelState)) {
        self.state.send_modify(change);
        (self.on_change)();
    }

    /// Says why and asks OpenVPN to stop.
    fn fail(&self, message: String) {
        self.update(|state| state.error = Some(message));
        self.send("signal SIGTERM\n".to_string());
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

    /// What the window answered to `prompt`, keyed by slot id.
    pub fn submit(&self, values: HashMap<String, Zeroizing<String>>) {
        let _ = self.answers.send(values);
    }

    fn send_login(&self, session: &mut Session, challenge: bool) {
        session.waiting = None;
        let Some(login) = &session.login else {
            return self.fail(format!("VPN {} asked for a user name and password. Choose that login in its settings.", self.label));
        };
        let response = challenge.then_some(login.response.as_str());
        match management::login_commands(&login.username, &login.password, response) {
            Ok(commands) => self.send(commands.to_string()),
            Err(error) => return self.fail(error.message),
        }
        session.code_used |= challenge;
    }

    fn answer(&self, values: HashMap<String, Zeroizing<String>>, session: &mut Session) {
        self.clear_prompt();
        if let Some(name) = session.pin_for.take() {
            let pin = values.get(&session.slots.pin_id).cloned().unwrap_or_default();
            match management::password_command(&name, &pin) {
                Ok(command) => self.send(command.to_string()),
                Err(error) => self.fail(error.message),
            }
            return;
        }
        if let Some(dynamic) = session.dynamic.take() {
            let response = values.get(&session.slots.challenge_id).cloned().unwrap_or_default();
            if session.waiting.take().is_some() {
                match management::challenge_commands(&dynamic, &response) {
                    Ok(commands) => self.send(commands.to_string()),
                    Err(error) => self.fail(error.message),
                }
            } else {
                session.dynamic_answer = Some((dynamic, response));
            }
            return;
        }
        if let Some(login) = session.login.as_mut() {
            if let Some(password) = session.slots.password.as_ref().and_then(|slot| values.get(&slot.id)) {
                login.password = password.to_string();
            }
            if let Some(code) = session.slots.code.as_ref().and_then(|slot| values.get(&slot.id)) {
                login.response = code.to_string();
                session.code_used = false;
            }
        }
        session.retry_password = false;
        if let Some(challenge) = session.waiting {
            self.send_login(session, challenge);
        }
    }

    fn handle(&self, event: Event, session: &mut Session) {
        match event {
            Event::Hold => self.send("hold release\n".to_string()),
            Event::NeedAuth { challenge } => {
                if let Some((dynamic, response)) = session.dynamic_answer.take() {
                    match management::challenge_commands(&dynamic, &response) {
                        Ok(commands) => self.send(commands.to_string()),
                        Err(error) => self.fail(error.message),
                    }
                    return;
                }
                if session.dynamic.is_some() || session.retry_password {
                    session.waiting = Some(challenge);
                    return;
                }
                if challenge && session.code_used {
                    session.waiting = Some(true);
                    let Some(code) = session.slots.code.clone() else {
                        return self.fail(format!("VPN {} asked for a code it doesn't have a prompt for", self.label));
                    };
                    return self.ask(VpnPrompt { title: format!("VPN {} asks for a new code", self.label), slots: vec![code] });
                }
                self.send_login(session, challenge);
            }
            Event::NeedPassword { name } => {
                let slot = SecretSlot::one_time(session.slots.pin_id.clone(), format!("PIN for {name}"));
                session.pin_for = Some(name.clone());
                self.ask(VpnPrompt { title: format!("VPN {} needs the PIN for {name}", self.label), slots: vec![slot] });
            }
            Event::AuthFailed { dynamic: Some(dynamic) } => {
                let label = if dynamic.text.trim().is_empty() { "Code".to_string() } else { dynamic.text.clone() };
                let slot = SecretSlot::one_time(session.slots.challenge_id.clone(), label);
                session.dynamic = Some(dynamic);
                self.ask(VpnPrompt { title: format!("VPN {} asks for one more sign-in step", self.label), slots: vec![slot] });
            }
            Event::AuthFailed { dynamic: None } => {
                let Some(password) = session.slots.password.clone() else {
                    return self.update(|state| state.error = Some("The VPN server refused the login".to_string()));
                };
                session.retry_password = true;
                session.code_used = false;
                let mut slots = vec![password];
                slots.extend(session.slots.code.clone());
                self.ask(VpnPrompt { title: format!("The VPN server refused the login for {}. Try again.", self.label), slots });
            }
            Event::Sign(request) => {
                let signed = match (&session.key, request.message) {
                    (None, _) => Err("This VPN has no client key in Fran".to_string()),
                    (Some(_), false) => Err("OpenVPN sent a hash instead of the message to sign".to_string()),
                    (Some(key), true) => keys::sign(key, &request.data, &request.algorithm, &request.hash, &request.salt_len),
                };
                match signed {
                    Ok(signature) => self.send(management::signature_command(&signature)),
                    Err(error) => {
                        self.update(|state| state.error = Some(format!("Signing with the client key failed: {error}")));
                        self.send("pk-sig\nEND\n".to_string());
                    }
                }
            }
            Event::State { name, address, address6 } => match name.as_str() {
                "CONNECTED" => {
                    self.adapter.set_addresses(address.as_deref().and_then(|address| address.parse::<Ipv4Addr>().ok()), address6);
                    self.update(|state| {
                        state.phase = Phase::Up;
                        state.error = None;
                        state.address = address;
                    });
                }
                "EXITING" => {}
                _ => self.update(|state| {
                    if state.phase == Phase::Up {
                        state.phase = Phase::Reconnecting;
                    }
                }),
            },
            Event::Bytes { bytes_in, bytes_out } => self.state.send_modify(|state| {
                state.bytes_in = bytes_in;
                state.bytes_out = bytes_out;
            }),
            Event::Dns(servers) => self.adapter.set_dns(servers),
            Event::Fatal(text) => self.update(|state| state.error = Some(text)),
            Event::Log { error: true, text } => session.last_log_error = Some(text),
            Event::Log { .. } | Event::Other => {}
        }
    }

    fn finish(&self, reason: Option<String>) {
        self.adapter.cut();
        if let Ok(mut current) = self.prompt.lock() {
            current.take();
        }
        if let Ok(mut process) = self.process.lock() {
            let ended = process.as_mut().and_then(launch::Process::ended);
            process.take();
            self.update(|state| {
                state.error = state.error.take().or(ended).or(reason);
                state.phase = Phase::Down;
            });
        }
        let _ = std::fs::remove_dir_all(&self.dir);
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
        self.send("signal SIGTERM\n".to_string());
        let mut changes = self.state.subscribe();
        let ended = async {
            while changes.borrow_and_update().phase != Phase::Down {
                if changes.changed().await.is_err() {
                    break;
                }
            }
        };
        if tokio::time::timeout(STOP_GRACE, ended).await.is_err() {
            if let Ok(mut process) = self.process.lock() {
                if let Some(process) = process.as_mut() {
                    process.kill();
                }
            }
            self.finish(None);
        }
    }

    /// A TCP connection that can only leave through this VPN's adapter, and that ends when the VPN is turned off.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<SystemStream> {
        self.wait_up(timeout).await.map_err(io::Error::other)?;
        self.adapter.connect(host, port, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(read_version("OpenVPN 2.6.12 x86_64-w64-mingw32 [SSL (OpenSSL)]").as_deref(), Some("2.6.12"));
        assert_eq!(read_version("nothing here"), None);
        assert!(new_enough("2.6.0") && new_enough("2.7_beta1") && new_enough("3.0"));
        assert!(!new_enough("2.5.9") && !new_enough("2.4"));
    }
}
