//! Own tunnels and system mode against OpenVPN 2.6 servers in Docker, the lab from the openvpn-rust-bindings repo.
//! For own tunnels the `fran-vpn` worker runs OpenVPN 3 (`cargo build -p vpn-worker` first), Fran signs for its client key, and
//! traffic goes through the userspace stack to an echo server that's only reachable inside the tunnel. System mode
//! runs the installed OpenVPN instead and only needs `e2e` plus `FRAN_E2E_SYSTEM_VPN=1`.
//! The lab servers have no `duplicate-cn` and every profile uses the same client certificate, so two cases on one server would kick each other off.

use std::{
    collections::HashMap,
    future::Future,
    net::Ipv4Addr,
    pin::Pin,
    process::Command,
    sync::Arc,
    time::Duration,
};

use fran_lib::vpn::{
    config, keys,
    frames::Login,
    tunnel::{Tunnel, TunnelStart, WorkerStart},
};
#[cfg(target_os = "linux")]
use fran_lib::vpn::frames::{self, AdapterOptions, Frame, FromWorker, ToWorker};
use libtest_mimic::{Failed, Trial};
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
    runners::SyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::support::TestResult;

const ENTRYPOINT: &[u8] = include_bytes!("../../../../openvpn-rust-bindings/lab/entrypoint.sh");
const ECHO_PORT: u16 = 7000;
const TIMEOUT: Duration = Duration::from_secs(40);

const PROFILES: &[&str] = &["client-tcp.ovpn", "client-udp.ovpn", "client-userpass.ovpn"];

pub struct Lab {
    profiles: HashMap<&'static str, String>,
    _container: Container<GenericImage>,
    _docker: crate::docker::DockerHost,
}

impl Lab {
    fn profile(&self, name: &str) -> Result<String, String> {
        self.profiles.get(name).cloned().ok_or_else(|| format!("{name} wasn't read from the lab"))
    }
}

// Read before the tests run, since testcontainers' blocking calls can't be made inside the tests' runtime.
fn read_profile(container: &Container<GenericImage>, name: &str, host: &str, ports: &HashMap<&str, u16>) -> Result<String, String> {
    let mut result = container
        .exec(ExecCommand::new(["cat", &format!("/out/{name}")]))
        .map_err(|error| format!("Couldn't read {name}: {error}"))?;
    let bytes = result.stdout_to_vec().map_err(|error| format!("Couldn't read {name}: {error}"))?;
    let mut profile = String::from_utf8(bytes).map_err(|_| format!("{name} isn't text"))?;
    for (placeholder, port) in ports {
        profile = profile.replace(placeholder, &format!("{host} {port}"));
    }
    Ok(profile)
}

// With Docker in WSL, UDP doesn't come through Windows' localhost, so the WSL machine's own address is used.
pub(crate) fn lab_host(container: &Container<GenericImage>) -> Result<String, String> {
    if let Ok(host) = std::env::var("OVPN_LAB_HOST") {
        return Ok(host);
    }
    let host = container.get_host().map_err(|error| format!("No host for the lab: {error}"))?.to_string();
    let loopback = host == "localhost" || host == "127.0.0.1";
    if cfg!(windows) && loopback {
        let output = Command::new("wsl.exe")
            .args(["-e", "hostname", "-I"])
            .output()
            .map_err(|error| format!("Couldn't ask WSL for its address: {error}"))?;
        let text = String::from_utf8_lossy(&output.stdout);
        return text.split_whitespace().next().map(str::to_string).ok_or_else(|| "WSL reported no address".to_string());
    }
    Ok(if loopback { "127.0.0.1".to_string() } else { host })
}

fn start_lab() -> Result<Lab, String> {
    let docker = crate::docker::prepare()?;
    let container = GenericImage::new("alpine", "3.22")
        .with_exposed_port(1194.tcp())
        .with_exposed_port(1194.udp())
        .with_exposed_port(1195.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Initialization Sequence Completed"))
        .with_copy_to("/entrypoint.sh", ENTRYPOINT.to_vec())
        .with_cmd([
            "sh",
            "-c",
            "apk add --no-cache openvpn openssl socat >/dev/null \
             && (socat TCP-LISTEN:7000,fork,reuseaddr EXEC:cat &) \
             && exec sh /entrypoint.sh",
        ])
        .with_privileged(true)
        .with_label("fran-e2e", "vpn")
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .map_err(|error| format!("The VPN lab didn't start: {error}"))?;
    let port = |port| container.get_host_port_ipv4(port).map_err(|error| format!("No mapped port: {error}"));
    let ports = HashMap::from([("@tcp@", port(1194.tcp())?), ("@udp@", port(1194.udp())?), ("@userpass@", port(1195.tcp())?)]);
    let host = lab_host(&container)?;
    let mut profiles = HashMap::new();
    for name in PROFILES {
        profiles.insert(*name, read_profile(&container, name, &host, &ports)?);
    }
    Ok(Lab { profiles, _container: container, _docker: docker })
}

/// What `VpnLeg` builds from a saved profile, done here from the parsed file without a vault.
fn start_for(name: &str, text: &str, login: Option<Login>) -> TestResult<TunnelStart> {
    let parsed = config::parse(text, name, None)?;
    let profile = parsed.profile;
    let key_text = parsed.private_key.ok_or("the lab profile has no key")?;
    let (key, _) = keys::read_client_key(&key_text)?;
    let mut certs = keys::pem_blocks(&profile.cert)?.into_iter().filter(|block| block.label == "CERTIFICATE");
    let cert = certs.next().ok_or("the lab profile has no certificate")?;
    let config = config::core_profile(&profile, parsed.tls_key.as_deref().map(|key| key.as_str()))?;
    assert!(!config.contains("PRIVATE KEY"), "the key went into the profile OpenVPN gets");
    Ok(TunnelStart {
        profile_id: name.to_string(),
        label: name.to_string(),
        worker: WorkerStart::OpenVpn { config, cert: keys::to_pem("CERTIFICATE", &cert.der), chain: String::new(), key: Some(Arc::new(key)), login },
        timeout: TIMEOUT,
    })
}

fn server_address(tunnel: &Tunnel) -> TestResult<Ipv4Addr> {
    let address: Ipv4Addr = tunnel.state().address.ok_or("the tunnel has no address")?.parse()?;
    let octets = address.octets();
    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], 1))
}

async fn echo_through(name: &str, text: String, login: Option<Login>) -> TestResult {
    let tunnel = Tunnel::spawn(start_for(name, &text, login)?, Arc::new(|| {}))?;
    tunnel.wait_up(TIMEOUT).await?;
    let server = server_address(&tunnel)?;

    let mut stream = tunnel.connect(&server.to_string(), ECHO_PORT, TIMEOUT).await?;
    let message: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let sending = async {
        writer.write_all(&message).await?;
        Ok::<_, std::io::Error>(())
    };
    let mut echoed = vec![0u8; message.len()];
    let receiving = reader.read_exact(&mut echoed);
    let (sent, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(sending, receiving) }).await?;
    sent?;
    received?;
    assert!(echoed == message, "the echo came back different");
    drop(stream);

    let refused = tunnel.connect(&server.to_string(), 9, Duration::from_secs(10)).await;
    assert!(refused.is_err(), "a closed port accepted the connection");

    tunnel.stop().await;
    assert!(!tunnel.alive(), "the tunnel is still up after stop");
    Ok(())
}

async fn tcp_tunnel_carries_a_stream(lab: &Lab) -> TestResult {
    echo_through("client-tcp.ovpn", lab.profile("client-tcp.ovpn")?, None).await
}

async fn udp_tunnel_carries_a_stream(lab: &Lab) -> TestResult {
    echo_through("client-udp.ovpn", lab.profile("client-udp.ovpn")?, None).await
}

async fn password_login_and_a_wrong_one(lab: &Lab) -> TestResult {
    let login = |password: &str| Login { username: "lab".to_string(), password: password.to_string(), response: String::new(), dynamic_cookie: String::new() };
    echo_through("client-userpass.ovpn", lab.profile("client-userpass.ovpn")?, Some(login("labpass"))).await?;

    let text = lab.profile("client-userpass.ovpn")?;
    let tunnel = Tunnel::spawn(start_for("client-userpass.ovpn", &text, Some(login("wrong")))?, Arc::new(|| {}))?;
    let error = tunnel.wait_up(TIMEOUT).await.err().ok_or("a wrong password connected")?;
    assert!(error.contains("refused the login"), "{error}");
    Ok(())
}

/// The installed OpenVPN on for the computer, as the app runs it: Interactive Service, pkexec or osascript, the
/// management connection checked by owner, Fran signing for the key, and a connection bound to the VPN's adapter.
/// Needs OpenVPN 2.6+ and admin rights (on Windows an admin or "OpenVPN Administrators" member), so it only runs
/// with `FRAN_E2E_SYSTEM_VPN=1`.
async fn system_mode_carries_a_stream(lab: &Lab) -> TestResult {
    use fran_lib::vpn::system::{PromptSlots, SystemStart, SystemVpn};
    let text = lab.profile("client-tcp.ovpn")?;
    let parsed = config::parse(&text, "client-tcp.ovpn", None)?;
    let key_text = parsed.private_key.ok_or("the lab profile has no key")?;
    let (key, _) = keys::read_client_key(&key_text)?;
    let config = config::system_profile(&parsed.profile, parsed.tls_key.as_deref().map(|key| key.as_str()))?;
    assert!(!config.contains("PRIVATE KEY"), "the key went into the config the installed OpenVPN gets");

    let start = SystemStart {
        label: "lab".to_string(),
        config,
        key: Some(Arc::new(key)),
        login: None,
        program: None,
        use_vpn_dns: true,
        prompts: PromptSlots { password: None, code: None, challenge_id: "challenge".to_string(), pin_id: "pin".to_string() },
        management_wait: Duration::from_secs(180),
    };
    let vpn = SystemVpn::start(start, Arc::new(|| {})).await?;
    vpn.wait_up(TIMEOUT).await?;
    let address: Ipv4Addr = vpn.state().address.ok_or("the VPN has no address")?.parse()?;
    let octets = address.octets();
    let server = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);

    let mut stream = vpn.connect(&server.to_string(), ECHO_PORT, TIMEOUT).await?;
    let message: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let sending = async {
        writer.write_all(&message).await?;
        Ok::<_, std::io::Error>(())
    };
    let mut echoed = vec![0u8; message.len()];
    let receiving = reader.read_exact(&mut echoed);
    let (sent, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(sending, receiving) }).await?;
    sent?;
    received?;
    assert!(echoed == message, "the echo came back different");

    vpn.stop().await;
    assert!(!vpn.alive(), "OpenVPN is still running after stop");
    let mut after = [0u8; 1];
    assert!(stream.read(&mut after).await.is_err(), "a connection over the VPN kept working after it was turned off");
    Ok(())
}

#[cfg(target_os = "linux")]
fn adapter_with(address: Ipv4Addr) -> Option<String> {
    if_addrs::get_if_addrs().ok()?.into_iter().find(|interface| interface.ip() == std::net::IpAddr::V4(address)).map(|interface| interface.name)
}

#[cfg(target_os = "linux")]
async fn gone(address: Ipv4Addr) -> bool {
    for _ in 0..30 {
        if adapter_with(address).is_none() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Stops the service when the case ends, also when it fails halfway.
#[cfg(target_os = "linux")]
struct Service(std::process::Child);

#[cfg(target_os = "linux")]
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The frames until the service ends the session, looking for one that matches.
#[cfg(target_os = "linux")]
async fn read_until(reader: &mut fran_lib::vpn::system::service::Reader, wanted: impl Fn(&FromWorker) -> bool) -> TestResult<FromWorker> {
    let reading = async {
        loop {
            match frames::read_frame_async::<FromWorker>(reader).await? {
                Some(Frame::Message(message)) if wanted(&message) => return Ok::<_, std::io::Error>(Some(message)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    };
    tokio::time::timeout(TIMEOUT, reading).await??.ok_or_else(|| "the service closed the session first".into())
}

/// Fran's VPN service on for the computer: `fran-vpn --service everyone`, Fran signing for the key, the adapter's
/// address, routes and a 200 KB echo bound to it, then everything gone after stop and after Fran's connection drops.
/// The service refuses a profile with a script option and another protocol version. Needs root, `NET_ADMIN` and
/// `/dev/net/tun` (the `fran-linux-check` image), so it only runs with `FRAN_E2E_SERVICE_VPN=1`. Windows goes on
/// the manual list.
#[cfg(not(target_os = "linux"))]
async fn service_runs_a_vpn_for_the_computer(_lab: &Lab) -> TestResult {
    Err("The service case runs on Linux, in the fran-linux-check image".into())
}

#[cfg(target_os = "linux")]
async fn service_runs_a_vpn_for_the_computer(lab: &Lab) -> TestResult {
    use fran_lib::vpn::system::{
        PromptSlots,
        service::{self, ServiceStart, ServiceVpn},
    };

    let worker = std::env::var_os("FRAN_VPN_WORKER").ok_or("FRAN_VPN_WORKER isn't set")?;
    let _service = Service(Command::new(&worker).args(["--service", "everyone"]).spawn()?);
    for _ in 0..50 {
        if std::path::Path::new(vpn_proto::SERVICE_SOCKET).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let WorkerStart::OpenVpn { config, cert, key, .. } = start_for("client-tcp.ovpn", &lab.profile("client-tcp.ovpn")?, None)?.worker else {
        return Err("the lab profile isn't OpenVPN".into());
    };
    let make = |config: String| ServiceStart {
        label: "lab".to_string(),
        worker: WorkerStart::OpenVpn { config, cert: cert.clone(), chain: String::new(), key: key.clone(), login: None },
        options: AdapterOptions { route_all: false, use_vpn_dns: true },
        prompts: PromptSlots { password: None, code: None, challenge_id: "challenge".to_string(), pin_id: "pin".to_string() },
        timeout: TIMEOUT,
    };

    let vpn = ServiceVpn::start(make(config.clone()), Arc::new(|| {})).await?;
    vpn.wait_up(TIMEOUT).await?;
    let address: Ipv4Addr = vpn.state().address.ok_or("the VPN has no address")?.parse()?;
    let octets = address.octets();
    let server = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
    let adapter = adapter_with(address).ok_or("no adapter has the VPN's address")?;
    assert!(adapter.starts_with("franvpn"), "the address is on {adapter}");
    // /proc/net/route lists the destination in hex, in the kernel's (little endian) byte order.
    let network = format!("{:08X}", u32::from_le_bytes([octets[0], octets[1], octets[2], 0]));
    let routes = std::fs::read_to_string("/proc/net/route")?;
    let routed = routes.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.first() == Some(&adapter.as_str()) && fields.get(1) == Some(&network.as_str())
    });
    assert!(routed, "the computer doesn't route {server} through {adapter}:\n{routes}");

    let mut stream = vpn.connect(&server.to_string(), ECHO_PORT, TIMEOUT).await?;
    let message: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let sending = async {
        writer.write_all(&message).await?;
        Ok::<_, std::io::Error>(())
    };
    let mut echoed = vec![0u8; message.len()];
    let receiving = reader.read_exact(&mut echoed);
    let (sent, received) = tokio::time::timeout(TIMEOUT, async { tokio::join!(sending, receiving) }).await?;
    sent?;
    received?;
    assert!(echoed == message, "the echo came back different");

    vpn.stop().await;
    assert!(gone(address).await, "the adapter is still there after stop");
    let mut after = [0u8; 1];
    assert!(stream.read(&mut after).await.is_err(), "a connection over the VPN kept working after it was turned off");

    // The service checks the profile itself, whatever the app sends.
    let (mut reader, mut writer, _) = service::open().await.map_err(|error| error.message())?;
    let start_message = |config: String| ToWorker::Start {
        profile: config,
        cert: cert.clone(),
        chain: String::new(),
        gui_version: "e2e".to_string(),
        timeout_secs: 30,
        login: None,
        adapter: Some(AdapterOptions { route_all: false, use_vpn_dns: true }),
    };
    service::send(&mut writer, &start_message(format!("{config}up /bin/sh\n"))).await?;
    let refused = read_until(&mut reader, |message| matches!(message, FromWorker::Refused { .. })).await?;
    assert!(matches!(&refused, FromWorker::Refused { message } if message.contains("up")), "{refused:?}");

    let (mut reader, mut writer) = service::connect_raw().await?;
    service::send(&mut writer, &ToWorker::Hello { version: vpn_proto::PROTOCOL_VERSION + 1 }).await?;
    read_until(&mut reader, |message| matches!(message, FromWorker::Refused { .. })).await?;

    // The tunnel ends with Fran's connection, so a VPN never outlives Fran.
    let (mut reader, mut writer, _) = service::open().await.map_err(|error| error.message())?;
    service::send(&mut writer, &start_message(config.clone())).await?;
    let up = loop {
        let message = read_until(&mut reader, |message| matches!(message, FromWorker::AdapterUp { .. } | FromWorker::Sign { .. })).await?;
        match message {
            FromWorker::AdapterUp { adapter } => break adapter,
            FromWorker::Sign { id, data, algorithm, hash, salt_len } => {
                let key = key.as_ref().ok_or("no key")?;
                let signature = keys::sign(key, &data, &algorithm, &hash, &salt_len)?;
                service::send(&mut writer, &ToWorker::SignReply { id, signature: Some(signature), error: None }).await?;
            }
            _ => {}
        }
    };
    let address = up.addr4.ok_or("the adapter has no address")?.0;
    assert!(adapter_with(address).is_some());
    drop((reader, writer));
    assert!(gone(address).await, "the adapter stayed after Fran's connection closed");
    Ok(())
}

type LabCase = for<'a> fn(&'a Lab) -> Pin<Box<dyn Future<Output = TestResult> + 'a>>;

macro_rules! lab_cases {
    ($($name:ident),* $(,)?) => {
        vec![$((stringify!($name), (|lab| Box::pin($name(lab))) as LabCase)),*]
    };
}

fn cases() -> Vec<(&'static str, LabCase)> {
    lab_cases![
        tcp_tunnel_carries_a_stream,
        udp_tunnel_carries_a_stream,
        password_login_and_a_wrong_one,
        system_mode_carries_a_stream,
        service_runs_a_vpn_for_the_computer,
    ]
}

/// System mode and the service need admin rights (and system mode the installed OpenVPN), so they only run when asked for.
fn needs_asking(name: &str) -> bool {
    (name.starts_with("system_") && std::env::var_os("FRAN_E2E_SYSTEM_VPN").is_none())
        || (name.starts_with("service_") && std::env::var_os("FRAN_E2E_SERVICE_VPN").is_none())
}

fn run(lab: &Result<Arc<Lab>, String>, case: LabCase) -> Result<(), Failed> {
    let lab = lab.as_ref().map_err(|error| Failed::from(format!("the VPN lab isn't available: {error}")))?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(Failed::from)?;
    runtime.block_on(case(lab)).map_err(|error| Failed::from(error.to_string()))
}

/// `fran-vpn` is another package's binary, so Cargo doesn't hand its path to this test. It's built into the same
/// target folder as the test: `target/<profile>/fran-vpn`, next to `deps/` where the test runs from.
fn worker_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("FRAN_VPN_WORKER") {
        return path.into();
    }
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().and_then(|deps| deps.parent()).map(std::path::Path::to_path_buf).unwrap_or_default();
    dir.join(format!("fran-vpn{}", std::env::consts::EXE_SUFFIX))
}

/// Trials named `vpn::<case>`. The lab only starts when one of them is selected.
pub fn trials(selected: impl Fn(&str) -> bool, list_only: bool) -> (Vec<Trial>, Option<Arc<Result<Arc<Lab>, String>>>) {
    let worker = worker_path();
    if !list_only && !worker.is_file() {
        eprintln!("\n{} isn't built, own tunnel cases will fail. Run cargo build -p vpn-worker first.\n", worker.display());
    }
    // SAFETY: set before any trial thread starts.
    unsafe { std::env::set_var("FRAN_VPN_WORKER", &worker) };
    let cases = cases();
    let wanted = !list_only && cases.iter().any(|(name, _)| !needs_asking(name) && selected(&format!("vpn::{name}")));
    let lab = wanted.then(|| Arc::new(start_lab().map(Arc::new)));
    if let Some(Err(error)) = lab.as_deref() {
        eprintln!("\nThe VPN lab isn't available, its tests will fail:\n  {error}\n");
    }
    let trials = cases
        .into_iter()
        .map(|(name, case)| {
            let lab = lab.clone();
            Trial::test(format!("vpn::{name}"), move || match lab {
                Some(lab) => run(&lab, case),
                None => Err(Failed::from("the VPN lab wasn't started")),
            })
            .with_ignored_flag(needs_asking(name))
        })
        .collect();
    (trials, lab)
}
