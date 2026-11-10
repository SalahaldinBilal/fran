//! Own WireGuard tunnels against kernel WireGuard in Docker. The `fran-vpn` worker runs boringtun, and traffic goes
//! through Fran's userspace stack to an echo server that only listens on the server's tunnel address. The container
//! needs the host kernel's WireGuard module, which WSL 2 and current Linux kernels have. Uses the worker path
//! `vpn::trials` sets, so it's registered after that.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use fran_lib::vpn::{
    frames::WireGuardStart,
    tunnel::{Tunnel, TunnelStart, WorkerStart},
    wireguard,
};
use libtest_mimic::{Failed, Trial};
use testcontainers::{
    Container, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::SyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::support::TestResult;

const PORT: u16 = 51820;
const ECHO_PORT: u16 = 7000;
const SERVER_ADDRESS: &str = "10.99.0.1";
const CLIENT_ADDRESS: &str = "10.99.0.2";
const TIMEOUT: Duration = Duration::from_secs(40);

const SCRIPT: &str = "apk add --no-cache wireguard-tools iproute2 socat >/dev/null \
    && printf '%s' \"$SERVER_KEY\" > /server.key \
    && ip link add wg0 type wireguard \
    && wg set wg0 listen-port 51820 private-key /server.key peer \"$CLIENT_PUBLIC\" allowed-ips 10.99.0.2/32 \
    && ip address add 10.99.0.1/24 dev wg0 \
    && ip link set wg0 up \
    && (socat TCP-LISTEN:7000,bind=10.99.0.1,fork,reuseaddr EXEC:cat &) \
    && echo wireguard-ready \
    && exec sleep infinity";

pub struct Lab {
    host: String,
    port: u16,
    server_public: String,
    client_private: String,
    _container: Container<GenericImage>,
    _docker: crate::docker::DockerHost,
}

fn start_lab() -> Result<Lab, String> {
    let docker = crate::docker::prepare()?;
    let (server_private, server_public) = wireguard::generate();
    let (client_private, client_public) = wireguard::generate();
    let container = GenericImage::new("alpine", "3.22")
        .with_exposed_port(PORT.udp())
        .with_wait_for(WaitFor::message_on_stdout("wireguard-ready"))
        .with_env_var("SERVER_KEY", server_private.as_str())
        .with_env_var("CLIENT_PUBLIC", client_public)
        .with_cmd(["sh", "-c", SCRIPT])
        .with_privileged(true)
        .with_label("fran-e2e", "wireguard")
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .map_err(|error| format!("The WireGuard lab didn't start: {error}"))?;
    let port = container.get_host_port_ipv4(PORT.udp()).map_err(|error| format!("No mapped port: {error}"))?;
    let host = crate::vpn::lab_host(&container)?;
    Ok(Lab { host, port, server_public, client_private: client_private.to_string(), _container: container, _docker: docker })
}

fn start(lab: &Lab, peer_public_key: &str) -> TunnelStart {
    TunnelStart {
        profile_id: "wireguard".to_string(),
        label: "wireguard".to_string(),
        worker: WorkerStart::WireGuard(WireGuardStart {
            private_key: lab.client_private.clone(),
            peer_public_key: peer_public_key.to_string(),
            preshared_key: None,
            endpoint_host: lab.host.clone(),
            endpoint_port: lab.port,
            allowed_ips: vec![(SERVER_ADDRESS.parse().unwrap(), 24)],
            keepalive_secs: None,
            addresses: vec![(CLIENT_ADDRESS.parse().unwrap(), 24)],
            dns: Vec::new(),
            search_domains: Vec::new(),
            mtu: None,
        }),
        timeout: TIMEOUT,
    }
}

async fn tunnel_carries_a_stream(lab: &Lab) -> TestResult {
    let tunnel = Tunnel::spawn(start(lab, &lab.server_public), Arc::new(|| {}))?;
    tunnel.wait_up(TIMEOUT).await?;
    assert_eq!(tunnel.state().address.as_deref(), Some(CLIENT_ADDRESS));

    let mut stream = tunnel.connect(SERVER_ADDRESS, ECHO_PORT, TIMEOUT).await?;
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

    tunnel.stop().await;
    assert!(!tunnel.alive(), "the tunnel is still up after stop");
    Ok(())
}

/// WireGuard never refuses anything, so a wrong key looks like silence. The error has to say what to check.
async fn a_wrong_server_key_says_so(lab: &Lab) -> TestResult {
    let (_, someone_else) = wireguard::generate();
    let tunnel = Tunnel::spawn(start(lab, &someone_else), Arc::new(|| {}))?;
    let error = tunnel.wait_up(Duration::from_secs(12)).await.err().ok_or("a wrong server key connected")?;
    assert!(error.contains("No answer from the WireGuard server"), "{error}");
    tunnel.stop().await;
    Ok(())
}

type LabCase = for<'a> fn(&'a Lab) -> Pin<Box<dyn Future<Output = TestResult> + 'a>>;

fn cases() -> Vec<(&'static str, LabCase)> {
    vec![
        ("tunnel_carries_a_stream", |lab| Box::pin(tunnel_carries_a_stream(lab))),
        ("a_wrong_server_key_says_so", |lab| Box::pin(a_wrong_server_key_says_so(lab))),
    ]
}

fn run(lab: &Result<Arc<Lab>, String>, case: LabCase) -> Result<(), Failed> {
    let lab = lab.as_ref().map_err(|error| Failed::from(format!("the WireGuard lab isn't available: {error}")))?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(Failed::from)?;
    runtime.block_on(case(lab)).map_err(|error| Failed::from(error.to_string()))
}

/// Trials named `wireguard::<case>`. The lab only starts when one of them is selected.
pub fn trials(selected: impl Fn(&str) -> bool, list_only: bool) -> (Vec<Trial>, Option<Arc<Result<Arc<Lab>, String>>>) {
    let cases = cases();
    let wanted = !list_only && cases.iter().any(|(name, _)| selected(&format!("wireguard::{name}")));
    let lab = wanted.then(|| Arc::new(start_lab().map(Arc::new)));
    if let Some(Err(error)) = lab.as_deref() {
        eprintln!("\nThe WireGuard lab isn't available, its tests will fail:\n  {error}\n");
    }
    let trials = cases
        .into_iter()
        .map(|(name, case)| {
            let lab = lab.clone();
            Trial::test(format!("wireguard::{name}"), move || match lab {
                Some(lab) => run(&lab, case),
                None => Err(Failed::from("the WireGuard lab wasn't started")),
            })
        })
        .collect();
    (trials, lab)
}
