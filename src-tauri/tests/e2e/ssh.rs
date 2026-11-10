//! SSH, routes, forwards and SFTP against real OpenSSH servers. Only the jump host's port is published, so the
//! target and the database can only be reached through it.

use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use fran_lib::connections::SecretBag;
use fran_lib::db::{DriverOptions, postgres::PostgresOptions, session::ContextAccess};
use fran_lib::error::{AppError, ErrorDetail};
use fran_lib::ssh::{
    HostKeyInfo, SshAccess, SshConnection, SshHandle, SshTunnel, forward_local,
    known_hosts::KnownHosts,
    policy::ChannelPolicy,
    route::{Hop, HopAuth, SshRoute},
    sftp::{
        SftpConn,
        transfer::{self, Control, Direction, TransferEvent},
    },
};
use libtest_mimic::{Failed, Trial};
use russh::ChannelMsg;
use tauri::ipc::{Channel, InvokeResponseBody};
use testcontainers::{Container, GenericImage, ImageExt, core::IntoContainerPort, core::WaitFor, runners::SyncRunner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::support::TestResult;

const PASSWORD: &str = "fran-e2e";
const TIMEOUT: Duration = Duration::from_secs(30);
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const REMOTE_PORT: u32 = 40_123;

// Root logs in with a password and forwarding is on, which a real server should never allow. Fine for a throwaway container.
const SSHD: &str = "apk add --no-cache openssh openssh-sftp-server >/dev/null \
    && ssh-keygen -A \
    && echo 'root:fran-e2e' | chpasswd \
    && touch /fran-$ROLE \
    && exec /usr/sbin/sshd -D -e -o PermitRootLogin=yes -o PasswordAuthentication=yes -o AllowTcpForwarding=yes";

pub struct Lab {
    jump_host: String,
    jump_port: u16,
    target: String,
    db: String,
    _containers: Vec<Container<GenericImage>>,
    _docker: crate::docker::DockerHost,
}

type LabCase = for<'a> fn(&'a Lab) -> Pin<Box<dyn Future<Output = TestResult> + 'a>>;

macro_rules! lab_cases {
    ($($name:ident),* $(,)?) => {
        vec![$((stringify!($name), (|lab| Box::pin($name(lab))) as LabCase)),*]
    };
}

fn cases() -> Vec<(&'static str, LabCase)> {
    lab_cases![
        one_hop_asks_for_an_unknown_key,
        two_hops_ask_for_the_second_key,
        changed_key_on_the_second_hop_stops,
        pty_runs_echo,
        postgres_through_the_route,
        local_forward_reaches_the_database,
        remote_forward_reaches_this_computer,
        sftp_round_trip,
        sftp_cancel_deletes_the_partial_file,
        sftp_overwrite_keeps_the_original_until_done,
    ]
}

fn start_lab() -> Result<Lab, String> {
    let docker = crate::docker::prepare()?;
    let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let network = format!("fran-e2e-{id}");
    fn failed(what: &'static str) -> impl Fn(testcontainers::TestcontainersError) -> String {
        move |error| format!("{what} didn't start: {error}")
    }

    let sshd = |role: &str, name: &str| {
        GenericImage::new("alpine", "3.20")
            .with_exposed_port(22.tcp())
            .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
            .with_cmd(["sh", "-c", SSHD])
            .with_env_var("ROLE", role)
            .with_network(network.clone())
            .with_container_name(name)
            .with_label("fran-e2e", "ssh")
            .with_startup_timeout(READY_TIMEOUT)
    };

    let target = format!("fran-e2e-target-{id}");
    let db = format!("fran-e2e-db-{id}");
    let jump = sshd("jump", &format!("fran-e2e-jump-{id}")).start().map_err(failed("The jump host"))?;
    let target_container = sshd("target", &target).start().map_err(failed("The target host"))?;
    let db_container = GenericImage::new("postgres", "17")
        .with_wait_for(WaitFor::message_on_stderr("database system is ready to accept connections"))
        .with_env_var("POSTGRES_PASSWORD", PASSWORD)
        .with_network(network.clone())
        .with_container_name(&db)
        .with_label("fran-e2e", "ssh")
        .with_startup_timeout(READY_TIMEOUT)
        .start()
        .map_err(failed("Postgres"))?;

    let jump_host = match jump.get_host().map_err(failed("The jump host"))?.to_string() {
        host if host == "localhost" => "127.0.0.1".to_string(),
        host => host,
    };
    let jump_port = jump.get_host_port_ipv4(22).map_err(failed("The jump host"))?;
    Ok(Lab { jump_host, jump_port, target, db, _containers: vec![jump, target_container, db_container], _docker: docker })
}

fn hop(label: &str, host: &str, port: u16) -> Hop {
    Hop {
        label: label.to_string(),
        host: host.to_string(),
        port,
        user: "root".to_string(),
        auth: HopAuth::Password(Zeroizing::new(PASSWORD.to_string())),
        keepalive_secs: 0,
    }
}

impl Lab {
    fn jump_route(&self) -> SshRoute {
        SshRoute { hops: vec![hop("jump", &self.jump_host, self.jump_port)], proxy: None, vpn: None }
    }

    fn target_route(&self) -> SshRoute {
        SshRoute { hops: vec![hop("jump", &self.jump_host, self.jump_port), hop("target", &self.target, 22)], proxy: None, vpn: None }
    }
}

fn fresh_known_hosts() -> KnownHosts {
    KnownHosts::load(std::env::temp_dir().join("fran-e2e").join(format!("ssh-{}.json", uuid::Uuid::new_v4())))
}

fn unknown_key(error: &AppError) -> Option<(HostKeyInfo, Option<usize>)> {
    match &error.detail {
        ErrorDetail::UnknownHostKey { key, hop, .. } => Some((key.clone(), hop.as_ref().map(|hop| hop.index))),
        _ => None,
    }
}

/// Connects, trusting each new key the way the prompt does when the user accepts it.
async fn connect_trusting(route: &SshRoute, known_hosts: &KnownHosts, policy: Arc<ChannelPolicy>) -> TestResult<SshConnection> {
    for _ in 0..=route.hops.len() {
        match SshConnection::open_with(route, known_hosts, TIMEOUT, policy.clone()).await {
            Ok(connection) => return Ok(connection),
            Err(error) => match unknown_key(&error) {
                Some((key, _)) => known_hosts.trust(key)?,
                None => return Err(error.into()),
            },
        }
    }
    Err("still asking for host keys after trusting every hop".into())
}

async fn exec(handle: &SshHandle, command: &str, pty: bool) -> TestResult<String> {
    let mut channel = handle.channel_open_session().await?;
    if pty {
        channel.request_pty(true, "xterm-256color", 80, 24, 0, 0, &[]).await?;
    }
    channel.exec(true, command).await?;
    let mut output = Vec::new();
    let collect = async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => output.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    tokio::time::timeout(TIMEOUT, collect).await.map_err(|_| format!("`{command}` didn't finish"))?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

async fn one_hop_asks_for_an_unknown_key(lab: &Lab) -> TestResult {
    let known_hosts = fresh_known_hosts();
    let route = lab.jump_route();
    let error = SshConnection::open(&route, &known_hosts, TIMEOUT).await.err().ok_or("connected to an unknown host")?;
    let (key, hop) = unknown_key(&error).ok_or_else(|| format!("expected an unknown key, got {error}"))?;
    assert_eq!(hop, None, "a one-hop route has no hop number");
    assert!(key.fingerprint.starts_with("SHA256:"), "{}", key.fingerprint);
    known_hosts.trust(key)?;

    let connection = SshConnection::open(&route, &known_hosts, TIMEOUT).await?;
    assert_eq!(exec(&connection.target(), "test -f /fran-jump && echo jump", false).await?.trim(), "jump");
    Ok(())
}

async fn two_hops_ask_for_the_second_key(lab: &Lab) -> TestResult {
    let known_hosts = fresh_known_hosts();
    connect_trusting(&lab.jump_route(), &known_hosts, Arc::default()).await?;

    let route = lab.target_route();
    let error = SshConnection::open(&route, &known_hosts, TIMEOUT).await.err().ok_or("connected to an unknown second hop")?;
    let (key, hop) = unknown_key(&error).ok_or_else(|| format!("expected an unknown key, got {error}"))?;
    assert_eq!(hop, Some(2));
    assert_eq!(key.host, lab.target);
    known_hosts.trust(key)?;

    let connection = SshConnection::open(&route, &known_hosts, TIMEOUT).await?;
    assert_eq!(exec(&connection.target(), "test -f /fran-target && echo target", false).await?.trim(), "target");
    Ok(())
}

async fn changed_key_on_the_second_hop_stops(lab: &Lab) -> TestResult {
    let known_hosts = fresh_known_hosts();
    connect_trusting(&lab.jump_route(), &known_hosts, Arc::default()).await?;
    known_hosts.trust(HostKeyInfo {
        host: lab.target.clone(),
        port: 22,
        algorithm: "ssh-ed25519".to_string(),
        fingerprint: "SHA256:not-the-real-key-at-all".to_string(),
        added: None,
    })?;

    let error = SshConnection::open(&lab.target_route(), &known_hosts, TIMEOUT).await.err().ok_or("connected with a changed key")?;
    match &error.detail {
        ErrorDetail::HostKeyChanged { hop, known_fingerprint, .. } => {
            assert_eq!(hop.as_ref().map(|hop| hop.index), Some(2));
            assert_eq!(known_fingerprint, "SHA256:not-the-real-key-at-all");
        }
        other => return Err(format!("expected a changed key, got {other:?}").into()),
    }
    Ok(())
}

async fn pty_runs_echo(lab: &Lab) -> TestResult {
    let known_hosts = fresh_known_hosts();
    let connection = connect_trusting(&lab.target_route(), &known_hosts, Arc::default()).await?;
    let output = exec(&connection.target(), "echo pty-ok", true).await?;
    assert!(output.contains("pty-ok"), "{output:?}");
    Ok(())
}

async fn postgres_through_the_route(lab: &Lab) -> TestResult {
    let known_hosts = fresh_known_hosts();
    connect_trusting(&lab.target_route(), &known_hosts, Arc::default()).await?;
    let tunnel = SshTunnel::open(&lab.target_route(), &known_hosts, &lab.db, 5432, 0, TIMEOUT).await?;

    let options = DriverOptions::Postgres(PostgresOptions {
        host: "127.0.0.1".to_string(),
        port: tunnel.local_port(),
        user: "postgres".to_string(),
        ..Default::default()
    });
    let secrets = SecretBag::new(HashMap::from([("password".to_string(), PASSWORD.to_string())]));
    let started = Instant::now();
    // The image restarts Postgres once after first-time setup.
    let session = loop {
        match options.connect(&secrets, &SshAccess::direct(&known_hosts)).await {
            Ok(session) => break session,
            Err(error) if started.elapsed() > READY_TIMEOUT => return Err(error.into()),
            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };
    let context = session.open_context(None, ContextAccess::ReadWrite).await?;
    let outcomes = session.execute(context, "SELECT 40 + 2 AS answer", 10).await?;
    let rows = &outcomes[0].result_sets[0].rows;
    assert_eq!(rows[0][0].as_deref(), Some("42"));
    session.close().await;
    Ok(())
}

async fn local_forward_reaches_the_database(lab: &Lab) -> TestResult {
    let known_hosts = fresh_known_hosts();
    let connection = connect_trusting(&lab.target_route(), &known_hosts, Arc::default()).await?;
    let forward = forward_local(connection.target(), &lab.db, 5432, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;

    // Postgres answers an SSLRequest with one byte, S or N.
    let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, forward.port)).await?;
    stream.write_all(&[0, 0, 0, 8, 4, 210, 22, 47]).await?;
    let mut reply = [0u8; 1];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut reply)).await??;
    assert!(reply[0] == b'S' || reply[0] == b'N', "{reply:?}");
    Ok(())
}

async fn remote_forward_reaches_this_computer(lab: &Lab) -> TestResult {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let local_port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                if let Ok(count) = socket.read(&mut buffer).await {
                    let _ = socket.write_all(&buffer[..count]).await;
                }
            });
        }
    });

    let known_hosts = fresh_known_hosts();
    let policy = Arc::new(ChannelPolicy::default());
    policy.add_remote_target(REMOTE_PORT, "127.0.0.1".to_string(), local_port);
    let connection = connect_trusting(&lab.target_route(), &known_hosts, policy).await?;
    connection.target().tcpip_forward("127.0.0.1".to_string(), REMOTE_PORT).await?;

    let output = exec(&connection.target(), &format!("echo ping | nc -w 3 127.0.0.1 {REMOTE_PORT}"), false).await?;
    assert_eq!(output.trim(), "ping");
    Ok(())
}

fn events_channel(on_event: impl Fn(&serde_json::Value) + Send + Sync + 'static) -> (Channel<TransferEvent>, Arc<Mutex<Vec<serde_json::Value>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let channel = Channel::new(move |body| {
        if let InvokeResponseBody::Json(json) = body
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&json)
        {
            on_event(&value);
            sink.lock().unwrap().push(value);
        }
        Ok(())
    });
    (channel, events)
}

async fn run_transfer(conn: &Arc<SftpConn>, direction: Direction, source: &str, target_dir: &str) -> TestResult<serde_json::Value> {
    let (channel, events) = events_channel(|_| {});
    let control = Arc::new(Control::new("e2e".to_string()));
    transfer::run(conn.clone(), control, direction, source.to_string(), target_dir.to_string(), channel).await;
    let last = events.lock().unwrap().last().cloned().ok_or("the transfer sent nothing")?;
    Ok(last)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("fran-e2e").join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

async fn sftp_conn(lab: &Lab) -> TestResult<Arc<SftpConn>> {
    let known_hosts = fresh_known_hosts();
    connect_trusting(&lab.target_route(), &known_hosts, Arc::default()).await?;
    Ok(SftpConn::connect(&lab.target_route(), &known_hosts, TIMEOUT).await?)
}

async fn sftp_round_trip(lab: &Lab) -> TestResult {
    let conn = sftp_conn(lab).await?;
    let home = conn.home().await?;
    let remote = conn.mkdir(&home, &format!("e2e-{}", uuid::Uuid::new_v4().simple())).await?;

    let local = scratch("upload");
    let tree = local.join("tree");
    write(&tree.join("a.txt"), b"first file");
    write(&tree.join("sub").join("b.bin"), &[0, 1, 2, 3, 255]);

    let finished = run_transfer(&conn, Direction::Upload, &tree.to_string_lossy(), &remote).await?;
    assert_eq!(finished["kind"], "finished", "{finished}");
    assert_eq!(finished["files"], 2);

    let listing = conn.list(&format!("{remote}/tree")).await?;
    let mut names: Vec<_> = listing.entries.iter().map(|entry| entry.name.clone()).collect();
    names.sort();
    assert_eq!(names, ["a.txt", "sub"]);

    let renamed = conn.rename(&format!("{remote}/tree/a.txt"), "renamed.txt").await?;
    assert!(renamed.ends_with("/tree/renamed.txt"));
    assert!(conn.rename(&renamed, "../escape").await.is_err());

    let download = scratch("download");
    let finished = run_transfer(&conn, Direction::Download, &format!("{remote}/tree"), &download.to_string_lossy()).await?;
    assert_eq!(finished["kind"], "finished", "{finished}");
    assert_eq!(std::fs::read(download.join("tree").join("renamed.txt"))?, b"first file");
    assert_eq!(std::fs::read(download.join("tree").join("sub").join("b.bin"))?, [0, 1, 2, 3, 255]);

    let count = conn.count(&remote).await?;
    assert_eq!((count.files, count.folders), (2, 3));
    assert!(conn.remove(&remote, false).await.is_err(), "a folder with files in it needs the recursive flag");
    conn.remove(&remote, true).await?;
    assert!(conn.stat(&remote).await.is_err());

    let _ = std::fs::remove_dir_all(local);
    let _ = std::fs::remove_dir_all(download);
    Ok(())
}

async fn sftp_cancel_deletes_the_partial_file(lab: &Lab) -> TestResult {
    let conn = sftp_conn(lab).await?;
    let home = conn.home().await?;
    let local = scratch("cancel");
    let big = local.join("big.bin");
    write(&big, &vec![7u8; 64 * 1024 * 1024]);

    let control = Arc::new(Control::new("e2e".to_string()));
    let cancel = control.clone();
    let (channel, events) = events_channel(move |event| {
        if event["kind"] == "progress" {
            cancel.cancel.cancel();
        }
    });
    transfer::run(conn.clone(), control, Direction::Upload, big.to_string_lossy().into_owned(), home.clone(), channel).await;

    let last = events.lock().unwrap().last().cloned().ok_or("nothing reported")?;
    assert_eq!(last["kind"], "cancelled", "{last}");
    assert!(conn.stat(&format!("{home}/big.bin")).await.is_err(), "the partial upload is gone");
    let _ = std::fs::remove_dir_all(local);
    Ok(())
}

async fn sftp_overwrite_keeps_the_original_until_done(lab: &Lab) -> TestResult {
    let conn = sftp_conn(lab).await?;
    let home = conn.home().await?;
    let dir = conn.mkdir(&home, &format!("e2e-{}", uuid::Uuid::new_v4().simple())).await?;
    let local = scratch("overwrite");
    write(&local.join("note.txt"), b"old");
    run_transfer(&conn, Direction::Upload, &local.join("note.txt").to_string_lossy(), &dir).await?;
    write(&local.join("note.txt"), b"new contents");

    let control = Arc::new(Control::new("e2e".to_string()));
    let answer = control.clone();
    let (channel, events) = events_channel(move |event| {
        if event["kind"] == "conflict" {
            answer.answer(transfer::ConflictChoice::Overwrite, false);
        }
    });
    transfer::run(conn.clone(), control, Direction::Upload, local.join("note.txt").to_string_lossy().into_owned(), dir.clone(), channel).await;
    let last = events.lock().unwrap().last().cloned().ok_or("nothing reported")?;
    assert_eq!(last["kind"], "finished", "{last}");

    let download = scratch("overwrite-check");
    run_transfer(&conn, Direction::Download, &format!("{dir}/note.txt"), &download.to_string_lossy()).await?;
    assert_eq!(std::fs::read(download.join("note.txt"))?, b"new contents");
    let leftovers: Vec<_> = conn.list(&dir).await?.entries.into_iter().filter(|entry| entry.name.ends_with(".part")).collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    conn.remove(&dir, true).await?;
    let _ = std::fs::remove_dir_all(local);
    let _ = std::fs::remove_dir_all(download);
    Ok(())
}

fn run(lab: &Result<Arc<Lab>, String>, case: LabCase) -> Result<(), Failed> {
    let lab = lab.as_ref().map_err(|error| Failed::from(format!("the SSH lab isn't available: {error}")))?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(Failed::from)?;
    runtime.block_on(case(lab)).map_err(|error| Failed::from(error.to_string()))
}

/// Trials named `ssh::<case>`. The lab only starts when one of them is selected.
pub fn trials(selected: impl Fn(&str) -> bool, list_only: bool) -> (Vec<Trial>, Option<Arc<Result<Arc<Lab>, String>>>) {
    let cases = cases();
    let wanted = !list_only && cases.iter().any(|(name, _)| selected(&format!("ssh::{name}")));
    let lab = wanted.then(|| Arc::new(start_lab().map(Arc::new)));
    if let Some(Err(error)) = lab.as_deref() {
        eprintln!("\nThe SSH lab isn't available, its tests will fail:\n  {error}\n");
    }
    let trials = cases
        .into_iter()
        .map(|(name, case)| {
            let lab = lab.clone();
            Trial::test(format!("ssh::{name}"), move || match lab {
                Some(lab) => run(&lab, case),
                None => Err(Failed::from("the SSH lab wasn't started")),
            })
        })
        .collect();
    (trials, lab)
}
