use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use russh::ChannelOpenFailure;
use russh::client::{ChannelOpenHandle, Msg};
use tokio::{net::TcpStream, sync::Notify};

const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Which channels a server may open toward us on one connection. Everything not set here is refused.
#[derive(Default)]
pub struct ChannelPolicy {
    /// The agent that forwarded agent requests go to. None refuses them.
    agent: Option<String>,
    /// Server port of a remote forward, to the host and port on this computer it goes to.
    remote_targets: Mutex<HashMap<u32, (String, u16)>>,
    closed: AtomicBool,
    closed_notify: Notify,
    reason: Mutex<Option<String>>,
}

impl ChannelPolicy {
    /// An empty socket means the usual agent for the OS.
    pub fn with_agent(socket: Option<String>) -> Self {
        Self {
            agent: socket,
            ..Default::default()
        }
    }

    pub fn forwards_agent(&self) -> bool {
        self.agent.is_some()
    }

    pub fn add_remote_target(&self, server_port: u32, host: String, port: u16) {
        if let Ok(mut targets) = self.remote_targets.lock() {
            targets.insert(server_port, (host, port));
        }
    }

    fn remote_target(&self, server_port: u32) -> Option<(String, u16)> {
        self.remote_targets.lock().ok()?.get(&server_port).cloned()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Why the server or the network ended the connection, when it said.
    pub fn close_reason(&self) -> Option<String> {
        self.reason.lock().ok()?.clone()
    }

    pub async fn wait_closed(&self) {
        loop {
            let notified = self.closed_notify.notified();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn mark_closed(&self, reason: Option<String>) {
        if let Ok(mut slot) = self.reason.lock() {
            if slot.is_none() {
                *slot = reason;
            }
        }
        self.closed.store(true, Ordering::SeqCst);
        self.closed_notify.notify_waiters();
    }

    pub(super) fn open_forwarded(&self, channel: russh::Channel<Msg>, connected_port: u32, reply: ChannelOpenHandle) {
        // Dropping the reply refuses the channel.
        let Some((host, port)) = self.remote_target(connected_port) else {
            return drop(reply);
        };
        tauri::async_runtime::spawn(async move {
            let connected = tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port))).await;
            let Ok(Ok(mut local)) = connected else {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return;
            };
            let _ = local.set_nodelay(true);
            reply.accept().await;
            let mut remote = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
        });
    }

    pub(super) fn open_agent(&self, channel: russh::Channel<Msg>, reply: ChannelOpenHandle) {
        let Some(socket) = self.agent.clone() else {
            return drop(reply);
        };
        tauri::async_runtime::spawn(async move {
            let Ok(agent) = super::connect_agent(&socket).await else {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return;
            };
            reply.accept().await;
            let mut agent = agent.into_inner();
            let mut remote = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut agent, &mut remote).await;
        });
    }
}
