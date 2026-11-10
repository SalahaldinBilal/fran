pub mod commands;
pub mod config;
pub mod dns;
pub mod keys;
pub mod manager;
pub mod net;
pub mod system;
pub mod tunnel;
pub mod wireguard;

pub use vpn_proto::frames;

use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{AppError, AppResult};
use crate::forward::LocalForward;
use manager::{VpnLease, VpnLeg};
use net::VpnStream;
use system::SystemStream;

/// `fran-vpn`, which Tauri bundles next to Fran's own exe.
pub fn sidecar() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let path = exe.parent().map(|dir| dir.join(format!("fran-vpn{}", std::env::consts::EXE_SUFFIX)));
    path.filter(|path| path.is_file()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Fran's VPN program (fran-vpn) is missing next to Fran. Reinstall Fran."))
}

/// A connection through a VPN: inside Fran's own tunnel, or over the computer's VPN adapter.
pub enum VpnConn {
    Own(VpnStream),
    System(SystemStream),
}

impl AsyncRead for VpnConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Own(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::System(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VpnConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Own(stream) => Pin::new(stream).poll_write(cx, data),
            Self::System(stream) => Pin::new(stream).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Own(stream) => Pin::new(stream).poll_flush(cx),
            Self::System(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Own(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::System(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A 127.0.0.1 port that sends each connection through a VPN, for drivers that only dial TCP.
pub struct VpnRelay {
    forward: LocalForward,
    _lease: Arc<VpnLease>,
}

impl VpnRelay {
    pub async fn open(leg: &VpnLeg, host: &str, port: u16, timeout: Duration) -> AppResult<Self> {
        let lease = Arc::new(leg.acquire().await?);
        // Check the target now, so a wrong address fails the connect instead of every later query.
        drop(lease.connect(host, port, timeout).await.map_err(|error| AppError::general(format!("{host}:{port} through VPN {}: {error}", leg.label)))?);

        let target = host.to_string();
        let relay_lease = lease.clone();
        let forward = LocalForward::start(0, move |_peer: SocketAddr| {
            let lease = relay_lease.clone();
            let target = target.clone();
            async move { lease.connect(&target, port, timeout).await }
        })
        .await?;
        Ok(Self { forward, _lease: lease })
    }

    pub fn local_port(&self) -> u16 {
        self.forward.port
    }
}
