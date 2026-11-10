use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tauri::async_runtime::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};

use super::SshHandle;

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;

const SUCCEEDED: u8 = 0;
const GENERAL_FAILURE: u8 = 1;
const CONNECTION_REFUSED: u8 = 5;
const COMMAND_NOT_SUPPORTED: u8 = 7;
const ADDRESS_NOT_SUPPORTED: u8 = 8;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> io::Result<()> {
    stream.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    stream.flush().await
}

/// Reads a SOCKS5 greeting and CONNECT request and returns where it wants to go.
/// Only CONNECT without a login is supported, anything else gets the matching refusal.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<(String, u16)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(refused("Not a SOCKS5 client"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Err(refused("The client wants a login method this proxy doesn't offer"));
    }
    stream.write_all(&[VERSION, NO_AUTH]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != VERSION {
        return Err(refused("Not a SOCKS5 request"));
    }
    if request[1] != CONNECT {
        reply(stream, COMMAND_NOT_SUPPORTED).await?;
        return Err(refused("Only CONNECT is supported"));
    }

    let host = match request[3] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| refused("The host name isn't valid text"))?
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => {
            reply(stream, ADDRESS_NOT_SUPPORTED).await?;
            return Err(refused("Unknown address type"));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    if host.is_empty() {
        reply(stream, GENERAL_FAILURE).await?;
        return Err(refused("Empty host name"));
    }
    Ok((host, u16::from_be_bytes(port)))
}

/// A SOCKS5 proxy whose connections leave through `direct-tcpip` channels on the SSH connection. Dropping it stops listening.
pub struct SocksServer {
    pub port: u16,
    task: JoinHandle<()>,
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SocksServer {
    pub async fn start(listen: SocketAddr, handle: Arc<SshHandle>) -> io::Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("Couldn't listen on {listen}: {error}")))?;
        let port = listener.local_addr()?.port();

        let task = tauri::async_runtime::spawn(async move {
            while let Ok((mut socket, peer)) = listener.accept().await {
                let handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = socket.set_nodelay(true);
                    let Ok(Ok((host, port))) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut socket)).await else {
                        return;
                    };
                    let opened = handle
                        .channel_open_direct_tcpip(host, u32::from(port), peer.ip().to_string(), u32::from(peer.port()))
                        .await;
                    let Ok(channel) = opened else {
                        let _ = reply(&mut socket, CONNECTION_REFUSED).await;
                        return;
                    };
                    if reply(&mut socket, SUCCEEDED).await.is_err() {
                        return;
                    }
                    let mut remote = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut remote).await;
                });
            }
        });

        Ok(Self { port, task })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(client_bytes: &[u8]) -> (io::Result<(String, u16)>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(client_bytes).await.unwrap();
        let result = handshake(&mut server).await;
        drop(server);
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        (result, answer)
    }

    #[tokio::test]
    async fn connect_by_name() {
        let mut bytes = vec![5, 1, 0, 5, 1, 0, 3, 11];
        bytes.extend_from_slice(b"example.org");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let (result, answer) = run(&bytes).await;
        assert_eq!(result.unwrap(), ("example.org".to_string(), 443));
        assert_eq!(answer, [5, 0]);
    }

    #[tokio::test]
    async fn connect_by_address() {
        let (v4, _) = run(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 7, 0, 80]).await;
        assert_eq!(v4.unwrap(), ("10.0.0.7".to_string(), 80));

        let mut bytes = vec![5, 1, 0, 5, 1, 0, 4];
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&22u16.to_be_bytes());
        let (v6, _) = run(&bytes).await;
        assert_eq!(v6.unwrap(), ("::1".to_string(), 22));
    }

    #[tokio::test]
    async fn login_methods_are_refused() {
        let (result, answer) = run(&[5, 1, 2]).await;
        assert!(result.is_err());
        assert_eq!(answer, [5, 0xff]);
    }

    #[tokio::test]
    async fn bind_and_udp_are_refused() {
        let (result, answer) = run(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80]).await;
        assert!(result.is_err());
        assert_eq!(answer, [5, 0, 5, COMMAND_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn socks4_is_refused() {
        let (result, answer) = run(&[4, 1, 0, 80, 127, 0, 0, 1, 0]).await;
        assert!(result.is_err());
        assert!(answer.is_empty());
    }
}
