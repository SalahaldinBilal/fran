use std::{
    io,
    net::{IpAddr, Ipv6Addr},
};

use base64ct::{Base64, Encoding};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::ssh_store::ProxyKind;

const MAX_HTTP_HEADER: usize = 16 * 1024;

pub struct ProxyTarget {
    pub kind: ProxyKind,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub login: Option<(String, Zeroizing<String>)>,
}

/// A TCP stream to `host:port` through the proxy, ready for SSH.
pub async fn connect(proxy: &ProxyTarget, host: &str, port: u16) -> AppResult<TcpStream> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await.map_err(|error| {
        AppError::ssh(format!("Couldn't reach the proxy {} at {}:{}: {error}", proxy.label, proxy.host, proxy.port))
    })?;
    stream.set_nodelay(true)?;
    handshake(&mut stream, proxy, host, port).await?;
    Ok(stream)
}

/// Asks the proxy at the other end of `stream` to open `host:port`.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, proxy: &ProxyTarget, host: &str, port: u16) -> AppResult<()> {
    let login = proxy.login.as_ref().map(|(user, password)| (user.as_str(), password.as_str()));
    let result = match proxy.kind {
        ProxyKind::Socks5 => socks5(stream, host, port, login).await,
        ProxyKind::HttpConnect => http_connect(stream, host, port, login).await,
    };
    result.map_err(|error| AppError::ssh(format!("The proxy {} didn't open {host}:{port}: {error}", proxy.label)))
}

fn refused(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, message.into())
}

pub async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
    login: Option<(&str, &str)>,
) -> io::Result<()> {
    let greeting: &[u8] = if login.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    stream.write_all(greeting).await?;

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != 5 {
        return Err(refused("it isn't a SOCKS5 proxy"));
    }
    match (choice[1], login) {
        (0, _) => {}
        (2, Some((user, password))) => {
            if user.len() > 255 || password.len() > 255 {
                return Err(refused("the proxy user or password is longer than 255 bytes"));
            }
            let mut request = vec![1, user.len() as u8];
            request.extend_from_slice(user.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            let request = Zeroizing::new(request);
            stream.write_all(&request).await?;

            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0 {
                return Err(refused("it rejected the user and password"));
            }
        }
        (2, None) => return Err(refused("it needs a login. Add a user to the proxy.")),
        _ => return Err(refused("it doesn't accept any login method Fran offers")),
    }

    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(refused("the host name is longer than 255 bytes"));
            }
            request.push(3);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(refused(socks_error(reply[1])));
    }
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        _ => return Err(refused("it sent a reply Fran can't read")),
    };
    let mut rest = vec![0u8; address_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

fn socks_error(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "the proxy's rules don't allow it",
        3 => "the network is unreachable",
        4 => "the host is unreachable",
        5 => "the connection was refused",
        6 => "the connection timed out",
        7 => "the proxy doesn't support CONNECT",
        8 => "the proxy doesn't support that address type",
        _ => "an unknown error",
    }
}

fn authority(host: &str, port: u16) -> String {
    match host.parse::<Ipv6Addr>() {
        Ok(_) => format!("[{host}]:{port}"),
        Err(_) => format!("{host}:{port}"),
    }
}

/// Reads byte by byte up to the blank line, so nothing of the SSH stream behind it is consumed.
pub async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
    login: Option<(&str, &str)>,
) -> io::Result<()> {
    if host.contains(['\r', '\n', ' ']) {
        return Err(refused("the host name has spaces or line breaks"));
    }
    let target = authority(host, port);
    let mut request = Zeroizing::new(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"));
    if let Some((user, password)) = login {
        let credentials = Zeroizing::new(format!("{user}:{password}"));
        let encoded = Zeroizing::new(Base64::encode_string(credentials.as_bytes()));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded.as_str()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HTTP_HEADER {
            return Err(refused("its reply was too long"));
        }
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }

    let text = String::from_utf8_lossy(&header);
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(refused("it isn't an HTTP proxy"));
    }
    match status {
        "200" => Ok(()),
        "407" => Err(refused("it needs a login, or rejected the one given")),
        _ => Err(refused(format!("it answered {}", status_line.trim()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
        (client.unwrap(), server.unwrap().0)
    }

    #[tokio::test]
    async fn socks5_without_login() {
        let (mut client, mut server) = pair().await;
        let proxy = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();

            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[..4], [5, 1, 0, 3]);
            let mut rest = vec![0u8; usize::from(head[4]) + 2];
            server.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[..rest.len() - 2], b"db.internal");
            assert_eq!(rest[rest.len() - 2..], 22u16.to_be_bytes());
            server.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 22, b'S']).await.unwrap();
        });

        socks5(&mut client, "db.internal", 22, None).await.unwrap();
        let mut first = [0u8; 1];
        client.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"S");
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_with_login_and_ip() {
        let (mut client, mut server) = pair().await;
        let proxy = tokio::spawn(async move {
            let mut greeting = [0u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            server.write_all(&[5, 2]).await.unwrap();

            let mut auth = [0u8; 2];
            server.read_exact(&mut auth).await.unwrap();
            let mut user = vec![0u8; usize::from(auth[1])];
            server.read_exact(&mut user).await.unwrap();
            let mut len = [0u8; 1];
            server.read_exact(&mut len).await.unwrap();
            let mut password = vec![0u8; usize::from(len[0])];
            server.read_exact(&mut password).await.unwrap();
            assert_eq!((user.as_slice(), password.as_slice()), (&b"me"[..], &b"secret"[..]));
            server.write_all(&[1, 0]).await.unwrap();

            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 1, 10, 0, 3, 11, 0, 22]);
            server.write_all(&[5, 0, 0, 3, 2, b'o', b'k', 0, 22]).await.unwrap();
        });

        socks5(&mut client, "10.0.3.11", 22, Some(("me", "secret"))).await.unwrap();
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_reports_refusals() {
        let (mut client, mut server) = pair().await;
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });

        let error = socks5(&mut client, "10.0.3.11", 22, None).await.unwrap_err();
        assert!(error.to_string().contains("refused"));
    }

    #[tokio::test]
    async fn socks5_needs_login_when_asked() {
        let (mut client, mut server) = pair().await;
        tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0xff]).await.unwrap();
        });
        assert!(socks5(&mut client, "host", 22, None).await.is_err());
    }

    async fn read_request(server: &mut TcpStream) -> String {
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        while !header.ends_with(b"\r\n\r\n") {
            server.read_exact(&mut byte).await.unwrap();
            header.push(byte[0]);
        }
        String::from_utf8(header).unwrap()
    }

    #[tokio::test]
    async fn http_connect_keeps_the_stream_after_the_header() {
        let (mut client, mut server) = pair().await;
        let proxy = tokio::spawn(async move {
            let request = read_request(&mut server).await;
            assert!(request.starts_with("CONNECT bastion.example:2222 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic bWU6c2VjcmV0\r\n"));
            server.write_all(b"HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\nSSH-2.0-test").await.unwrap();
        });

        http_connect(&mut client, "bastion.example", 2222, Some(("me", "secret"))).await.unwrap();
        let mut banner = [0u8; 12];
        client.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-test");
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_brackets_ipv6_and_reports_errors() {
        let (mut client, mut server) = pair().await;
        tokio::spawn(async move {
            let request = read_request(&mut server).await;
            assert!(request.starts_with("CONNECT [::1]:22 HTTP/1.1\r\n"));
            server.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.unwrap();
        });

        let error = http_connect(&mut client, "::1", 22, None).await.unwrap_err();
        assert!(error.to_string().contains("login"));
    }

    #[tokio::test]
    async fn http_connect_refuses_header_injection() {
        let (mut client, _server) = pair().await;
        assert!(http_connect(&mut client, "host\r\nX-Evil: 1", 22, None).await.is_err());
    }
}
