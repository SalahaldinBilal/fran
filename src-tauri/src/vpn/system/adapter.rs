//! Fran's own connections over a VPN that's on for the whole computer, whichever program runs it: bound to the
//! VPN's adapter, names looked up with the VPN's DNS servers, and cut off the moment the VPN goes down.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpSocket, TcpStream, UdpSocket},
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::vpn::dns;

const DNS_TIMEOUT: Duration = Duration::from_secs(3);

pub struct Adapter {
    pub label: String,
    use_vpn_dns: bool,
    address4: Mutex<Option<Ipv4Addr>>,
    address6: Mutex<Option<Ipv6Addr>>,
    dns: Mutex<Vec<IpAddr>>,
    down: Mutex<CancellationToken>,
}

impl Adapter {
    pub fn new(label: String, use_vpn_dns: bool) -> Self {
        Self {
            label,
            use_vpn_dns,
            address4: Mutex::new(None),
            address6: Mutex::new(None),
            dns: Mutex::new(Vec::new()),
            down: Mutex::new(CancellationToken::new()),
        }
    }

    pub fn set_addresses(&self, address4: Option<Ipv4Addr>, address6: Option<Ipv6Addr>) {
        if let Ok(mut current) = self.address4.lock() {
            *current = address4;
        }
        if let Ok(mut current) = self.address6.lock() {
            *current = address6;
        }
    }

    pub fn set_dns(&self, servers: Vec<IpAddr>) {
        if let Ok(mut current) = self.dns.lock() {
            *current = servers;
        }
    }

    /// Ends every connection made so far. Later ones get a fresh start.
    pub fn cut(&self) {
        if let Ok(mut down) = self.down.lock() {
            down.cancel();
            *down = CancellationToken::new();
        }
    }

    fn down(&self) -> CancellationToken {
        self.down.lock().map(|down| down.clone()).unwrap_or_default()
    }

    pub fn address4(&self) -> Option<Ipv4Addr> {
        self.address4.lock().ok().and_then(|current| *current)
    }

    pub fn address6(&self) -> Option<Ipv6Addr> {
        self.address6.lock().ok().and_then(|current| *current)
    }

    fn local_for(&self, target: &IpAddr) -> Option<IpAddr> {
        match target {
            IpAddr::V4(_) => self.address4().map(IpAddr::V4),
            IpAddr::V6(_) => self.address6().map(IpAddr::V6),
        }
    }

    /// One query to one of the VPN's DNS servers, over the VPN's adapter.
    async fn query(&self, server: IpAddr, name: &str, record: u16) -> io::Result<dns::Answer> {
        let local = self.local_for(&server).ok_or_else(|| io::Error::other("The VPN has no address of that kind"))?;
        let interface = find_interface(local)?;
        let domain = if server.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        bind_interface(&socket2::SockRef::from(&socket), &interface, server.is_ipv6())?;
        socket.bind(&SocketAddr::new(local, 0).into())?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket.into())?;

        let random = uuid::Uuid::new_v4();
        let id = u16::from_be_bytes([random.as_bytes()[0], random.as_bytes()[1]]);
        socket.send_to(&dns::query(id, name, record).map_err(io::Error::other)?, (server, 53)).await?;
        let mut buf = vec![0u8; 1500];
        let deadline = Instant::now() + DNS_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (read, from) = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("The VPN's DNS server {server} didn't answer")))??;
            if from.ip() != server {
                continue;
            }
            if let Ok(answer) = dns::parse(&buf[..read], id) {
                return Ok(answer);
            }
        }
    }

    /// DNS over TCP: each message has a two byte length in front.
    async fn query_tcp(&self, server: IpAddr, name: &str, record: u16) -> io::Result<dns::Answer> {
        use tokio::io::AsyncReadExt;
        let local = self.local_for(&server).ok_or_else(|| io::Error::other("The VPN has no address of that kind"))?;
        let random = uuid::Uuid::new_v4();
        let id = u16::from_be_bytes([random.as_bytes()[0], random.as_bytes()[1]]);
        let exchange = async {
            let mut stream = connect_bound(local, SocketAddr::new(server, 53)).await?;
            let query = dns::query(id, name, record).map_err(io::Error::other)?;
            let mut message = (query.len() as u16).to_be_bytes().to_vec();
            message.extend(query);
            stream.write_all(&message).await?;
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await?;
            let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut reply).await?;
            dns::parse(&reply, id).map_err(io::Error::other)
        };
        tokio::time::timeout(DNS_TIMEOUT, exchange)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("The VPN's DNS server {server} didn't answer over TCP")))?
    }

    /// Names go to the DNS servers the VPN pushed, so names only the VPN knows work too. The computer's resolver
    /// is used when there are none, or when the profile says not to use the VPN's DNS.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, port)]);
        }
        let servers = if self.use_vpn_dns { self.dns.lock().map(|servers| servers.clone()).unwrap_or_default() } else { Vec::new() };
        let mut last = None;
        for server in servers.iter().filter(|server| self.local_for(server).is_some()) {
            let mut found = Vec::new();
            let records = [(dns::TYPE_A, self.address4().is_some()), (dns::TYPE_AAAA, self.address6().is_some())];
            for (record, usable) in records {
                if !usable {
                    continue;
                }
                let answer = match self.query(*server, host, record).await {
                    // Too big for UDP: the same question over TCP, through the adapter too.
                    Ok(dns::Answer::Truncated) => self.query_tcp(*server, host, record).await,
                    other => other,
                };
                match answer {
                    Ok(dns::Answer::Addresses(addresses)) => found.extend(addresses.into_iter().map(|address| SocketAddr::new(address, port))),
                    Ok(dns::Answer::NoSuchName) => return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host} isn't known to VPN {}", self.label))),
                    Ok(dns::Answer::Truncated | dns::Answer::Failed(_)) => {}
                    Err(error) => last = Some(error),
                }
            }
            if !found.is_empty() {
                return Ok(found);
            }
        }
        match tokio::net::lookup_host((host, port)).await {
            Ok(addresses) => Ok(addresses.collect()),
            Err(error) => Err(last.unwrap_or(error)),
        }
    }

    /// A TCP connection that can only leave through this VPN's adapter, and that ends when the VPN is turned off.
    pub async fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<SystemStream> {
        let targets = self.resolve(host, port).await?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address VPN {} can reach", self.label));
        for target in targets {
            let Some(local) = self.local_for(&target.ip()) else { continue };
            match tokio::time::timeout(timeout, connect_bound(local, target)).await {
                Ok(Ok(stream)) => return Ok(SystemStream { stream, down: Box::pin(self.down().cancelled_owned()) }),
                Ok(Err(error)) => last = error,
                Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, format!("{target} didn't answer through VPN {}", self.label)),
            }
        }
        Err(last)
    }
}

/// A connection over a VPN that's on for the computer. It fails as soon as that VPN is turned off or drops,
/// instead of waiting for TCP to notice the adapter is gone.
pub struct SystemStream {
    stream: TcpStream,
    down: Pin<Box<WaitForCancellationFutureOwned>>,
}

fn turned_off() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "The VPN was turned off")
}

impl AsyncRead for SystemStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.down.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(turned_off()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SystemStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.down.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(turned_off()));
        }
        Pin::new(&mut self.stream).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn find_interface(address: IpAddr) -> io::Result<if_addrs::Interface> {
    if_addrs::get_if_addrs()?
        .into_iter()
        .find(|interface| interface.ip() == address)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, format!("No network adapter has the VPN's address {address}")))
}

async fn connect_bound(local: IpAddr, target: SocketAddr) -> io::Result<TcpStream> {
    let interface = find_interface(local)?;
    let socket = if local.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    bind_interface(&socket2::SockRef::from(&socket), &interface, local.is_ipv6())?;
    socket.bind(SocketAddr::new(local, 0))?;
    let stream = socket.connect(target).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn bind_interface(socket: &socket2::SockRef<'_>, interface: &if_addrs::Interface, _v6: bool) -> io::Result<()> {
    socket.bind_device(Some(interface.name.as_bytes()))
}

#[cfg(target_os = "macos")]
fn bind_interface(socket: &socket2::SockRef<'_>, interface: &if_addrs::Interface, v6: bool) -> io::Result<()> {
    let index = interface.index.and_then(std::num::NonZeroU32::new).ok_or_else(|| io::Error::other("The VPN adapter has no index"))?;
    if v6 { socket.bind_device_by_index_v6(Some(index)) } else { socket.bind_device_by_index_v4(Some(index)) }
}

#[cfg(windows)]
fn bind_interface(socket: &socket2::SockRef<'_>, interface: &if_addrs::Interface, v6: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt};
    let index = interface.index.ok_or_else(|| io::Error::other("The VPN adapter has no index"))?;
    // IPv4 takes the index in network byte order, IPv6 in host order.
    let (level, option, value) = if v6 { (IPPROTO_IPV6.0, IPV6_UNICAST_IF, index.to_ne_bytes()) } else { (IPPROTO_IP.0, IP_UNICAST_IF, index.to_be_bytes()) };
    let result = unsafe { setsockopt(SOCKET(socket.as_raw_socket() as usize), level, option, Some(&value)) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
