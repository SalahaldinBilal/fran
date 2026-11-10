// A userspace IP stack per tunnel. Only sockets Fran opens live in it, nothing listens.

use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Notify,
};

use super::dns::{self, Answer};
use super::frames::TunnelSettings;

const TCP_BUFFER: usize = 256 * 1024;
const MAX_QUEUED: usize = 4096;
const ORPHAN_GRACE: Duration = Duration::from_secs(30);
const IDLE_POLL: Duration = Duration::from_secs(1);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_MTU: usize = 1500;

pub type PacketSink = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

struct RxPacket(Vec<u8>);

impl RxToken for RxPacket {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxPacket<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for TxPacket<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for Queues {
    type RxToken<'a> = RxPacket;
    type TxToken<'a> = TxPacket<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxPacket(packet), TxPacket(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxPacket(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct Stack {
    iface: Interface,
    device: Queues,
    sockets: SocketSet<'static>,
    ports: HashMap<SocketHandle, u16>,
    orphans: Vec<(SocketHandle, Instant)>,
    closed: bool,
}

impl Stack {
    fn free_port(&self) -> io::Result<u16> {
        let mut seed = [0u8; 2];
        getrandom::fill(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
        let start = u16::from_be_bytes(seed) % 16_384;
        (0..16_384u16)
            .map(|offset| 49_152 + (start + offset) % 16_384)
            .find(|port| !self.ports.values().any(|used| used == port))
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free port left in the tunnel"))
    }

    fn remove(&mut self, handle: SocketHandle) {
        self.ports.remove(&handle);
        self.sockets.remove(handle);
    }

    /// Closed sockets are removed once their goodbye is done, or after a grace period.
    fn sweep(&mut self) {
        let now = Instant::now();
        let orphans = std::mem::take(&mut self.orphans);
        for (handle, since) in orphans {
            let done = match self.sockets.get_mut::<tcp::Socket>(handle) {
                socket if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) => true,
                socket if now.duration_since(since) > ORPHAN_GRACE => {
                    socket.abort();
                    true
                }
                _ => false,
            };
            if done {
                self.remove(handle);
            } else {
                self.orphans.push((handle, since));
            }
        }
    }
}

struct Shared {
    stack: Mutex<Stack>,
    wake: Notify,
}

impl Shared {
    fn lock(&self) -> io::Result<MutexGuard<'_, Stack>> {
        self.stack.lock().map_err(|_| io::Error::other("tunnel stack lock poisoned"))
    }
}

fn down() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "the VPN tunnel went down")
}

/// One tunnel's addresses, sockets and DNS. Dropping it ends every connection in it.
pub struct NetStack {
    shared: Arc<Shared>,
    settings: TunnelSettings,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for NetStack {
    fn drop(&mut self) {
        self.shutdown();
        self.task.abort();
    }
}

fn first_host(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix >= 31 {
        return addr;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    Ipv4Addr::from((u32::from(addr) & mask) + 1)
}

impl NetStack {
    /// Must run inside a Tokio runtime. Packets the stack sends go to `sink`.
    pub fn new(settings: TunnelSettings, sink: PacketSink) -> io::Result<Self> {
        if settings.addr4.is_none() && settings.addr6.is_none() {
            return Err(io::Error::other("The VPN server gave this tunnel no address"));
        }
        let mut device = Queues {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: settings.mtu.map(usize::from).filter(|mtu| *mtu >= 576).unwrap_or(DEFAULT_MTU),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
        config.random_seed = u64::from_be_bytes(seed);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            if let Some((addr, prefix)) = settings.addr4 {
                let _ = addrs.push(IpCidr::new(IpAddress::from(IpAddr::V4(addr)), prefix));
            }
            if let Some((addr, prefix)) = settings.addr6 {
                let _ = addrs.push(IpCidr::new(IpAddress::from(IpAddr::V6(addr)), prefix));
            }
        });
        // Everything Fran sends into a tunnel is meant for it, whatever the server pushed as routes.
        if let Some((addr, prefix)) = settings.addr4 {
            let _ = iface.routes_mut().add_default_ipv4_route(settings.gw4.unwrap_or_else(|| first_host(addr, prefix)));
        }
        if let Some((addr, _)) = settings.addr6 {
            let _ = iface.routes_mut().add_default_ipv6_route(settings.gw6.unwrap_or(addr));
        }

        let shared = Arc::new(Shared {
            stack: Mutex::new(Stack {
                iface,
                device,
                sockets: SocketSet::new(Vec::new()),
                ports: HashMap::new(),
                orphans: Vec::new(),
                closed: false,
            }),
            wake: Notify::new(),
        });
        let task = tokio::spawn(drive(shared.clone(), sink));
        Ok(Self { shared, settings, task })
    }

    pub fn settings(&self) -> &TunnelSettings {
        &self.settings
    }

    /// One IP packet that came out of the tunnel.
    pub fn receive(&self, packet: Vec<u8>) {
        if let Ok(mut stack) = self.shared.lock() {
            if stack.closed || stack.device.rx.len() >= MAX_QUEUED {
                return;
            }
            stack.device.rx.push_back(packet);
        }
        self.shared.wake.notify_one();
    }

    pub fn shutdown(&self) {
        if let Ok(mut stack) = self.shared.lock() {
            if stack.closed {
                return;
            }
            stack.closed = true;
            for (_, socket) in stack.sockets.iter_mut() {
                match socket {
                    smoltcp::socket::Socket::Tcp(socket) => socket.abort(),
                    smoltcp::socket::Socket::Udp(socket) => socket.close(),
                    #[allow(unreachable_patterns)]
                    _ => {}
                }
            }
        }
        self.shared.wake.notify_one();
    }

    pub async fn connect(&self, target: SocketAddr, timeout: Duration) -> io::Result<VpnStream> {
        let handle = {
            let mut stack = self.shared.lock()?;
            if stack.closed {
                return Err(down());
            }
            let port = stack.free_port()?;
            let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUFFER]), tcp::SocketBuffer::new(vec![0; TCP_BUFFER]));
            socket.set_nagle_enabled(false);
            socket.set_keep_alive(Some(SmolDuration::from_secs(60)));
            socket.set_timeout(Some(SmolDuration::from_secs(180)));
            let Stack { iface, .. } = &mut *stack;
            socket
                .connect(iface.context(), IpEndpoint::new(IpAddress::from(target.ip()), target.port()), port)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("Can't connect to {target} through the VPN: {error}")))?;
            let handle = stack.sockets.add(socket);
            stack.ports.insert(handle, port);
            handle
        };
        self.shared.wake.notify_one();
        let stream = VpnStream { shared: self.shared.clone(), handle };

        let established = poll_fn(|cx| {
            let mut stack = self.shared.lock()?;
            if stack.closed {
                return Poll::Ready(Err(down()));
            }
            let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
            match socket.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                tcp::State::Closed => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("{target} refused the connection through the VPN"),
                ))),
                _ => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
        });
        match tokio::time::timeout(timeout, established).await {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("Timed out reaching {target} through the VPN"))),
        }
    }

    /// Looks a name up through the tunnel's own DNS servers. Without any, the computer's resolver is used.
    pub async fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let servers: Vec<SocketAddr> = self
            .settings
            .dns
            .iter()
            .copied()
            .filter(|server| match server.ip() {
                IpAddr::V4(_) => self.settings.addr4.is_some(),
                IpAddr::V6(_) => self.settings.addr6.is_some(),
            })
            .collect();
        if servers.is_empty() {
            return Ok(tokio::net::lookup_host((name, port)).await?.collect());
        }

        let mut names = Vec::new();
        if !name.contains('.') {
            names.extend(self.settings.domains.iter().map(|domain| format!("{name}.{domain}")));
        }
        names.push(name.to_string());
        let mut records = vec![dns::TYPE_A];
        if self.settings.addr6.is_some() {
            records.push(dns::TYPE_AAAA);
        }

        let mut last_error = io::Error::new(io::ErrorKind::NotFound, format!("The VPN's DNS doesn't know {name}"));
        for candidate in &names {
            for server in &servers {
                let mut found = Vec::new();
                for record in &records {
                    match self.lookup(*server, candidate, *record).await {
                        Ok(addresses) => found.extend(addresses),
                        Err(error) => last_error = error,
                    }
                }
                if !found.is_empty() {
                    return Ok(found.into_iter().map(|ip| SocketAddr::new(ip, port)).collect());
                }
            }
        }
        Err(last_error)
    }

    async fn lookup(&self, server: SocketAddr, name: &str, record: u16) -> io::Result<Vec<IpAddr>> {
        let mut id = [0u8; 2];
        getrandom::fill(&mut id).map_err(|error| io::Error::other(error.to_string()))?;
        let id = u16::from_be_bytes(id);
        let query = dns::query(id, name, record).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let reply = match self.udp_exchange(server, &query).await? {
            reply if matches!(dns::parse(&reply, id), Ok(Answer::Truncated)) => self.tcp_exchange(server, &query).await?,
            reply => reply,
        };
        match dns::parse(&reply, id).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))? {
            Answer::Addresses(addresses) => Ok(addresses),
            Answer::NoSuchName => Err(io::Error::new(io::ErrorKind::NotFound, format!("The VPN's DNS doesn't know {name}"))),
            Answer::Truncated => Err(io::Error::new(io::ErrorKind::InvalidData, "The VPN's DNS reply was cut off")),
            Answer::Failed(code) => Err(io::Error::other(format!("The VPN's DNS failed with code {code}"))),
        }
    }

    async fn udp_exchange(&self, server: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let handle = {
            let mut stack = self.shared.lock()?;
            if stack.closed {
                return Err(down());
            }
            let port = stack.free_port()?;
            let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
            let mut socket = udp::Socket::new(buffer(), buffer());
            socket.bind(port).map_err(|error| io::Error::other(error.to_string()))?;
            socket
                .send_slice(query, IpEndpoint::new(IpAddress::from(server.ip()), server.port()))
                .map_err(|error| io::Error::other(error.to_string()))?;
            let handle = stack.sockets.add(socket);
            stack.ports.insert(handle, port);
            handle
        };
        self.shared.wake.notify_one();

        let reply = poll_fn(|cx| {
            let mut stack = self.shared.lock()?;
            if stack.closed {
                return Poll::Ready(Err(down()));
            }
            let socket = stack.sockets.get_mut::<udp::Socket>(handle);
            let mut buffer = vec![0u8; 4096];
            loop {
                match socket.recv_slice(&mut buffer) {
                    Ok((len, meta)) if meta.endpoint.addr == IpAddress::from(server.ip()) && meta.endpoint.port == server.port() => {
                        buffer.truncate(len);
                        return Poll::Ready(Ok(buffer));
                    }
                    Ok(_) => continue,
                    Err(udp::RecvError::Exhausted) => {
                        socket.register_recv_waker(cx.waker());
                        return Poll::Pending;
                    }
                    Err(error) => return Poll::Ready(Err(io::Error::other(error.to_string()))),
                }
            }
        });
        let result = tokio::time::timeout(DNS_TIMEOUT, reply).await;
        if let Ok(mut stack) = self.shared.lock() {
            stack.remove(handle);
        }
        match result {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("The VPN's DNS server {server} didn't answer"))),
        }
    }

    async fn tcp_exchange(&self, server: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = self.connect(server, DNS_TIMEOUT).await?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        let exchange = async {
            stream.write_all(&framed).await?;
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await?;
            let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut reply).await?;
            Ok::<_, io::Error>(reply)
        };
        tokio::time::timeout(DNS_TIMEOUT, exchange)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("The VPN's DNS server {server} didn't answer")))?
    }

    #[cfg(test)]
    async fn accept(&self, port: u16) -> io::Result<VpnStream> {
        let handle = {
            let mut stack = self.shared.lock()?;
            let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUFFER]), tcp::SocketBuffer::new(vec![0; TCP_BUFFER]));
            socket.listen(port).map_err(|error| io::Error::other(error.to_string()))?;
            let handle = stack.sockets.add(socket);
            stack.ports.insert(handle, port);
            handle
        };
        poll_fn(|cx| {
            let mut stack = self.shared.lock()?;
            let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
            if socket.state() == tcp::State::Established {
                return Poll::Ready(Ok::<_, io::Error>(()));
            }
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await?;
        Ok(VpnStream { shared: self.shared.clone(), handle })
    }
}

async fn drive(shared: Arc<Shared>, sink: PacketSink) {
    loop {
        let (outgoing, delay) = {
            let Ok(mut stack) = shared.lock() else {
                return;
            };
            let Stack { iface, device, sockets, .. } = &mut *stack;
            let now = SmolInstant::now();
            iface.poll(now, device, sockets);
            let delay = iface.poll_delay(now, sockets);
            stack.sweep();
            let outgoing: Vec<Vec<u8>> = stack.device.tx.drain(..).collect();
            // A closed stack still sends its resets, then stops.
            if stack.closed && outgoing.is_empty() {
                return;
            }
            (outgoing, delay.map(|delay| Duration::from_micros(delay.total_micros())).unwrap_or(IDLE_POLL))
        };
        for packet in outgoing {
            sink(packet);
        }
        tokio::select! {
            _ = shared.wake.notified() => {}
            _ = tokio::time::sleep(delay.min(IDLE_POLL)) => {}
        }
    }
}

/// A TCP connection inside a tunnel.
pub struct VpnStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
}

impl Drop for VpnStream {
    fn drop(&mut self) {
        if let Ok(mut stack) = self.shared.lock() {
            stack.sockets.get_mut::<tcp::Socket>(self.handle).close();
            stack.orphans.push((self.handle, Instant::now()));
        }
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for VpnStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut stack = self.shared.lock()?;
        if stack.closed {
            return Poll::Ready(Err(down()));
        }
        let socket = stack.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_recv() {
            let read = socket.recv_slice(buf.initialize_unfilled()).map_err(|error| io::Error::other(error.to_string()))?;
            buf.advance(read);
            drop(stack);
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for VpnStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut stack = self.shared.lock()?;
        if stack.closed {
            return Poll::Ready(Err(down()));
        }
        let socket = stack.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_send() {
            let written = socket.send_slice(data).map_err(|error| io::Error::other(error.to_string()))?;
            drop(stack);
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(written));
        }
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the connection through the VPN closed")));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut stack) = self.shared.lock() {
            stack.sockets.get_mut::<tcp::Socket>(self.handle).close();
        }
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn settings(last: u8) -> TunnelSettings {
        TunnelSettings { addr4: Some((Ipv4Addr::new(10, 8, 0, last), 24)), ..Default::default() }
    }

    fn sink() -> (PacketSink, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Arc::new(move |packet| drop(sender.send(packet))), receiver)
    }

    fn wire(mut from: mpsc::UnboundedReceiver<Vec<u8>>, to: Arc<NetStack>) {
        tokio::spawn(async move {
            while let Some(packet) = from.recv().await {
                to.receive(packet);
            }
        });
    }

    async fn pair() -> (Arc<NetStack>, Arc<NetStack>) {
        let (sink_a, out_a) = sink();
        let (sink_b, out_b) = sink();
        let a = Arc::new(NetStack::new(settings(2), sink_a).unwrap());
        let b = Arc::new(NetStack::new(settings(1), sink_b).unwrap());
        wire(out_a, b.clone());
        wire(out_b, a.clone());
        (a, b)
    }

    #[tokio::test]
    async fn streams_carry_data_both_ways() {
        let (a, b) = pair().await;
        let server = tokio::spawn({
            let b = b.clone();
            async move {
                let mut stream = b.accept(5432).await.unwrap();
                let mut request = vec![0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                let big = vec![7u8; 600_000];
                stream.write_all(&big).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let mut client = a.connect("10.8.0.1:5432".parse().unwrap(), Duration::from_secs(5)).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), 600_000);
        assert!(received.iter().all(|byte| *byte == 7));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn closed_ports_refuse_and_shutdown_ends_streams() {
        let (a, b) = pair().await;
        let refused = a.connect("10.8.0.1:9".parse().unwrap(), Duration::from_secs(5)).await;
        assert_eq!(refused.err().map(|error| error.kind()), Some(io::ErrorKind::ConnectionRefused));

        let accept = tokio::spawn({
            let b = b.clone();
            async move { b.accept(22).await.unwrap() }
        });
        let mut client = a.connect("10.8.0.1:22".parse().unwrap(), Duration::from_secs(5)).await.unwrap();
        let _server = accept.await.unwrap();
        a.shutdown();
        let mut buffer = [0u8; 1];
        assert_eq!(client.read(&mut buffer).await.err().map(|error| error.kind()), Some(io::ErrorKind::ConnectionAborted));
        assert!(a.connect("10.8.0.1:22".parse().unwrap(), Duration::from_secs(1)).await.is_err());
    }

    #[tokio::test]
    async fn addresses_skip_dns() {
        let (sink, _out) = sink();
        let stack = NetStack::new(settings(2), sink).unwrap();
        assert_eq!(stack.resolve("10.0.3.4", 5432).await.unwrap(), vec!["10.0.3.4:5432".parse().unwrap()]);
        assert!(NetStack::new(TunnelSettings::default(), Arc::new(|_| {})).is_err());
    }

    #[test]
    fn gateway_defaults_to_the_first_host() {
        assert_eq!(first_host(Ipv4Addr::new(10, 8, 0, 6), 24), Ipv4Addr::new(10, 8, 0, 1));
        assert_eq!(first_host(Ipv4Addr::new(10, 8, 0, 6), 32), Ipv4Addr::new(10, 8, 0, 6));
    }
}
