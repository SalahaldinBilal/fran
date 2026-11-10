//! One WireGuard peer, run with boringtun. The packets go to the same `Tun` an OpenVPN session uses: Fran's network
//! stack for an own tunnel, or the computer's adapter in the service.

use std::{
    io::{ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use openvpn_rust_bindings::{Route, TunSettings};
use vpn_proto::frames::{self, Frame, FromWorker, ToWorker, WireGuardStart};
use zeroize::Zeroizing;

use crate::session::{Out, Tun, Uplink};

const TICK: Duration = Duration::from_millis(250);
const STATS_EVERY: Duration = Duration::from_secs(2);
/// WireGuard sends the first handshake again after 5 seconds, so no answer by then means a wrong endpoint or key.
const FIRST_ANSWER: Duration = Duration::from_secs(6);
/// WireGuard stops using a session's keys after this long.
const SESSION_LIFETIME: Duration = Duration::from_secs(180);
const DEFAULT_MTU: u16 = 1420;
const MAX_DATAGRAM: usize = 65_535;
/// boringtun needs room for its header and tag, and never less than a handshake message.
const OVERHEAD: usize = 148;

fn key(text: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = Zeroizing::new(STANDARD.decode(text.trim()).map_err(|_| format!("The WireGuard {what} isn't valid base64"))?);
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("The WireGuard {what} isn't 32 bytes"))
}

fn network(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => {
            let prefix = u32::from(prefix.min(32));
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(addr) & mask))
        }
        IpAddr::V6(addr) => {
            let prefix = u32::from(prefix.min(128));
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
        }
    }
}

/// Whether a packet from `source` may come out of the tunnel, by the peer's AllowedIPs.
pub fn allows(allowed: &[(IpAddr, u8)], source: IpAddr) -> bool {
    allowed.iter().any(|&(addr, prefix)| addr.is_ipv4() == source.is_ipv4() && network(addr, prefix) == network(source, prefix))
}

/// The settings an OpenVPN server would have pushed, so the adapter and Fran's network stack treat both the same.
pub fn tun_settings(config: &WireGuardStart, endpoint: IpAddr) -> TunSettings {
    let mut settings = TunSettings { remote: Some(endpoint), mtu: Some(config.mtu.unwrap_or(DEFAULT_MTU)), ..Default::default() };
    for &(addr, prefix) in &config.addresses {
        match addr {
            IpAddr::V4(addr) if settings.addr4.is_none() => settings.addr4 = Some((addr, prefix.min(32))),
            IpAddr::V6(addr) if settings.addr6.is_none() => settings.addr6 = Some((addr, prefix.min(128))),
            _ => {}
        }
    }
    let mut specific = Vec::new();
    for &(addr, prefix) in &config.allowed_ips {
        match network(addr, prefix) {
            IpAddr::V4(_) if prefix == 0 => settings.redirect.ipv4 = true,
            IpAddr::V6(_) if prefix == 0 => settings.redirect.ipv6 = true,
            IpAddr::V4(address) => {
                settings.routes4.push(Route { address, prefix: prefix.min(32), metric: None });
                specific.push((addr, prefix));
            }
            IpAddr::V6(address) => {
                settings.routes6.push(Route { address, prefix: prefix.min(128), metric: None });
                specific.push((addr, prefix));
            }
        }
    }
    settings.redirect.def1 = settings.redirect.ipv4 || settings.redirect.ipv6;
    // A default route is kept off the endpoint through `remote`. Narrower ones like 0.0.0.0/1 need it said here.
    if allows(&specific, endpoint) {
        match endpoint {
            IpAddr::V4(address) => settings.excludes4.push(Route { address, prefix: 32, metric: None }),
            IpAddr::V6(address) => settings.excludes6.push(Route { address, prefix: 128, metric: None }),
        }
    }
    settings.dns = config.dns.iter().map(|&ip| SocketAddr::new(ip, 53)).collect();
    settings.domains = config.search_domains.clone();
    settings.split_domains = config.search_domains.clone();
    settings
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("Couldn't look up the WireGuard server {host}: {error}"))?
        .min_by_key(SocketAddr::is_ipv6)
        .ok_or_else(|| format!("The WireGuard server {host} has no address"))
}

struct Wire {
    tunn: Mutex<Tunn>,
    socket: UdpSocket,
    endpoint: SocketAddr,
    out: Arc<Out>,
    tun: Arc<dyn Tun>,
    allowed: Vec<(IpAddr, u8)>,
    settings: Mutex<Option<TunSettings>>,
    handshake_at: Mutex<Option<Instant>>,
    /// Since a packet waited for a new handshake, while the last session's keys were too old to use.
    waiting_since: Mutex<Option<Instant>>,
    up: AtomicBool,
    stale: AtomicBool,
    stop: AtomicBool,
    ended: AtomicBool,
    me: Weak<Wire>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Wire {
    fn open(config: &WireGuardStart, out: Arc<Out>, tun: Arc<dyn Tun>) -> Result<Arc<Self>, String> {
        let private = StaticSecret::from(key(&config.private_key, "private key")?);
        let peer = PublicKey::from(key(&config.peer_public_key, "peer public key")?);
        let preshared = config.preshared_key.as_deref().filter(|text| !text.trim().is_empty()).map(|text| key(text, "preshared key")).transpose()?;
        let endpoint = resolve(&config.endpoint_host, config.endpoint_port)?;
        let bind: SocketAddr = if endpoint.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
        let socket = UdpSocket::bind(bind).map_err(|error| format!("Couldn't open a UDP socket for WireGuard: {error}"))?;
        socket.connect(endpoint).map_err(|error| format!("Couldn't reach the WireGuard server at {endpoint}: {error}"))?;
        socket.set_read_timeout(Some(TICK)).map_err(|error| error.to_string())?;
        let tunn = Tunn::new(private, peer, preshared, config.keepalive_secs.filter(|secs| *secs > 0), 1, None);
        let settings = tun_settings(config, endpoint.ip());
        Ok(Arc::new_cyclic(|me| Self {
            tunn: Mutex::new(tunn),
            socket,
            endpoint,
            out,
            tun,
            allowed: config.allowed_ips.clone(),
            settings: Mutex::new(Some(settings)),
            handshake_at: Mutex::new(None),
            waiting_since: Mutex::new(None),
            up: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            me: me.clone(),
        }))
    }

    fn end(&self, error: Option<String>) {
        self.stop.store(true, Ordering::SeqCst);
        if !self.ended.swap(true, Ordering::SeqCst) {
            self.out.send(&FromWorker::Ended { error });
        }
    }

    fn initiate(&self) {
        let mut dst = vec![0u8; OVERHEAD];
        let mut tunn = lock(&self.tunn);
        if let TunnResult::WriteToNetwork(packet) = tunn.format_handshake_initiation(&mut dst, false) {
            let _ = self.socket.send(packet);
        }
    }

    /// Notices a handshake that finished since the last look, from the time boringtun reports.
    fn check_handshake(&self, tunn: &Tunn) {
        let Some(at) = tunn.time_since_last_handshake().and_then(|since| Instant::now().checked_sub(since)) else { return };
        {
            let mut last = lock(&self.handshake_at);
            if last.is_some_and(|last| at <= last + Duration::from_secs(1)) {
                return;
            }
            *last = Some(at);
        }
        lock(&self.waiting_since).take();
        if !self.up.load(Ordering::SeqCst) {
            self.bring_up();
        } else if self.stale.swap(false, Ordering::SeqCst) {
            self.out.send(&FromWorker::Handshake);
        }
    }

    fn bring_up(&self) {
        let (Some(settings), Some(me)) = (lock(&self.settings).take(), self.me.upgrade()) else { return };
        match self.tun.up(settings, me) {
            Ok(message) => {
                self.up.store(true, Ordering::SeqCst);
                self.out.send(&message);
            }
            Err(message) => {
                self.out.send(&FromWorker::TunFailed { message });
                self.end(None);
            }
        }
    }

    fn receive_loop(&self) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut dst = vec![0u8; MAX_DATAGRAM];
        while !self.stop.load(Ordering::SeqCst) {
            let len = match self.socket.recv(&mut buf) {
                Ok(len) => len,
                // Windows reports an ICMP "port unreachable" from an earlier send as a reset. The server may come back.
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused) => continue,
                Err(error) => {
                    self.end(Some(format!("The connection to the WireGuard server failed: {error}")));
                    break;
                }
            };
            let delivered = {
                let mut tunn = lock(&self.tunn);
                let delivered = match tunn.decapsulate(Some(self.endpoint.ip()), &buf[..len], &mut dst) {
                    TunnResult::WriteToNetwork(packet) => {
                        let _ = self.socket.send(packet);
                        while let TunnResult::WriteToNetwork(packet) = tunn.decapsulate(None, &[], &mut dst) {
                            let _ = self.socket.send(packet);
                        }
                        None
                    }
                    TunnResult::WriteToTunnelV4(packet, source) if allows(&self.allowed, IpAddr::V4(source)) => Some(packet.to_vec()),
                    TunnResult::WriteToTunnelV6(packet, source) if allows(&self.allowed, IpAddr::V6(source)) => Some(packet.to_vec()),
                    _ => None,
                };
                self.check_handshake(&tunn);
                delivered
            };
            if let Some(packet) = delivered.filter(|_| self.up.load(Ordering::SeqCst)) {
                self.tun.packet(&packet);
            }
        }
    }

    fn timer_loop(&self) {
        let started = Instant::now();
        let mut dst = vec![0u8; MAX_DATAGRAM];
        let mut warned = false;
        let mut last_stats = Instant::now();
        while !self.stop.load(Ordering::SeqCst) {
            thread::sleep(TICK);
            let stats = {
                let mut tunn = lock(&self.tunn);
                if let TunnResult::WriteToNetwork(packet) = tunn.update_timers(&mut dst) {
                    let _ = self.socket.send(packet);
                }
                self.check_handshake(&tunn);
                let (_, sent, received, _, _) = tunn.stats();
                (sent, received)
            };

            if !self.up.load(Ordering::SeqCst) && !warned && started.elapsed() >= FIRST_ANSWER {
                warned = true;
                self.out.send(&FromWorker::Event { name: "HANDSHAKE_TIMEOUT".to_string(), info: self.endpoint.to_string(), error: true, fatal: false });
            }
            let waited_too_long = lock(&self.waiting_since).is_some_and(|since| since.elapsed() >= FIRST_ANSWER);
            if self.up.load(Ordering::SeqCst) && waited_too_long && !self.stale.swap(true, Ordering::SeqCst) {
                self.out.send(&FromWorker::Event { name: "RECONNECTING".to_string(), info: String::new(), error: false, fatal: false });
            }

            if last_stats.elapsed() >= STATS_EVERY {
                last_stats = Instant::now();
                let (sent, received) = stats;
                if !self.out.send(&FromWorker::Stats { bytes_in: received as i64, bytes_out: sent as i64 }) {
                    self.end(None);
                }
            }
        }
    }
}

impl Uplink for Wire {
    fn send(&self, packet: &[u8]) {
        let mut dst = vec![0u8; packet.len() + OVERHEAD];
        let mut tunn = lock(&self.tunn);
        if tunn.time_since_last_handshake().is_none_or(|since| since >= SESSION_LIFETIME) {
            lock(&self.waiting_since).get_or_insert_with(Instant::now);
        }
        if let TunnResult::WriteToNetwork(datagram) = tunn.encapsulate(packet, &mut dst) {
            let _ = self.socket.send(datagram);
        }
    }
}

/// Runs until Fran sends Stop or goes away. "Up" waits for the first handshake, since nothing earlier says the server is there.
pub fn run(mut reader: impl Read, out: Arc<Out>, tun: Arc<dyn Tun>, config: WireGuardStart) -> i32 {
    let wire = match Wire::open(&config, out.clone(), tun.clone()) {
        Ok(wire) => wire,
        Err(message) => {
            out.send(&FromWorker::Refused { message });
            return 1;
        }
    };
    drop(config);
    wire.initiate();

    let receiver = {
        let wire = wire.clone();
        thread::spawn(move || wire.receive_loop())
    };
    let timers = {
        let wire = wire.clone();
        thread::spawn(move || wire.timer_loop())
    };

    loop {
        match frames::read_frame::<ToWorker>(&mut reader) {
            Ok(Some(Frame::Packet(packet))) if tun.takes_packets() => wire.send(&packet),
            Ok(Some(Frame::Message(ToWorker::Stop))) => break,
            Ok(Some(Frame::Message(_))) => {}
            Ok(Some(Frame::Packet(_))) | Ok(None) | Err(_) => break,
        }
    }

    wire.stop.store(true, Ordering::SeqCst);
    let _ = receiver.join();
    let _ = timers.join();
    if wire.up.load(Ordering::SeqCst) {
        tun.down();
    }
    wire.end(None);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str, prefix: u8) -> (IpAddr, u8) {
        (text.parse().unwrap(), prefix)
    }

    #[test]
    fn decrypted_packets_from_outside_allowed_ips_are_dropped() {
        let allowed = [net("10.64.0.1", 32), net("10.20.0.0", 16), net("fd00::", 64)];
        assert!(allows(&allowed, "10.20.7.9".parse().unwrap()));
        assert!(allows(&allowed, "fd00::42".parse().unwrap()));
        assert!(!allows(&allowed, "10.21.0.1".parse().unwrap()), "a peer could inject packets claiming any source");
        assert!(!allows(&allowed, "192.168.1.10".parse().unwrap()));
        assert!(allows(&[net("0.0.0.0", 0)], "192.168.1.10".parse().unwrap()));
        assert!(!allows(&[net("0.0.0.0", 0)], "fd00::1".parse().unwrap()));
    }

    #[test]
    fn allowed_ips_with_host_bits_become_proper_routes() {
        let mut config = start();
        config.allowed_ips = vec![net("10.20.30.40", 16)];
        let settings = tun_settings(&config, "203.0.113.7".parse().unwrap());
        assert_eq!(settings.routes4, vec![Route { address: Ipv4Addr::new(10, 20, 0, 0), prefix: 16, metric: None }]);
    }

    #[test]
    fn split_default_routes_keep_the_endpoint_outside() {
        let mut config = start();
        config.allowed_ips = vec![net("0.0.0.0", 1), net("128.0.0.0", 1)];
        let settings = tun_settings(&config, "203.0.113.7".parse().unwrap());
        assert!(!settings.redirect.ipv4);
        assert_eq!(settings.excludes4, vec![Route { address: Ipv4Addr::new(203, 0, 113, 7), prefix: 32, metric: None }]);
    }

    fn start() -> WireGuardStart {
        WireGuardStart {
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            endpoint_host: "203.0.113.7".to_string(),
            endpoint_port: 51820,
            allowed_ips: vec![net("0.0.0.0", 0), net("::", 0)],
            keepalive_secs: None,
            addresses: vec![net("10.64.0.2", 32), net("fc00:bbbb::2", 128)],
            dns: vec!["10.64.0.1".parse().unwrap()],
            search_domains: Vec::new(),
            mtu: None,
        }
    }
}
