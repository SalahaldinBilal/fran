use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use openvpn_rust_bindings::TunSettings;
use vpn_proto::frames::{AdapterInfo, AdapterOptions, FromWorker};

#[cfg(target_os = "linux")]
use super::linux::net as platform;
#[cfg(target_os = "macos")]
use super::macos::net as platform;
#[cfg(windows)]
use super::windows::net as platform;
use crate::session::{Out, Tun, Uplink};

const DEFAULT_MTU: u16 = 1500;

/// A network, through the adapter or around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
    pub metric: Option<u32>,
}

impl Net {
    fn v4(addr: Ipv4Addr, prefix: u8, metric: Option<u32>) -> Self {
        Self { addr: IpAddr::V4(addr), prefix, metric }
    }

    fn v6(addr: Ipv6Addr, prefix: u8, metric: Option<u32>) -> Self {
        Self { addr: IpAddr::V6(addr), prefix, metric }
    }
}

/// What the adapter gets, worked out from what the server pushed and the profile's choices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub addr4: Option<(Ipv4Addr, u8)>,
    pub addr6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
    pub metric: Option<u32>,
    pub routes: Vec<Net>,
    /// Through the computer's current route, not the adapter.
    pub bypass: Vec<Net>,
    pub dns: Vec<IpAddr>,
    pub search: Vec<String>,
    /// Only names in these domains go to the VPN's DNS. Empty with `dns_default`, where every name does.
    pub split: Vec<String>,
    pub dns_default: bool,
    pub routes_all: bool,
}

impl Plan {
    pub fn new(settings: &TunSettings, options: AdapterOptions) -> Self {
        let redirect = &settings.redirect;
        let all4 = options.route_all && redirect.ipv4 && settings.addr4.is_some();
        let all6 = options.route_all && redirect.ipv6 && settings.addr6.is_some();
        // Without its own IPv6, a VPN that takes all traffic and pushes block-ipv6 sends IPv6 into the tunnel to be dropped there.
        let block6 = all4 && settings.addr6.is_none() && settings.block6;
        let metric = settings.route_metric;

        let mut routes = Vec::new();
        routes.extend(settings.routes4.iter().map(|route| Net::v4(route.address, route.prefix, route.metric.or(metric))));
        routes.extend(settings.routes6.iter().map(|route| Net::v6(route.address, route.prefix, route.metric.or(metric))));
        // Two halves instead of replacing the default route, so nothing of the computer's own setup has to be put back.
        if all4 {
            routes.push(Net::v4(Ipv4Addr::UNSPECIFIED, 1, metric));
            routes.push(Net::v4(Ipv4Addr::new(128, 0, 0, 0), 1, metric));
        }
        if all6 || block6 {
            routes.push(Net::v6(Ipv6Addr::UNSPECIFIED, 1, metric));
            routes.push(Net::v6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1, metric));
        }

        let mut bypass = Vec::new();
        if let Some(remote) = settings.remote.filter(|remote| (remote.is_ipv4() && all4) || (remote.is_ipv6() && (all6 || block6))) {
            bypass.push(Net { addr: remote, prefix: if remote.is_ipv4() { 32 } else { 128 }, metric: None });
        }
        bypass.extend(settings.excludes4.iter().map(|route| Net::v4(route.address, route.prefix, route.metric)));
        bypass.extend(settings.excludes6.iter().map(|route| Net::v6(route.address, route.prefix, route.metric)));

        let (dns, search, split, dns_default) = if options.use_vpn_dns {
            let dns: Vec<IpAddr> = settings.dns.iter().map(|server| server.ip()).collect();
            let default = all4 || all6;
            let split = if default { Vec::new() } else { settings.split_domains.clone() };
            (dns, settings.domains.clone(), split, default)
        } else {
            (Vec::new(), Vec::new(), Vec::new(), false)
        };

        Self {
            addr4: settings.addr4,
            addr6: settings.addr6,
            mtu: settings.mtu.unwrap_or(DEFAULT_MTU),
            metric,
            routes,
            bypass,
            dns,
            search,
            split,
            dns_default,
            routes_all: all4 || all6,
        }
    }
}

struct Up {
    device: Arc<platform::Device>,
    applied: Option<platform::Applied>,
    stop: Arc<AtomicBool>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Up {
    fn close(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(applied) = self.applied.take() {
            applied.undo();
        }
    }
}

/// A tunnel on a real adapter. Each time OpenVPN 3 or WireGuard sets up the tunnel, a fresh adapter is made and configured, and
/// it's removed when the tunnel goes down, so a reconnect never keeps stale routes or DNS.
pub struct AdapterTun {
    out: Arc<Out>,
    options: AdapterOptions,
    current: Mutex<Option<Up>>,
}

impl AdapterTun {
    pub fn new(out: Arc<Out>, options: AdapterOptions) -> Self {
        Self { out, options, current: Mutex::new(None) }
    }

    fn close(&self) -> bool {
        let up = self.current.lock().ok().and_then(|mut current| current.take());
        let was_up = up.is_some();
        if let Some(up) = up {
            up.close();
        }
        was_up
    }
}

impl Tun for AdapterTun {
    fn up(&self, settings: TunSettings, uplink: Arc<dyn Uplink>) -> Result<FromWorker, String> {
        self.close();
        let plan = Plan::new(&settings, self.options);
        let device = Arc::new(platform::Device::open(&plan).map_err(|error| format!("The VPN adapter couldn't be made: {error}"))?);
        let applied = platform::apply(&device, &plan)?;
        let info = AdapterInfo {
            name: device.name.clone(),
            index: device.index,
            addr4: plan.addr4,
            addr6: plan.addr6,
            dns: plan.dns.clone(),
            dns_set: applied.dns_set,
            routes_all: plan.routes_all,
        };

        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let device = device.clone();
            let stop = stop.clone();
            let uplink: Weak<dyn Uplink> = Arc::downgrade(&uplink);
            thread::spawn(move || {
                let mut buf = vec![0u8; usize::from(u16::MAX)];
                while !stop.load(Ordering::SeqCst) {
                    match device.read(&mut buf) {
                        Ok(Some(len)) => match uplink.upgrade() {
                            Some(uplink) => uplink.send(&buf[..len]),
                            None => break,
                        },
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
            })
        };
        if let Ok(mut current) = self.current.lock() {
            *current = Some(Up { device, applied: Some(applied), stop, reader: Some(reader) });
        }
        Ok(FromWorker::AdapterUp { adapter: info })
    }

    fn packet(&self, packet: &[u8]) -> bool {
        let device = self.current.lock().ok().and_then(|current| current.as_ref().map(|up| up.device.clone()));
        device.is_some_and(|device| device.write(packet))
    }

    fn down(&self) {
        if self.close() {
            self.out.send(&FromWorker::TunDown);
        }
    }

    fn takes_packets(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use openvpn_rust_bindings::{Redirect, Route};

    use super::*;

    fn pushed() -> TunSettings {
        TunSettings {
            addr4: Some((Ipv4Addr::new(10, 8, 0, 2), 24)),
            routes4: vec![Route { address: Ipv4Addr::new(10, 20, 0, 0), prefix: 16, metric: None }],
            excludes4: vec![Route { address: Ipv4Addr::new(192, 0, 2, 0), prefix: 24, metric: None }],
            redirect: Redirect { ipv4: true, ipv6: false, def1: true },
            remote: Some("203.0.113.7".parse().unwrap()),
            dns: vec!["10.8.0.1:53".parse().unwrap()],
            domains: vec!["corp.example".to_string()],
            split_domains: vec!["corp.example".to_string()],
            mtu: Some(1400),
            ..Default::default()
        }
    }

    const ALL: AdapterOptions = AdapterOptions { route_all: true, use_vpn_dns: true };
    const OWN_NETWORKS: AdapterOptions = AdapterOptions { route_all: false, use_vpn_dns: true };

    #[test]
    fn route_all_takes_both_halves_and_keeps_the_server_outside() {
        let plan = Plan::new(&pushed(), ALL);
        assert!(plan.routes.contains(&Net::v4(Ipv4Addr::UNSPECIFIED, 1, None)));
        assert!(plan.routes.contains(&Net::v4(Ipv4Addr::new(128, 0, 0, 0), 1, None)));
        assert!(plan.bypass.contains(&Net { addr: "203.0.113.7".parse().unwrap(), prefix: 32, metric: None }));
        assert!(plan.bypass.contains(&Net::v4(Ipv4Addr::new(192, 0, 2, 0), 24, None)));
        assert!(plan.routes_all && plan.dns_default);
        assert!(plan.split.is_empty(), "with every name going to the VPN, split domains add nothing");
    }

    #[test]
    fn own_networks_only_ignores_the_redirect() {
        let plan = Plan::new(&pushed(), OWN_NETWORKS);
        assert_eq!(plan.routes, vec![Net::v4(Ipv4Addr::new(10, 20, 0, 0), 16, None)]);
        assert!(!plan.bypass.iter().any(|net| net.prefix == 32), "no server bypass without a default route through the VPN");
        assert!(!plan.routes_all && !plan.dns_default);
        assert_eq!(plan.split, vec!["corp.example".to_string()]);
    }

    #[test]
    fn block_ipv6_only_when_pushed_and_routing_everything() {
        let mut settings = pushed();
        assert!(!Plan::new(&settings, ALL).routes.iter().any(|net| net.addr.is_ipv6()), "IPv6 was taken over without block-ipv6");
        settings.block6 = true;
        assert!(Plan::new(&settings, ALL).routes.contains(&Net::v6(Ipv6Addr::UNSPECIFIED, 1, None)));
        assert!(!Plan::new(&settings, OWN_NETWORKS).routes.iter().any(|net| net.addr.is_ipv6()));
    }

    #[test]
    fn the_profile_can_keep_the_computers_dns() {
        let plan = Plan::new(&pushed(), AdapterOptions { route_all: true, use_vpn_dns: false });
        assert!(plan.dns.is_empty() && plan.split.is_empty() && plan.search.is_empty() && !plan.dns_default);
    }

    #[test]
    fn a_wireguard_full_tunnel_keeps_its_endpoint_outside() {
        let config = vpn_proto::frames::WireGuardStart {
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            endpoint_host: "198.51.100.4".to_string(),
            endpoint_port: 51820,
            allowed_ips: vec![("0.0.0.0".parse().unwrap(), 0), ("::".parse().unwrap(), 0)],
            keepalive_secs: Some(25),
            addresses: vec![("10.64.0.2".parse().unwrap(), 32), ("fc00:bbbb::2".parse().unwrap(), 128)],
            dns: vec!["10.64.0.1".parse().unwrap()],
            search_domains: Vec::new(),
            mtu: None,
        };
        let plan = Plan::new(&crate::wireguard::tun_settings(&config, "198.51.100.4".parse().unwrap()), ALL);
        assert!(plan.bypass.contains(&Net { addr: "198.51.100.4".parse().unwrap(), prefix: 32, metric: None }));
        assert!(plan.routes.contains(&Net::v4(Ipv4Addr::UNSPECIFIED, 1, None)));
        assert!(plan.routes.contains(&Net::v6(Ipv6Addr::UNSPECIFIED, 1, None)));
        assert!(plan.dns_default && plan.mtu == 1420);
    }

    #[test]
    fn route_metrics_fall_back_to_the_pushed_default() {
        let mut settings = pushed();
        settings.route_metric = Some(50);
        settings.routes4.push(Route { address: Ipv4Addr::new(10, 30, 0, 0), prefix: 16, metric: Some(5) });
        let plan = Plan::new(&settings, OWN_NETWORKS);
        assert!(plan.routes.contains(&Net::v4(Ipv4Addr::new(10, 20, 0, 0), 16, Some(50))));
        assert!(plan.routes.contains(&Net::v4(Ipv4Addr::new(10, 30, 0, 0), 16, Some(5))));
    }
}
