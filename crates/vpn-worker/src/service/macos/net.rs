use std::{
    ffi::CStr,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Command, Stdio},
};

use crate::service::{
    adapter::Plan,
    leftovers::{self, Leftover},
};

// From sys/kern_control.h, sys/sys_domain.h and net/if_utun.h.
const PF_SYSTEM: libc::c_int = 32;
const AF_SYSTEM: u8 = 32;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: u16 = 2;
const UTUN_OPT_IFNAME: libc::c_int = 2;
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";
/// utun puts the packet's address family in front of every packet, in network byte order.
const HEADER: usize = 4;
const READ_WAIT_MS: libc::c_int = 250;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [libc::c_char; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

pub struct Device {
    fd: OwnedFd,
    pub name: String,
    pub index: u32,
}

impl Device {
    /// A new utun device, numbered by the kernel. It goes away when this closes.
    pub fn open(_plan: &Plan) -> io::Result<Self> {
        let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };

        let mut info: CtlInfo = unsafe { std::mem::zeroed() };
        for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL) {
            *slot = *byte as libc::c_char;
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let address = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        let connected = unsafe { libc::connect(fd.as_raw_fd(), (&address as *const SockaddrCtl).cast(), std::mem::size_of::<SockaddrCtl>() as libc::socklen_t) };
        if connected < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        if unsafe { libc::getsockopt(fd.as_raw_fd(), SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name.as_mut_ptr().cast(), &mut len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy().to_string();
        Ok(Self { fd, name, index })
    }

    /// None when nothing arrived for a moment, so the reader can check whether it should stop.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let mut poll = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, READ_WAIT_MS) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(error) };
        }
        if ready == 0 {
            return Ok(None);
        }
        let mut packet = vec![0u8; buf.len() + HEADER];
        let read = unsafe { libc::read(self.fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            return if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) { Ok(None) } else { Err(error) };
        }
        let read = read as usize;
        if read <= HEADER {
            return Ok(None);
        }
        let len = read - HEADER;
        buf[..len].copy_from_slice(&packet[HEADER..read]);
        Ok(Some(len))
    }

    pub fn write(&self, packet: &[u8]) -> bool {
        let family = match packet.first().map(|byte| byte >> 4) {
            Some(4) => libc::AF_INET,
            Some(6) => libc::AF_INET6,
            _ => return false,
        };
        let mut framed = Vec::with_capacity(packet.len() + HEADER);
        framed.extend_from_slice(&(family as u32).to_be_bytes());
        framed.extend_from_slice(packet);
        let written = unsafe { libc::write(self.fd.as_raw_fd(), framed.as_ptr().cast(), framed.len()) };
        written == framed.len() as isize
    }
}

fn run(program: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("Couldn't run {program}: {error}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(format!("{program} {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim()))
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn network(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
            IpAddr::V4(Ipv4Addr::from(u32::from(addr) & mask))
        }
        IpAddr::V6(addr) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix.min(128))) };
            IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
        }
    }
}

fn family_flag(addr: &IpAddr) -> Vec<String> {
    if addr.is_ipv6() { args(&["-inet6"]) } else { Vec::new() }
}

/// `route add`, through a device or a gateway. False when the route is already there, which belongs to someone else then.
fn add_route(addr: IpAddr, prefix: u8, via: Via<'_>) -> Result<bool, String> {
    let mut command = args(&["-n", "add"]);
    command.extend(family_flag(&addr));
    command.push("-net".to_string());
    command.push(format!("{}/{prefix}", network(addr, prefix)));
    match via {
        Via::Device(name) => command.extend(args(&["-interface", name])),
        Via::Gateway(gateway) => command.push(gateway.to_string()),
    }
    match run("/sbin/route", &command) {
        Ok(_) => Ok(true),
        Err(error) if error.contains("File exists") => Ok(false),
        Err(error) => Err(error),
    }
}

fn delete_route(addr: IpAddr, prefix: u8) {
    let mut command = args(&["-n", "delete"]);
    command.extend(family_flag(&addr));
    command.push("-net".to_string());
    command.push(format!("{}/{prefix}", network(addr, prefix)));
    let _ = run("/sbin/route", &command);
}

enum Via<'a> {
    Device(&'a str),
    Gateway(IpAddr),
}

/// The gateway and interface the computer uses for `addr` right now, from `route get`.
fn route_to(addr: IpAddr) -> Result<(Option<IpAddr>, String), String> {
    let mut command = args(&["-n", "get"]);
    command.extend(family_flag(&addr));
    command.push(addr.to_string());
    let text = run("/sbin/route", &command).map_err(|error| format!("Couldn't find the way to {addr} outside the VPN: {error}"))?;
    let field = |name: &str| text.lines().find_map(|line| line.trim().strip_prefix(name).map(|value| value.trim().to_string()));
    let interface = field("interface:").ok_or_else(|| format!("No route to {addr}"))?;
    // A link-local gateway comes with its interface, like fe80::1%en0.
    let gateway = field("gateway:").and_then(|gateway| gateway.split('%').next().and_then(|gateway| gateway.parse().ok()));
    Ok((gateway, interface))
}

fn scutil(script: &str) -> Result<(), String> {
    let mut child = Command::new("/usr/sbin/scutil").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|error| format!("Couldn't run scutil: {error}"))?;
    child.stdin.take().ok_or("scutil has no input")?.write_all(script.as_bytes()).map_err(|error| error.to_string())?;
    let output = child.wait_with_output().map_err(|error| error.to_string())?;
    if output.status.success() { Ok(()) } else { Err(format!("scutil failed: {}", String::from_utf8_lossy(&output.stderr).trim())) }
}

/// A DNS entry in the dynamic store. With match domains only those names go to the VPN. An empty match domain
/// makes it a resolver for every name.
fn set_dns(key: &str, plan: &Plan) -> Result<(), String> {
    let mut script = String::from("d.init\n");
    let servers: Vec<String> = plan.dns.iter().map(ToString::to_string).collect();
    script.push_str(&format!("d.add ServerAddresses * {}\n", servers.join(" ")));
    if !plan.search.is_empty() {
        script.push_str(&format!("d.add SearchDomains * {}\n", plan.search.join(" ")));
    }
    if plan.dns_default {
        script.push_str("d.add SupplementalMatchDomains * \"\"\n");
    } else if !plan.split.is_empty() {
        script.push_str(&format!("d.add SupplementalMatchDomains * {}\n", plan.split.join(" ")));
    }
    script.push_str(&format!("set {key}\nquit\n"));
    scutil(&script)
}

fn remove_dns(key: &str) {
    let _ = scutil(&format!("remove {key}\nquit\n"));
}

fn safe_word(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_'))
}

pub struct Applied {
    outside: Vec<Leftover>,
    pub dns_set: bool,
}

impl Applied {
    pub fn undo(self) {
        for item in &self.outside {
            match item {
                Leftover::Route { addr, prefix, .. } => delete_route(*addr, *prefix),
                Leftover::DnsKey { key } => remove_dns(key),
                Leftover::NrptRule { .. } | Leftover::Adapter { .. } => {}
            }
            leftovers::remove(item);
        }
    }
}

fn fill(device: &Device, plan: &Plan, applied: &mut Applied) -> Result<(), String> {
    let name = device.name.as_str();
    let mtu = plan.mtu.to_string();
    if let Some((addr, prefix)) = plan.addr4 {
        let mask = Ipv4Addr::from(if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) }).to_string();
        // utun is point to point, so the address is its own peer and the VPN's subnet gets a route of its own.
        run("/sbin/ifconfig", &args(&[name, "inet", &addr.to_string(), &addr.to_string(), "netmask", &mask, "mtu", &mtu, "up"]))?;
        add_route(IpAddr::V4(addr), prefix, Via::Device(name))?;
    }
    if let Some((addr, prefix)) = plan.addr6 {
        run("/sbin/ifconfig", &args(&[name, "inet6", &addr.to_string(), "prefixlen", &prefix.to_string(), "mtu", &mtu, "up"]))?;
    }
    // Before the routes into the adapter, so the lookup still finds the computer's own way out.
    for net in &plan.bypass {
        let (gateway, interface) = route_to(net.addr)?;
        if interface == device.name {
            continue;
        }
        let index = std::ffi::CString::new(interface.clone()).map(|interface| unsafe { libc::if_nametoindex(interface.as_ptr()) }).unwrap_or(0);
        let item = Leftover::Route { addr: net.addr, prefix: net.prefix, gateway, index };
        leftovers::add(item.clone());
        let via = match gateway {
            Some(gateway) => Via::Gateway(gateway),
            None => Via::Device(&interface),
        };
        match add_route(net.addr, net.prefix, via) {
            Ok(true) => applied.outside.push(item),
            Ok(false) => leftovers::remove(&item),
            Err(error) => {
                leftovers::remove(&item);
                return Err(format!("Couldn't keep {}/{} outside the VPN: {error}", net.addr, net.prefix));
            }
        }
    }
    for net in &plan.routes {
        add_route(net.addr, net.prefix, Via::Device(name)).map_err(|error| format!("Couldn't route {}/{} through the VPN: {error}", net.addr, net.prefix))?;
    }
    // Domains go into scutil's own command language, so only plain names do.
    let domains_ok = plan.search.iter().chain(&plan.split).all(|domain| safe_word(domain));
    if !plan.dns.is_empty() && domains_ok {
        let key = format!("State:/Network/Service/FranVpn-{name}/DNS");
        let item = Leftover::DnsKey { key: key.clone() };
        leftovers::add(item.clone());
        applied.outside.push(item);
        applied.dns_set = set_dns(&key, plan).is_ok();
    }
    Ok(())
}

pub fn apply(device: &Device, plan: &Plan) -> Result<Applied, String> {
    let mut applied = Applied { outside: Vec::new(), dns_set: false };
    match fill(device, plan, &mut applied) {
        Ok(()) => Ok(applied),
        Err(error) => {
            applied.undo();
            Err(error)
        }
    }
}

/// Bypass routes and DNS entries a crashed run left. Its utun devices went away with it.
pub fn clean_leftovers() {
    for item in leftovers::take_all() {
        match item {
            Leftover::Route { addr, prefix, .. } => delete_route(addr, prefix),
            Leftover::DnsKey { key } => remove_dns(&key),
            Leftover::NrptRule { .. } | Leftover::Adapter { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_name_the_network_not_the_host() {
        assert_eq!(network("10.8.0.2".parse().unwrap(), 24), "10.8.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(network("203.0.113.7".parse().unwrap(), 32), "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(network("fd00::1:2".parse().unwrap(), 64), "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(network("0.0.0.0".parse().unwrap(), 1), "0.0.0.0".parse::<IpAddr>().unwrap());
    }
}
