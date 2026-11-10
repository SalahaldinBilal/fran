use std::{
    ffi::CStr,
    io,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use super::netlink::Netlink;
use crate::service::{
    adapter::Plan,
    leftovers::{self, Leftover},
};

/// `_IOW('T', 202, int)` from linux/if_tun.h.
const TUNSETIFF: u64 = 0x4004_54ca;
const READ_WAIT_MS: libc::c_int = 250;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct Device {
    fd: OwnedFd,
    pub name: String,
    pub index: u32,
}

impl Device {
    /// A new `franvpnN` tun device. It's removed by the kernel when this closes.
    pub fn open(_plan: &Plan) -> io::Result<Self> {
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut request: IfReq = unsafe { std::mem::zeroed() };
        for (slot, byte) in request.name.iter_mut().zip(b"franvpn%d") {
            *slot = *byte as libc::c_char;
        }
        request.flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = unsafe { CStr::from_ptr(request.name.as_ptr()) }.to_string_lossy().to_string();
        let index = unsafe { libc::if_nametoindex(request.name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
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
        let read = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            return if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) { Ok(None) } else { Err(error) };
        }
        Ok(Some(read as usize))
    }

    pub fn write(&self, packet: &[u8]) -> bool {
        let written = unsafe { libc::write(self.fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        written == packet.len() as isize
    }
}

/// What was changed outside the adapter. Routes through the adapter go away with it.
pub struct Applied {
    index: u32,
    bypass: Vec<Leftover>,
    resolved: bool,
    pub dns_set: bool,
}

impl Applied {
    pub fn undo(self) {
        if self.resolved {
            let _ = resolved::revert(self.index);
        }
        if let Ok(netlink) = Netlink::open() {
            for item in &self.bypass {
                if let Leftover::Route { addr, prefix, gateway, index } = item {
                    let _ = netlink.delete_route(*addr, *prefix, *gateway, *index);
                }
                leftovers::remove(item);
            }
        }
    }
}

fn fill(netlink: &Netlink, device: &Device, plan: &Plan, applied: &mut Applied) -> Result<(), String> {
    let failed = |what: &str, error: io::Error| format!("Couldn't {what} on the VPN adapter: {error}");
    netlink.set_link_up(device.index, plan.mtu).map_err(|error| failed("bring up the link", error))?;
    if let Some((addr, prefix)) = plan.addr4 {
        netlink.add_address(device.index, IpAddr::V4(addr), prefix).map_err(|error| failed("set the IPv4 address", error))?;
    }
    if let Some((addr, prefix)) = plan.addr6 {
        netlink.add_address(device.index, IpAddr::V6(addr), prefix).map_err(|error| failed("set the IPv6 address", error))?;
    }
    // Before the routes into the adapter, so the lookup still finds the computer's own way out.
    for net in &plan.bypass {
        let (gateway, index) = netlink.route_to(net.addr).map_err(|error| format!("Couldn't find the way to {} outside the VPN: {error}", net.addr))?;
        if index == device.index {
            continue;
        }
        let item = Leftover::Route { addr: net.addr, prefix: net.prefix, gateway, index };
        leftovers::add(item.clone());
        match netlink.add_route(net.addr, net.prefix, gateway, index, net.metric) {
            Ok(true) => applied.bypass.push(item),
            Ok(false) => leftovers::remove(&item),
            Err(error) => {
                leftovers::remove(&item);
                return Err(format!("Couldn't keep {}/{} outside the VPN: {error}", net.addr, net.prefix));
            }
        }
    }
    for net in &plan.routes {
        netlink
            .add_route(net.addr, net.prefix, None, device.index, net.metric)
            .map_err(|error| format!("Couldn't route {}/{} through the VPN: {error}", net.addr, net.prefix))?;
    }
    if !plan.dns.is_empty() {
        applied.resolved = true;
        applied.dns_set = resolved::set(device.index, plan).is_ok();
    }
    Ok(())
}

pub fn apply(device: &Device, plan: &Plan) -> Result<Applied, String> {
    let netlink = Netlink::open().map_err(|error| format!("Couldn't talk to the kernel's routing: {error}"))?;
    let mut applied = Applied { index: device.index, bypass: Vec::new(), resolved: false, dns_set: false };
    match fill(&netlink, device, plan, &mut applied) {
        Ok(()) => Ok(applied),
        Err(error) => {
            applied.undo();
            Err(error)
        }
    }
}

/// Routes a crashed run left behind. Its adapters went away with it.
pub fn clean_leftovers() {
    let items = leftovers::take_all();
    let Ok(netlink) = Netlink::open() else { return };
    for item in items {
        if let Leftover::Route { addr, prefix, gateway, index } = item {
            let _ = netlink.delete_route(addr, prefix, gateway, index);
        }
    }
}

/// systemd-resolved's D-Bus API. Without resolved the computer keeps its DNS, which `AdapterInfo::dns_set` reports.
mod resolved {
    use std::net::IpAddr;

    use zbus::{blocking::Connection, zvariant::DynamicType};

    use crate::service::adapter::Plan;

    fn call<B: serde::Serialize + DynamicType>(connection: &Connection, method: &str, body: &B) -> zbus::Result<()> {
        connection
            .call_method(Some("org.freedesktop.resolve1"), "/org/freedesktop/resolve1", Some("org.freedesktop.resolve1.Manager"), method, body)
            .map(drop)
    }

    pub fn set(index: u32, plan: &Plan) -> zbus::Result<()> {
        let connection = Connection::system()?;
        let link = index as i32;
        let servers: Vec<(i32, Vec<u8>)> = plan
            .dns
            .iter()
            .map(|server| match server {
                IpAddr::V4(addr) => (libc::AF_INET, addr.octets().to_vec()),
                IpAddr::V6(addr) => (libc::AF_INET6, addr.octets().to_vec()),
            })
            .collect();
        call(&connection, "SetLinkDNS", &(link, servers))?;
        // `~` domains only route lookups to this link, plain ones are also searched for short names.
        let mut domains: Vec<(String, bool)> = plan.search.iter().map(|domain| (domain.clone(), false)).collect();
        domains.extend(plan.split.iter().map(|domain| (domain.clone(), true)));
        if plan.dns_default {
            domains.push((".".to_string(), true));
        }
        call(&connection, "SetLinkDomains", &(link, domains))?;
        call(&connection, "SetLinkDefaultRoute", &(link, plan.dns_default))
    }

    pub fn revert(index: u32) -> zbus::Result<()> {
        call(&Connection::system()?, "RevertLink", &(index as i32,))
    }
}
