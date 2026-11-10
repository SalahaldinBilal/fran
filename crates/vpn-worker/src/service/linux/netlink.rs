//! Just enough rtnetlink to bring a link up and add addresses and routes, without a crate or the `ip` program.

use std::{
    cell::Cell,
    io,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

const IFLA_MTU: u16 = 4;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;

const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;
const HEADER: usize = 16;
const RTMSG: usize = 12;

fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn family(addr: &IpAddr) -> u8 {
    if addr.is_ipv4() { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 }
}

fn octets(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    }
}

fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(align(out.len()), 0);
}

/// The attributes after a fixed header, as (kind, data).
fn attrs(payload: &[u8], fixed: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = align(fixed);
    while at + 4 <= payload.len() {
        let len = usize::from(u16::from_ne_bytes([payload[at], payload[at + 1]]));
        let kind = u16::from_ne_bytes([payload[at + 2], payload[at + 3]]);
        if len < 4 || at + len > payload.len() {
            break;
        }
        out.push((kind, &payload[at + 4..at + len]));
        at += align(len);
    }
    out
}

fn ip_from(data: &[u8]) -> Option<IpAddr> {
    match data.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
        _ => None,
    }
}

pub struct Netlink {
    fd: OwnedFd,
    seq: Cell<u32>,
}

impl Netlink {
    pub fn open() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let bound = unsafe { libc::bind(fd.as_raw_fd(), (&local as *const libc::sockaddr_nl).cast(), std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, seq: Cell::new(0) })
    }

    /// Sends one request and returns the payloads of its replies, up to the kernel's acknowledgement.
    fn request(&self, kind: u16, flags: u16, body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let seq = self.seq.get().wrapping_add(1);
        self.seq.set(seq);
        let mut message = Vec::with_capacity(HEADER + body.len());
        message.extend_from_slice(&((HEADER + body.len()) as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        message.extend_from_slice(&seq.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        let sent = unsafe { libc::send(self.fd.as_raw_fd(), message.as_ptr().cast(), message.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut replies = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let read = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if read < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut at = 0;
            let read = read as usize;
            while at + HEADER <= read {
                let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap_or_default()) as usize;
                let kind = u16::from_ne_bytes([buf[at + 4], buf[at + 5]]);
                let reply_seq = u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap_or_default());
                if len < HEADER || at + len > read {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "a cut off netlink reply"));
                }
                let payload = &buf[at + HEADER..at + len];
                at += align(len);
                if reply_seq != seq {
                    continue;
                }
                match kind {
                    NLMSG_ERROR => {
                        let code = payload.get(..4).map(|bytes| i32::from_ne_bytes(bytes.try_into().unwrap_or_default())).unwrap_or(-libc::EIO);
                        return if code == 0 { Ok(replies) } else { Err(io::Error::from_raw_os_error(-code)) };
                    }
                    NLMSG_DONE => return Ok(replies),
                    _ => replies.push(payload.to_vec()),
                }
            }
        }
    }

    pub fn set_link_up(&self, index: u32, mtu: u16) -> io::Result<()> {
        let mut body = vec![libc::AF_UNSPEC as u8, 0, 0, 0];
        body.extend_from_slice(&(index as i32).to_ne_bytes());
        body.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
        body.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
        attr(&mut body, IFLA_MTU, &u32::from(mtu).to_ne_bytes());
        self.request(RTM_NEWLINK, 0, &body).map(drop)
    }

    pub fn add_address(&self, index: u32, addr: IpAddr, prefix: u8) -> io::Result<()> {
        let mut body = vec![family(&addr), prefix, 0, RT_SCOPE_UNIVERSE];
        body.extend_from_slice(&index.to_ne_bytes());
        attr(&mut body, IFA_LOCAL, &octets(&addr));
        attr(&mut body, IFA_ADDRESS, &octets(&addr));
        self.request(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &body).map(drop)
    }

    fn route_body(addr: IpAddr, prefix: u8, gateway: Option<IpAddr>, index: u32, metric: Option<u32>) -> Vec<u8> {
        // IPv6 routes are always universe scope. An IPv4 route straight onto a link is link scope, like `ip route add ... dev`.
        let scope = if gateway.is_none() && addr.is_ipv4() { RT_SCOPE_LINK } else { RT_SCOPE_UNIVERSE };
        let mut body = vec![family(&addr), prefix, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, scope, RTN_UNICAST];
        body.extend_from_slice(&0u32.to_ne_bytes());
        attr(&mut body, RTA_DST, &octets(&addr));
        attr(&mut body, RTA_OIF, &index.to_ne_bytes());
        if let Some(gateway) = gateway {
            attr(&mut body, RTA_GATEWAY, &octets(&gateway));
        }
        if let Some(metric) = metric {
            attr(&mut body, RTA_PRIORITY, &metric.to_ne_bytes());
        }
        body
    }

    /// False when the same route is already there, which belongs to someone else then.
    pub fn add_route(&self, addr: IpAddr, prefix: u8, gateway: Option<IpAddr>, index: u32, metric: Option<u32>) -> io::Result<bool> {
        match self.request(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &Self::route_body(addr, prefix, gateway, index, metric)) {
            Ok(_) => Ok(true),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn delete_route(&self, addr: IpAddr, prefix: u8, gateway: Option<IpAddr>, index: u32) -> io::Result<()> {
        match self.request(RTM_DELROUTE, 0, &Self::route_body(addr, prefix, gateway, index, None)) {
            Err(error) if error.raw_os_error() != Some(libc::ESRCH) => Err(error),
            _ => Ok(()),
        }
    }

    /// The gateway and interface the computer uses for `addr` right now.
    pub fn route_to(&self, addr: IpAddr) -> io::Result<(Option<IpAddr>, u32)> {
        let full = if addr.is_ipv4() { 32 } else { 128 };
        let mut body = vec![family(&addr), full, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&0u32.to_ne_bytes());
        attr(&mut body, RTA_DST, &octets(&addr));
        let replies = self.request(RTM_GETROUTE, 0, &body)?;
        let reply = replies.first().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("No route to {addr}")))?;
        let mut gateway = None;
        let mut index = None;
        for (kind, data) in attrs(reply, RTMSG) {
            match kind {
                RTA_GATEWAY => gateway = ip_from(data),
                RTA_OIF if data.len() == 4 => index = Some(u32::from_ne_bytes(data.try_into().unwrap_or_default())),
                _ => {}
            }
        }
        Ok((gateway, index.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("No route to {addr}")))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_read_back_with_padding() {
        let mut body = vec![0u8; RTMSG];
        attr(&mut body, RTA_GATEWAY, &[192, 168, 1, 1]);
        attr(&mut body, 99, &[1, 2, 3]);
        attr(&mut body, RTA_OIF, &7u32.to_ne_bytes());
        let found = attrs(&body, RTMSG);
        assert_eq!(found[0], (RTA_GATEWAY, &[192u8, 168, 1, 1][..]));
        assert_eq!(found[1], (99, &[1u8, 2, 3][..]));
        assert_eq!(found[2], (RTA_OIF, &7u32.to_ne_bytes()[..]));
    }
}
