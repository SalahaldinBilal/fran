use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU32, Ordering},
};

use windows::{
    Win32::{
        Foundation::{ERROR_NO_MORE_ITEMS, ERROR_OBJECT_ALREADY_EXISTS, GetLastError, WIN32_ERROR},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, DeleteIpForwardEntry2,
                GetBestRoute2, GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
                MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings, SetIpInterfaceEntry,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN6_ADDR, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET},
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW},
            Threading::WaitForSingleObject,
        },
    },
    core::{GUID, HSTRING, PCSTR, PCWSTR, PWSTR},
};

use super::wintun::{self, Session, Wintun};
use crate::service::{
    adapter::Plan,
    leftovers::{self, Leftover},
};

const RING: u32 = 0x40_0000;
const READ_WAIT_MS: u32 = 250;
/// Low, so Windows prefers the VPN's DNS servers and routes over the computer's own.
const INTERFACE_METRIC: u32 = 5;
const NRPT: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const NRPT_PREFIX: &str = "FranVpn-";

static NEXT: AtomicU32 = AtomicU32::new(1);

fn win32(code: WIN32_ERROR, what: &str) -> Result<(), String> {
    if code.is_ok() { Ok(()) } else { Err(format!("Couldn't {what}: {}", windows::core::Error::from(code.to_hresult()).message())) }
}

pub struct Device {
    wintun: &'static Wintun,
    adapter: wintun::Adapter,
    session: Session,
    read_event: windows::Win32::Foundation::HANDLE,
    pub luid: NET_LUID_LH,
    pub guid: GUID,
    pub name: String,
    pub index: u32,
}

// Wintun's sessions are made for one reader thread and any number of senders.
unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Device {
    pub fn open(_plan: &Plan) -> io::Result<Self> {
        let wintun = wintun::get().map_err(io::Error::other)?;
        let name = format!("Fran VPN {}", NEXT.fetch_add(1, Ordering::SeqCst));
        let wide_name = HSTRING::from(&name);
        let kind = HSTRING::from("Fran VPN");
        let adapter = unsafe { (wintun.create_adapter)(PCWSTR(wide_name.as_ptr()), PCWSTR(kind.as_ptr()), std::ptr::null()) };
        if adapter.is_null() {
            return Err(io::Error::last_os_error());
        }
        leftovers::add(Leftover::Adapter { name: name.clone() });
        let close = |error: io::Error| {
            unsafe { (wintun.close_adapter)(adapter) };
            leftovers::remove(&Leftover::Adapter { name: name.clone() });
            error
        };
        let mut luid = NET_LUID_LH::default();
        unsafe { (wintun.get_adapter_luid)(adapter, &mut luid) };
        let mut index = 0u32;
        let mut guid = GUID::zeroed();
        unsafe {
            if ConvertInterfaceLuidToIndex(&luid, &mut index).is_err() || ConvertInterfaceLuidToGuid(&luid, &mut guid).is_err() {
                return Err(close(io::Error::other("The VPN adapter has no index")));
            }
        }
        let session = unsafe { (wintun.start_session)(adapter, RING) };
        if session.is_null() {
            return Err(close(io::Error::last_os_error()));
        }
        let read_event = unsafe { (wintun.get_read_wait_event)(session) };
        Ok(Self { wintun, adapter, session, read_event, luid, guid, name, index })
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let mut size = 0u32;
        let packet = unsafe { (self.wintun.receive_packet)(self.session, &mut size) };
        if packet.is_null() {
            if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                unsafe { WaitForSingleObject(self.read_event, READ_WAIT_MS) };
                return Ok(None);
            }
            return Err(io::Error::last_os_error());
        }
        let len = (size as usize).min(buf.len());
        unsafe {
            std::ptr::copy_nonoverlapping(packet, buf.as_mut_ptr(), len);
            (self.wintun.release_receive_packet)(self.session, packet);
        }
        Ok(Some(len))
    }

    pub fn write(&self, packet: &[u8]) -> bool {
        let Ok(len) = u32::try_from(packet.len()) else { return false };
        let slot = unsafe { (self.wintun.allocate_send_packet)(self.session, len) };
        if slot.is_null() {
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len());
            (self.wintun.send_packet)(self.session, slot);
        }
        true
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            (self.wintun.end_session)(self.session);
            (self.wintun.close_adapter)(self.adapter);
        }
        leftovers::remove(&Leftover::Adapter { name: self.name.clone() });
    }
}

fn sockaddr(addr: IpAddr) -> SOCKADDR_INET {
    let mut out = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(addr) => {
            out.Ipv4 = SOCKADDR_IN { sin_family: AF_INET, sin_addr: IN_ADDR::from(addr), ..Default::default() };
        }
        IpAddr::V6(addr) => {
            out.Ipv6 = SOCKADDR_IN6 { sin6_family: AF_INET6, sin6_addr: IN6_ADDR::from(addr), ..Default::default() };
        }
    }
    out
}

fn from_sockaddr(addr: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        if addr.si_family == AF_INET {
            Some(IpAddr::V4(Ipv4Addr::from(addr.Ipv4.sin_addr)))
        } else if addr.si_family == AF_INET6 {
            Some(IpAddr::V6(Ipv6Addr::from(addr.Ipv6.sin6_addr)))
        } else {
            None
        }
    }
}

fn unspecified(v6: bool) -> IpAddr {
    if v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) }
}

fn family(v6: bool) -> ADDRESS_FAMILY {
    if v6 { AF_INET6 } else { AF_INET }
}

fn set_interface(luid: NET_LUID_LH, v6: bool, mtu: u16) -> Result<(), String> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family(v6);
    row.InterfaceLuid = luid;
    win32(unsafe { GetIpInterfaceEntry(&mut row) }, "read the VPN adapter's settings")?;
    row.NlMtu = u32::from(mtu);
    row.UseAutomaticMetric = false.into();
    row.Metric = INTERFACE_METRIC;
    if !v6 {
        // Windows refuses the change otherwise.
        row.SitePrefixLength = 0;
    }
    win32(unsafe { SetIpInterfaceEntry(&mut row) }, "set the VPN adapter's MTU and metric")
}

fn add_address(luid: NET_LUID_LH, addr: IpAddr, prefix: u8) -> Result<(), String> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.Address = sockaddr(addr);
    row.OnLinkPrefixLength = prefix;
    row.DadState = IpDadStatePreferred;
    win32(unsafe { CreateUnicastIpAddressEntry(&row) }, &format!("give the VPN adapter its address {addr}"))
}

fn route_row(addr: IpAddr, prefix: u8, gateway: Option<IpAddr>, luid: Option<NET_LUID_LH>, index: u32, metric: Option<u32>) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    if let Some(luid) = luid {
        row.InterfaceLuid = luid;
    } else {
        row.InterfaceIndex = index;
    }
    row.DestinationPrefix.Prefix = sockaddr(addr);
    row.DestinationPrefix.PrefixLength = prefix;
    row.NextHop = sockaddr(gateway.unwrap_or_else(|| unspecified(addr.is_ipv6())));
    row.Metric = metric.unwrap_or(0);
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// False when the same route is already there, which belongs to someone else then.
fn add_route(row: &MIB_IPFORWARD_ROW2, what: &str) -> Result<bool, String> {
    let code = unsafe { CreateIpForwardEntry2(row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(false);
    }
    win32(code, what).map(|()| true)
}

fn delete_route(addr: IpAddr, prefix: u8, gateway: Option<IpAddr>, index: u32) {
    let row = route_row(addr, prefix, gateway, None, index, None);
    let _ = unsafe { DeleteIpForwardEntry2(&row) };
}

/// The interface and next hop the computer uses for `addr` right now.
fn best_route(addr: IpAddr) -> Result<(Option<IpAddr>, u32), String> {
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let target = sockaddr(addr);
    win32(unsafe { GetBestRoute2(None, 0, None, &target, 0, &mut route, &mut source) }, &format!("find the way to {addr} outside the VPN"))?;
    let gateway = from_sockaddr(&route.NextHop).filter(|hop| !hop.is_unspecified());
    Ok((gateway, route.InterfaceIndex))
}

fn wide_list(items: &[String], separator: &str) -> Vec<u16> {
    let mut out: Vec<u16> = items.join(separator).encode_utf16().collect();
    out.push(0);
    out
}

fn set_dns(device: &Device, servers: &[IpAddr], search: &[String], v6: bool) -> Result<(), String> {
    let servers: Vec<String> = servers.iter().filter(|server| server.is_ipv6() == v6).map(ToString::to_string).collect();
    if servers.is_empty() {
        return Ok(());
    }
    let mut names = wide_list(&servers, ",");
    let mut list = wide_list(search, ",");
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST) as u64,
        NameServer: PWSTR(names.as_mut_ptr()),
        SearchList: PWSTR(list.as_mut_ptr()),
        ..Default::default()
    };
    if v6 {
        settings.Flags |= DNS_SETTING_IPV6 as u64;
    }
    win32(unsafe { SetInterfaceDnsSettings(device.guid, &settings) }, "point the VPN adapter at the VPN's DNS servers")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_value(key: HKEY, name: &str, kind: windows::Win32::System::Registry::REG_VALUE_TYPE, data: &[u8]) -> Result<(), String> {
    win32(unsafe { RegSetValueExW(key, &HSTRING::from(name), None, kind, Some(data)) }, "write a DNS rule")
}

/// An NRPT rule: names in the VPN's domains go to its DNS servers, everything else stays with the computer's.
fn add_nrpt(name: &str, domains: &[String], servers: &[IpAddr]) -> Result<(), String> {
    let mut key = HKEY::default();
    let path = format!(r"{NRPT}\{name}");
    win32(
        unsafe { RegCreateKeyExW(HKEY_LOCAL_MACHINE, &HSTRING::from(path), None, PCWSTR::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut key, None) },
        "add a DNS rule for the VPN's domains",
    )?;
    let mut names: Vec<u16> = Vec::new();
    for domain in domains {
        names.extend(wide(&format!(".{}", domain.trim_start_matches('.'))));
    }
    names.push(0);
    let servers: Vec<String> = servers.iter().map(ToString::to_string).collect();
    let result = (|| {
        set_value(key, "Version", REG_DWORD, &2u32.to_le_bytes())?;
        set_value(key, "Name", REG_MULTI_SZ, bytes(&names))?;
        set_value(key, "GenericDNSServers", REG_SZ, bytes(&wide(&servers.join(";"))))?;
        set_value(key, "ConfigOptions", REG_DWORD, &8u32.to_le_bytes())?;
        set_value(key, "IPSECCARestriction", REG_SZ, bytes(&wide("")))
    })();
    unsafe {
        let _ = RegCloseKey(key);
    }
    result
}

fn bytes(units: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(units.as_ptr().cast(), units.len() * 2) }
}

fn remove_nrpt(name: &str) {
    let _ = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, &HSTRING::from(format!(r"{NRPT}\{name}"))) };
}

/// So new rules and servers apply to names the computer already looked up.
fn flush_dns() {
    unsafe {
        let Ok(module) = LoadLibraryW(&HSTRING::from("dnsapi.dll")) else { return };
        if let Some(flush) = GetProcAddress(module, PCSTR(b"DnsFlushResolverCache\0".as_ptr())) {
            let flush: unsafe extern "system" fn() -> i32 = std::mem::transmute(flush);
            flush();
        }
    }
}

/// What was changed outside the adapter. Routes and DNS servers on the adapter go away with it.
pub struct Applied {
    outside: Vec<Leftover>,
    pub dns_set: bool,
}

impl Applied {
    pub fn undo(self) {
        let had_rules = self.outside.iter().any(|item| matches!(item, Leftover::NrptRule { .. }));
        for item in &self.outside {
            match item {
                Leftover::Route { addr, prefix, gateway, index } => delete_route(*addr, *prefix, *gateway, *index),
                Leftover::NrptRule { name } => remove_nrpt(name),
                Leftover::Adapter { .. } | Leftover::DnsKey { .. } => {}
            }
            leftovers::remove(item);
        }
        if had_rules {
            flush_dns();
        }
    }
}

fn fill(device: &Device, plan: &Plan, applied: &mut Applied) -> Result<(), String> {
    if let Some((addr, prefix)) = plan.addr4 {
        set_interface(device.luid, false, plan.mtu)?;
        add_address(device.luid, IpAddr::V4(addr), prefix)?;
    }
    if let Some((addr, prefix)) = plan.addr6 {
        set_interface(device.luid, true, plan.mtu)?;
        add_address(device.luid, IpAddr::V6(addr), prefix)?;
    }
    // Before the routes into the adapter, so the lookup still finds the computer's own way out.
    for net in &plan.bypass {
        let (gateway, index) = best_route(net.addr)?;
        if index == device.index {
            continue;
        }
        let item = Leftover::Route { addr: net.addr, prefix: net.prefix, gateway, index };
        leftovers::add(item.clone());
        match add_route(&route_row(net.addr, net.prefix, gateway, None, index, net.metric), &format!("keep {}/{} outside the VPN", net.addr, net.prefix)) {
            Ok(true) => applied.outside.push(item),
            Ok(false) => leftovers::remove(&item),
            Err(error) => {
                leftovers::remove(&item);
                return Err(error);
            }
        }
    }
    for net in &plan.routes {
        add_route(&route_row(net.addr, net.prefix, None, Some(device.luid), device.index, net.metric), &format!("route {}/{} through the VPN", net.addr, net.prefix))?;
    }
    if !plan.dns.is_empty() {
        set_dns(device, &plan.dns, &plan.search, false)?;
        set_dns(device, &plan.dns, &plan.search, true)?;
        if !plan.split.is_empty() {
            let name = format!("{NRPT_PREFIX}{}", device.index);
            let item = Leftover::NrptRule { name: name.clone() };
            leftovers::add(item.clone());
            applied.outside.push(item);
            add_nrpt(&name, &plan.split, &plan.dns)?;
        }
        flush_dns();
        applied.dns_set = true;
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

/// What a crashed run left: bypass routes, DNS rules and adapters Windows kept.
pub fn clean_leftovers() {
    let items = leftovers::take_all();
    let mut flushed = false;
    for item in items {
        match item {
            Leftover::Route { addr, prefix, gateway, index } => delete_route(addr, prefix, gateway, index),
            Leftover::NrptRule { name } => {
                remove_nrpt(&name);
                flushed = true;
            }
            Leftover::Adapter { name } => {
                if let Ok(wintun) = wintun::get() {
                    let wide_name = HSTRING::from(&name);
                    let adapter = unsafe { (wintun.open_adapter)(PCWSTR(wide_name.as_ptr())) };
                    if !adapter.is_null() {
                        unsafe { (wintun.close_adapter)(adapter) };
                    }
                }
            }
            Leftover::DnsKey { .. } => {}
        }
    }
    if flushed {
        flush_dns();
    }
}
