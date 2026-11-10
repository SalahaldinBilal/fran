//! What the service changed outside its adapter, written down as it goes so a crash doesn't leave it behind.
//! Routes through the adapter go away with it. Bypass routes and DNS rules don't.

use std::{net::IpAddr, path::PathBuf, sync::Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Leftover {
    /// Through the computer's own network, so the VPN's server and excluded networks stay outside the VPN.
    Route { addr: IpAddr, prefix: u8, gateway: Option<IpAddr>, index: u32 },
    /// A Windows NRPT rule sending a domain's names to the VPN's DNS.
    NrptRule { name: String },
    /// A Wintun adapter, which Windows can keep after a crash.
    Adapter { name: String },
    /// A macOS dynamic store key (`scutil`) holding the VPN's DNS.
    DnsKey { key: String },
}

static LOCK: Mutex<()> = Mutex::new(());

fn path() -> PathBuf {
    #[cfg(target_os = "linux")]
    return super::linux::state_dir().join("leftovers.json");
    #[cfg(target_os = "macos")]
    return super::macos::state_dir().join("leftovers.json");
    #[cfg(windows)]
    return super::windows::state_dir().join("leftovers.json");
}

fn read() -> Vec<Leftover> {
    std::fs::read(path()).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
}

fn write(items: &[Leftover]) {
    if let Ok(bytes) = serde_json::to_vec(items) {
        let _ = std::fs::write(path(), bytes);
    }
}

pub fn add(item: Leftover) {
    let _held = LOCK.lock();
    let mut items = read();
    items.push(item);
    write(&items);
}

pub fn remove(item: &Leftover) {
    let _held = LOCK.lock();
    let mut items = read();
    if let Some(index) = items.iter().position(|existing| existing == item) {
        items.remove(index);
        write(&items);
    }
}

/// Everything a previous run left, for the service to undo on start.
pub fn take_all() -> Vec<Leftover> {
    let _held = LOCK.lock();
    let items = read();
    write(&[]);
    items
}
