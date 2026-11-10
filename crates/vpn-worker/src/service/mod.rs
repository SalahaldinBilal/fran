#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod adapter;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod leftovers;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
pub mod setup;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::{
    io::{Read, Write},
    sync::Arc,
};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use vpn_proto::frames::{Access, ServiceInfo};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::session::{self, Out, Tun};

/// One connection from Fran: the hello, then at most one tunnel on a real adapter. It ends when the connection does.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn handle(reader: impl Read, writer: Box<dyn Write + Send>, access: Access, caller: Result<(), String>) {
    let info = ServiceInfo { build: env!("CARGO_PKG_VERSION").to_string(), access, allowed: caller.is_ok(), refused: caller.err() };
    let out = Out::new(writer);
    let tun_out = out.clone();
    session::run(
        reader,
        out,
        Some(info),
        Box::new(move |options| match options {
            Some(options) => Ok(Arc::new(adapter::AdapterTun::new(tun_out, options)) as Arc<dyn Tun>),
            None => Err("The service only runs VPNs on for the whole computer".to_string()),
        }),
    );
}

pub fn serve(args: &[String]) -> i32 {
    #[cfg(target_os = "linux")]
    return linux::serve(args);
    #[cfg(target_os = "macos")]
    return macos::serve(args);
    #[cfg(windows)]
    return windows::serve(args);
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = args;
        eprintln!("Fran's VPN service doesn't run on this system");
        2
    }
}
