// No console window when Fran starts it, or when Windows runs it as a service.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod service;
mod session;
mod wireguard;

use std::{
    io::{self, BufReader, BufWriter},
    sync::Arc,
};

use session::{FrameTun, Out, Tun};

fn worker() -> i32 {
    let out = Out::new(Box::new(BufWriter::new(io::stdout())));
    let tun_out = out.clone();
    session::run(
        BufReader::new(io::stdin()),
        out,
        None,
        Box::new(move |adapter| match adapter {
            None => Ok(Arc::new(FrameTun { out: tun_out }) as Arc<dyn Tun>),
            Some(_) => Err("An own tunnel has no adapter to set up".to_string()),
        }),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some(vpn_proto::WORKER_ARG) => worker(),
        Some(vpn_proto::SERVICE_ARG) => service::serve(&args[1..]),
        Some(vpn_proto::INSTALL_ARG) => service::setup::install(&args[1..]),
        Some(vpn_proto::UNINSTALL_ARG) => service::setup::uninstall(&args[1..]),
        Some(vpn_proto::ACCESS_ARG) => service::setup::set_access(&args[1..]),
        _ => 2,
    };
    std::process::exit(code);
}
