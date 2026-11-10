const WORKER_MANIFEST: &str = "../crates/vpn-worker/Cargo.toml";

/// The fran-vpn version this build expects, so an installed service from another one is offered Update.
fn worker_version() -> String {
    let manifest = std::fs::read_to_string(WORKER_MANIFEST).expect("crates/vpn-worker/Cargo.toml is missing");
    manifest
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("crates/vpn-worker/Cargo.toml has no version line")
        .to_string()
}

fn main() {
    println!("cargo:rerun-if-changed={WORKER_MANIFEST}");
    println!("cargo:rustc-env=FRAN_VPN_VERSION={}", worker_version());
    tauri_build::build()
}
