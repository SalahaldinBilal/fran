//! `fran-vpn --install <everyone|group> [user] [--result <file>]`, `--set-access` with the same arguments, and
//! `--uninstall [--result <file>]`. All run with admin rights. The error goes to `--result`, since an elevated
//! process can't always hand Fran its output (UAC on Windows, osascript on macOS).

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use vpn_proto::frames::Access;

#[cfg(target_os = "linux")]
use super::linux::setup as platform;
#[cfg(target_os = "macos")]
use super::macos::setup as platform;
#[cfg(windows)]
use super::windows::setup as platform;

struct Args {
    plain: Vec<String>,
    result: Option<std::path::PathBuf>,
}

fn read(args: &[String]) -> Args {
    let mut plain = Vec::new();
    let mut result = None;
    let mut items = args.iter();
    while let Some(arg) = items.next() {
        if arg == "--result" {
            result = items.next().map(std::path::PathBuf::from);
        } else {
            plain.push(arg.clone());
        }
    }
    Args { plain, result }
}

fn finish(args: &Args, outcome: Result<(), String>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            if let Some(path) = &args.result {
                let _ = std::fs::write(path, &error);
            }
            1
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn access(args: &Args) -> Result<(Access, Option<&str>), String> {
    let access = args.plain.first().and_then(|arg| Access::from_arg(arg)).ok_or_else(|| "Say who may use the service: everyone or group".to_string())?;
    Ok((access, args.plain.get(1).map(String::as_str)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn unsupported() -> Result<(), String> {
    Err("Fran's VPN service doesn't run on this system".to_string())
}

pub fn install(args: &[String]) -> i32 {
    let args = read(args);
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    let outcome = access(&args).and_then(|(access, user)| platform::install(access, user));
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let outcome = unsupported();
    finish(&args, outcome)
}

pub fn uninstall(args: &[String]) -> i32 {
    let args = read(args);
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    let outcome = platform::uninstall();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let outcome = unsupported();
    finish(&args, outcome)
}

pub fn set_access(args: &[String]) -> i32 {
    let args = read(args);
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    let outcome = access(&args).and_then(|(access, user)| platform::set_access(access, user));
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let outcome = unsupported();
    finish(&args, outcome)
}
