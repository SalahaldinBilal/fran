//! Setting up, updating and removing Fran's VPN service, and helping install OpenVPN for the profiles Core can't run.
//! Every change runs `fran-vpn` with admin rights, which asks once (UAC, pkexec or osascript).

use serde::Serialize;
use vpn_proto::frames::Access;

use super::service::{self, Unreachable};
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum ServiceStatus {
    /// `nixos`: it's turned on in the NixOS configuration, not from Fran.
    NotSetUp { nixos: bool },
    /// Set up, but nothing answers.
    NotRunning { reason: String },
    /// Speaks another protocol version, so Fran can't use it until it's updated.
    NeedsUpdate { reason: String },
    #[serde(rename_all = "camelCase")]
    Running { build: String, access: Access, allowed: bool, refused: Option<String>, outdated: bool },
}

impl ServiceStatus {
    pub fn usable(&self) -> bool {
        matches!(self, Self::Running { allowed: true, .. })
    }
}

#[cfg(target_os = "linux")]
fn installed() -> bool {
    std::path::Path::new("/usr/local/libexec/fran/fran-vpn").is_file() || std::path::Path::new("/etc/systemd/system/fran-vpn.service").is_file()
}

#[cfg(windows)]
fn install_dir() -> std::path::PathBuf {
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")).unwrap_or_else(|| r"C:\Program Files".into());
    std::path::PathBuf::from(base).join("Fran").join("vpn")
}

#[cfg(windows)]
fn installed() -> bool {
    install_dir().join("fran-vpn.exe").is_file()
}

#[cfg(target_os = "macos")]
fn installed() -> bool {
    std::path::Path::new("/Library/Application Support/Fran/vpn/fran-vpn").is_file()
        || std::path::Path::new(&format!("/Library/LaunchDaemons/{}.plist", vpn_proto::SERVICE_LABEL)).is_file()
}

fn nixos() -> bool {
    cfg!(target_os = "linux") && std::path::Path::new("/etc/NIXOS").exists()
}

pub async fn status() -> ServiceStatus {
    match service::open().await {
        Ok((_, _, info)) | Err(Unreachable::Refused(info)) => running(info.build, info.access, info.allowed, info.refused),
        Err(Unreachable::OtherVersion(reason)) => ServiceStatus::NeedsUpdate { reason },
        Err(Unreachable::NotRunning(reason)) if installed() => ServiceStatus::NotRunning { reason },
        Err(Unreachable::NotRunning(_)) => ServiceStatus::NotSetUp { nixos: nixos() },
    }
}

fn running(build: String, access: Access, allowed: bool, refused: Option<String>) -> ServiceStatus {
    let outdated = build != env!("CARGO_PKG_VERSION");
    ServiceStatus::Running { build, access, allowed, refused, outdated }
}

/// The service that answers, or why none can be used. False when it isn't set up.
pub async fn usable_service() -> AppResult<bool> {
    match status().await {
        status if status.usable() => Ok(true),
        ServiceStatus::NotSetUp { .. } => Ok(false),
        ServiceStatus::NotRunning { reason } => Err(AppError::general(format!("Fran's VPN service is set up but isn't running: {reason}"))),
        ServiceStatus::NeedsUpdate { .. } => Err(AppError::general("Fran's VPN service needs updating. Click Update in Settings > VPN.")),
        ServiceStatus::Running { refused, .. } => Err(AppError::general(refused.unwrap_or_else(|| "Fran's VPN service doesn't take your account".to_string()))),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Change {
    Install(Access),
    SetAccess(Access),
    Remove,
}

impl Change {
    fn args(self) -> Vec<String> {
        match self {
            Self::Install(access) => vec![vpn_proto::INSTALL_ARG.to_string(), access.as_arg().to_string()],
            Self::SetAccess(access) => vec![vpn_proto::ACCESS_ARG.to_string(), access.as_arg().to_string()],
            Self::Remove => vec![vpn_proto::UNINSTALL_ARG.to_string()],
        }
    }
}

/// Runs `fran-vpn` with admin rights for one change. The account to add to the group goes along, since the admin
/// who confirms can be someone else.
pub async fn change(change: Change) -> AppResult<()> {
    if nixos() {
        return Err(AppError::general("On NixOS, Fran's VPN service is set up in your configuration with programs.fran.vpnService"));
    }
    let program = crate::vpn::sidecar().map_err(|error| AppError::general(error.to_string()))?;
    let mut args = change.args();
    if !matches!(change, Change::Remove) {
        args.push(current_user()?);
    }
    elevated(&program, &args).await
}

#[cfg(windows)]
fn current_user() -> AppResult<String> {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let failed = || AppError::general("Fran couldn't tell which account it runs as");
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(|_| failed())?;
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let read = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), needed, &mut needed);
        let _ = CloseHandle(token);
        read.map_err(|_| failed())?;
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let mut text = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).map_err(|_| failed())?;
        let value = text.to_string().map_err(|_| failed());
        LocalFree(Some(HLOCAL(text.0.cast())));
        value
    }
}

#[cfg(unix)]
fn current_user() -> AppResult<String> {
    use std::os::unix::fs::MetadataExt;
    // `/proc/self` and the process' own temp files belong to the real user.
    let path = if cfg!(target_os = "linux") { "/proc/self".to_string() } else { std::env::temp_dir().to_string_lossy().to_string() };
    std::fs::metadata(path).map(|meta| meta.uid().to_string()).map_err(|_| AppError::general("Fran couldn't tell which account it runs as"))
}

#[cfg(windows)]
async fn elevated(program: &std::path::Path, args: &[String]) -> AppResult<()> {
    use windows::{
        Win32::{
            Foundation::{CloseHandle, ERROR_CANCELLED},
            System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject},
            UI::{
                Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
                WindowsAndMessaging::SW_HIDE,
            },
        },
        core::{HSTRING, PCWSTR},
    };

    let result = std::env::temp_dir().join(format!("fran-vpn-setup-{}.txt", uuid::Uuid::new_v4().simple()));
    let mut all = args.to_vec();
    all.push("--result".to_string());
    all.push(result.to_string_lossy().to_string());
    let line = all.iter().map(|arg| super::launch::windows_service::quote_arg(arg)).collect::<Vec<_>>().join(" ");
    let program = program.to_path_buf();

    let code = tokio::task::spawn_blocking(move || -> Result<u32, AppError> {
        let verb = HSTRING::from("runas");
        let file = HSTRING::from(program.as_os_str());
        let params = HSTRING::from(line);
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(params.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        if let Err(error) = unsafe { ShellExecuteExW(&mut info) } {
            if error.code() == ERROR_CANCELLED.to_hresult() {
                return Err(AppError::general("The admin prompt was cancelled"));
            }
            return Err(AppError::general(format!("Couldn't ask for admin rights: {error}")));
        }
        let mut code = 1u32;
        unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            let _ = GetExitCodeProcess(info.hProcess, &mut code);
            let _ = CloseHandle(info.hProcess);
        }
        Ok(code)
    })
    .await
    .map_err(|error| AppError::general(error.to_string()))??;

    let message = std::fs::read_to_string(&result).ok().map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
    let _ = std::fs::remove_file(&result);
    match (code, message) {
        (0, _) => Ok(()),
        (_, Some(message)) => Err(AppError::general(message)),
        (code, None) => Err(AppError::general(format!("Fran's VPN service setup failed (exit code {code})"))),
    }
}

/// pkexec asks through the desktop's polkit agent. It runs a copy in a private folder, since root can't always read
/// the original (an AppImage is mounted for this user only). The copy then installs itself where only root can write.
#[cfg(target_os = "linux")]
async fn elevated(program: &std::path::Path, args: &[String]) -> AppResult<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let running_as_root = std::fs::metadata("/proc/self").is_ok_and(|meta| std::os::unix::fs::MetadataExt::uid(&meta) == 0);
    let dir = std::env::temp_dir().join(format!("fran-vpn-setup-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let copy = dir.join("fran-vpn");
    let staged = std::fs::copy(program, &copy).and_then(|_| std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)));
    if let Err(error) = staged {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(AppError::general(format!("Couldn't stage Fran's VPN service: {error}")));
    }
    let mut command = if running_as_root {
        tokio::process::Command::new(&copy)
    } else {
        let mut command = tokio::process::Command::new("pkexec");
        command.arg(&copy);
        command
    };
    let output = command.args(args).stdin(std::process::Stdio::null()).output().await;
    let _ = std::fs::remove_dir_all(&dir);
    let output = output.map_err(|error| AppError::general(format!("Fran needs pkexec (polkit) to set up its VPN service: {error}")))?;
    match output.status.code() {
        Some(0) => Ok(()),
        Some(126) => Err(AppError::general("The admin password prompt was cancelled")),
        Some(127) => Err(AppError::general("Your account isn't allowed to set up Fran's VPN service")),
        _ => {
            let text = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(AppError::general(if text.is_empty() { "Fran's VPN service setup failed".to_string() } else { text }))
        }
    }
}

/// osascript asks for an administrator's password once. Its error text is only "execution error", so the service
/// writes what went wrong to a file Fran reads afterwards.
#[cfg(target_os = "macos")]
async fn elevated(program: &std::path::Path, args: &[String]) -> AppResult<()> {
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
    fn applescript_string(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }

    let result = std::env::temp_dir().join(format!("fran-vpn-setup-{}.txt", uuid::Uuid::new_v4().simple()));
    let mut parts = vec![shell_quote(&program.to_string_lossy())];
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    parts.push("--result".to_string());
    parts.push(shell_quote(&result.to_string_lossy()));
    let script = format!("do shell script {} with administrator privileges", applescript_string(&parts.join(" ")));
    let output = tokio::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .output()
        .await
        .map_err(|error| AppError::general(format!("Couldn't ask for the admin password: {error}")))?;
    let message = std::fs::read_to_string(&result).ok().map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
    let _ = std::fs::remove_file(&result);
    if output.status.success() {
        return Ok(());
    }
    if String::from_utf8_lossy(&output.stderr).contains("-128") {
        return Err(AppError::general("The admin password prompt was cancelled"));
    }
    Err(AppError::general(message.unwrap_or_else(|| "Fran's VPN service setup failed".to_string())))
}

/// Any process could create the pipe and wait for logins. Asks the service manager, since Fran can't open a SYSTEM process.
#[cfg(windows)]
pub fn check_pipe_server(pipe: &tokio::net::windows::named_pipe::NamedPipeClient) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeServerProcessId};
    let mut pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }
        .map_err(|error| std::io::Error::other(format!("Couldn't tell which process holds Fran's VPN service pipe: {error}")))?;
    let service = registered_service()?;
    let expected = format!("\"{}\" {}", install_dir().join("fran-vpn.exe").display(), vpn_proto::SERVICE_ARG);
    if !service.command.eq_ignore_ascii_case(&expected) {
        return Err(std::io::Error::other(format!("Fran's VPN service is registered to run {}, not {expected}", service.command)));
    }
    if service.pid != pid {
        return Err(std::io::Error::other("Something other than Fran's VPN service holds its pipe"));
    }
    Ok(())
}

#[cfg(windows)]
struct RegisteredService {
    pid: u32,
    command: String,
}

#[cfg(windows)]
fn registered_service() -> std::io::Result<RegisteredService> {
    use windows::{
        Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
            SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
        },
        core::{HSTRING, PCWSTR},
    };

    struct Handle(SC_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }

    let failed = |what: &str, error: windows::core::Error| std::io::Error::other(format!("Couldn't {what} Fran's VPN service: {error}"));
    let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.map(Handle).map_err(|error| failed("look up", error))?;
    let service = unsafe { OpenServiceW(manager.0, &HSTRING::from(vpn_proto::SERVICE_NAME), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG) }
        .map(Handle)
        .map_err(|error| failed("look up", error))?;

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    let bytes = unsafe { std::slice::from_raw_parts_mut((&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(), size_of::<SERVICE_STATUS_PROCESS>()) };
    unsafe { QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed) }.map_err(|error| failed("read the status of", error))?;

    let _ = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let config = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    unsafe { QueryServiceConfigW(service.0, Some(config), (buf.len() * 8) as u32, &mut needed) }.map_err(|error| failed("read the setup of", error))?;
    let command = unsafe { (*config).lpBinaryPathName.to_string() }.map_err(|_| std::io::Error::other("Fran's VPN service has an unreadable program path"))?;

    Ok(RegisteredService { pid: status.dwProcessId, command })
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum InstallHelp {
    /// Fran can run the installer (winget on Windows, Homebrew on macOS), which asks for admin rights itself.
    Run { with: String },
    /// A command to copy, since running a package manager for the user goes wrong too easily.
    Command { command: String },
    None,
}

#[cfg(target_os = "macos")]
fn brew() -> Option<&'static str> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].into_iter().find(|path| std::path::Path::new(path).is_file())
}

#[cfg(target_os = "linux")]
fn distro_command() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    let field = |name: &str| {
        text.lines().find_map(|line| line.strip_prefix(&format!("{name}="))).map(|value| value.trim_matches('"').to_lowercase()).unwrap_or_default()
    };
    let names = format!("{} {}", field("ID"), field("ID_LIKE"));
    let has = |name: &str| names.split_whitespace().any(|word| word == name);
    Some(
        if has("nixos") {
            "Add pkgs.openvpn to environment.systemPackages"
        } else if has("debian") || has("ubuntu") {
            "sudo apt install openvpn"
        } else if has("fedora") || has("rhel") || has("centos") {
            "sudo dnf install openvpn"
        } else if has("arch") {
            "sudo pacman -S openvpn"
        } else if has("suse") || has("opensuse") {
            "sudo zypper install openvpn"
        } else {
            return None;
        }
        .to_string(),
    )
}

pub fn install_help() -> InstallHelp {
    #[cfg(windows)]
    return InstallHelp::Run { with: "winget".to_string() };
    #[cfg(target_os = "macos")]
    return match brew() {
        Some(_) => InstallHelp::Run { with: "Homebrew".to_string() },
        None => InstallHelp::None,
    };
    #[cfg(target_os = "linux")]
    return distro_command().map_or(InstallHelp::None, |command| InstallHelp::Command { command });
}

/// winget and Homebrew show their own prompts. Fran never ships the OpenVPN installer itself.
pub async fn install_openvpn() -> AppResult<()> {
    #[cfg(windows)]
    let mut command = {
        let mut command = super::quiet_command("winget");
        command.args(["install", "--id", "OpenVPNTechnologies.OpenVPN", "--exact", "--accept-source-agreements", "--accept-package-agreements"]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let brew = brew().ok_or_else(|| AppError::general("Homebrew isn't installed"))?;
        let mut command = super::quiet_command(brew);
        command.args(["install", "openvpn"]);
        command
    };
    #[cfg(target_os = "linux")]
    return Err(AppError::general("Install OpenVPN with your distribution's package manager"));
    #[cfg(not(target_os = "linux"))]
    {
        command.stderr(std::process::Stdio::piped());
        let output = command.output().await.map_err(|error| AppError::general(format!("Couldn't start the installer: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&output.stdout).lines().chain(String::from_utf8_lossy(&output.stderr).lines()).map(str::trim).filter(|line| !line.is_empty()).last().map(str::to_string);
        Err(AppError::general(text.unwrap_or_else(|| "Installing OpenVPN failed".to_string())))
    }
}
