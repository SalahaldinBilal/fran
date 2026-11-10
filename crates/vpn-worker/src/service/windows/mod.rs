mod caller;
pub mod net;
mod pipe;
pub mod setup;
mod wintun;

use std::{
    ffi::c_void,
    io::BufReader,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use vpn_proto::frames::Access;
use windows::{
    Win32::{
        Foundation::{ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, NO_ERROR},
        System::{
            Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW},
            Services::{
                RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
                SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
                SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
            },
        },
    },
    core::{HSTRING, PWSTR},
};

use pipe::{Pipe, PipeReader, PipeWriter};

pub const SETTINGS_KEY: &str = r"SOFTWARE\Fran\Vpn";
const STOP_GRACE: Duration = Duration::from_secs(5);

static STOPPING: AtomicBool = AtomicBool::new(false);
static OPEN: Mutex<Vec<Arc<Pipe>>> = Mutex::new(Vec::new());
static SESSIONS: AtomicUsize = AtomicUsize::new(0);
static STATUS: AtomicUsize = AtomicUsize::new(0);

/// The leftovers file lives with the installed service, in a folder only administrators can write.
pub fn state_dir() -> PathBuf {
    install_dir()
}

pub fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")).unwrap_or_else(|| r"C:\Program Files".into());
    PathBuf::from(base).join("Fran").join("vpn")
}

fn read_access() -> Result<Access, String> {
    let mut buf = vec![0u16; 64];
    let mut len = (buf.len() * 2) as u32;
    let code = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, &HSTRING::from(SETTINGS_KEY), &HSTRING::from("Access"), RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr().cast()), Some(&mut len))
    };
    if code.is_err() {
        return Err("Fran's VPN service has no access setting. Set it up again in Settings, VPN.".to_string());
    }
    let text = String::from_utf16_lossy(&buf[..(len as usize / 2)]);
    Access::from_arg(text.trim_end_matches('\0')).ok_or_else(|| "Fran's VPN service has an unknown access setting. Set it up again in Settings, VPN.".to_string())
}

fn report(state: SERVICE_STATUS_CURRENT_STATE) {
    let raw = STATUS.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    let handle = SERVICE_STATUS_HANDLE(raw as *mut c_void);
    let accepted = if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: NO_ERROR.0,
        dwWaitHint: if state == SERVICE_RUNNING { 0 } else { STOP_GRACE.as_millis() as u32 + 1000 },
        ..Default::default()
    };
    let _ = unsafe { SetServiceStatus(handle, &status) };
}

/// Ends every session, which takes its adapter, routes and DNS rules down with it.
fn stop_sessions() {
    STOPPING.store(true, Ordering::SeqCst);
    if let Ok(open) = OPEN.lock() {
        for pipe in open.iter() {
            pipe.close();
        }
    }
    let started = Instant::now();
    while SESSIONS.load(Ordering::SeqCst) > 0 && started.elapsed() < STOP_GRACE {
        thread::sleep(Duration::from_millis(50));
    }
}

unsafe extern "system" fn control(code: u32, _kind: u32, _data: *mut c_void, _context: *mut c_void) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        report(SERVICE_STOP_PENDING);
        thread::spawn(|| {
            stop_sessions();
            report(SERVICE_STOPPED);
            std::process::exit(0);
        });
    }
    NO_ERROR.0
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let handle = unsafe { RegisterServiceCtrlHandlerExW(&HSTRING::from(vpn_proto::SERVICE_NAME), Some(control), None) };
    let Ok(handle) = handle else { return };
    STATUS.store(handle.0 as usize, Ordering::SeqCst);
    report(SERVICE_START_PENDING);
    net::clean_leftovers();
    report(SERVICE_RUNNING);
    listen();
    report(SERVICE_STOPPED);
}

fn session(pipe: Arc<Pipe>) {
    let (access, caller) = match read_access() {
        Ok(access) => (access, caller::check(&pipe, access)),
        Err(error) => (Access::Group, Err(error)),
    };
    super::handle(BufReader::new(PipeReader(pipe.clone())), Box::new(PipeWriter(pipe.clone())), access, caller);
    if let Ok(mut open) = OPEN.lock() {
        open.retain(|other| !Arc::ptr_eq(other, &pipe));
    }
}

fn listen() {
    let mut first = true;
    while !STOPPING.load(Ordering::SeqCst) {
        let pipe = match Pipe::create(first) {
            Ok(pipe) => Arc::new(pipe),
            Err(error) => {
                // Someone else holds the name: never serve under it.
                if first {
                    eprintln!("Couldn't open {}: {error}", vpn_proto::SERVICE_PIPE);
                    return;
                }
                thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        first = false;
        if pipe.accept().is_err() || STOPPING.load(Ordering::SeqCst) {
            continue;
        }
        if let Ok(mut open) = OPEN.lock() {
            open.push(pipe.clone());
        }
        SESSIONS.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            session(pipe);
            SESSIONS.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Under the service control manager. Started by hand (for a look while testing), it serves until killed.
pub fn serve(_args: &[String]) -> i32 {
    let name = HSTRING::from(vpn_proto::SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: PWSTR(name.as_ptr() as *mut u16), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        Ok(()) => 0,
        Err(error) if error.code() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.to_hresult() => {
            net::clean_leftovers();
            listen();
            0
        }
        Err(error) => {
            eprintln!("The service didn't start: {error}");
            1
        }
    }
}
