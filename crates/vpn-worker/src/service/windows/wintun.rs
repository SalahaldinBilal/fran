//! The few Wintun calls the service needs, from wintun.h. The DLL is loaded by its full path next to the service,
//! never through the search path.

use std::{ffi::c_void, sync::OnceLock};

use windows::{
    Win32::{
        Foundation::{HANDLE, HMODULE},
        NetworkManagement::Ndis::NET_LUID_LH,
        System::LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
    },
    core::{GUID, HSTRING, PCSTR, PCWSTR},
};

pub type Adapter = *mut c_void;
pub type Session = *mut c_void;

type CreateAdapter = unsafe extern "system" fn(PCWSTR, PCWSTR, *const GUID) -> Adapter;
type OpenAdapter = unsafe extern "system" fn(PCWSTR) -> Adapter;
type CloseAdapter = unsafe extern "system" fn(Adapter);
type GetAdapterLuid = unsafe extern "system" fn(Adapter, *mut NET_LUID_LH);
type StartSession = unsafe extern "system" fn(Adapter, u32) -> Session;
type EndSession = unsafe extern "system" fn(Session);
type GetReadWaitEvent = unsafe extern "system" fn(Session) -> HANDLE;
type ReceivePacket = unsafe extern "system" fn(Session, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(Session, *const u8);
type AllocateSendPacket = unsafe extern "system" fn(Session, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(Session, *const u8);

pub struct Wintun {
    pub create_adapter: CreateAdapter,
    pub open_adapter: OpenAdapter,
    pub close_adapter: CloseAdapter,
    pub get_adapter_luid: GetAdapterLuid,
    pub start_session: StartSession,
    pub end_session: EndSession,
    pub get_read_wait_event: GetReadWaitEvent,
    pub receive_packet: ReceivePacket,
    pub release_receive_packet: ReleaseReceivePacket,
    pub allocate_send_packet: AllocateSendPacket,
    pub send_packet: SendPacket,
}

// Plain function pointers into a DLL that stays loaded for the life of the process.
unsafe impl Send for Wintun {}
unsafe impl Sync for Wintun {}

static WINTUN: OnceLock<Result<Wintun, String>> = OnceLock::new();

fn symbol<T>(module: HMODULE, name: &'static [u8]) -> Result<T, String> {
    let address = unsafe { GetProcAddress(module, PCSTR(name.as_ptr())) };
    let address = address.ok_or_else(|| format!("wintun.dll has no {}", String::from_utf8_lossy(&name[..name.len() - 1])))?;
    Ok(unsafe { std::mem::transmute_copy(&address) })
}

fn load() -> Result<Wintun, String> {
    let dir = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.to_path_buf())).ok_or("The service doesn't know its folder")?;
    let path = dir.join("wintun.dll");
    let module = unsafe { LoadLibraryExW(&HSTRING::from(path.as_os_str()), None, LOAD_WITH_ALTERED_SEARCH_PATH) }
        .map_err(|error| format!("Couldn't load {}: {error}", path.display()))?;
    Ok(Wintun {
        create_adapter: symbol(module, b"WintunCreateAdapter\0")?,
        open_adapter: symbol(module, b"WintunOpenAdapter\0")?,
        close_adapter: symbol(module, b"WintunCloseAdapter\0")?,
        get_adapter_luid: symbol(module, b"WintunGetAdapterLUID\0")?,
        start_session: symbol(module, b"WintunStartSession\0")?,
        end_session: symbol(module, b"WintunEndSession\0")?,
        get_read_wait_event: symbol(module, b"WintunGetReadWaitEvent\0")?,
        receive_packet: symbol(module, b"WintunReceivePacket\0")?,
        release_receive_packet: symbol(module, b"WintunReleaseReceivePacket\0")?,
        allocate_send_packet: symbol(module, b"WintunAllocateSendPacket\0")?,
        send_packet: symbol(module, b"WintunSendPacket\0")?,
    })
}

pub fn get() -> Result<&'static Wintun, String> {
    WINTUN.get_or_init(load).as_ref().map_err(Clone::clone)
}
