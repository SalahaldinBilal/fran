use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile},
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT},
            Threading::CreateEventW,
        },
    },
    core::{HSTRING, PCWSTR},
};

const BUFFER: u32 = 64 * 1024;
/// SYSTEM and Administrators get everything, signed-in accounts may connect. Who gets a tunnel is checked per connection.
const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

pub struct Pipe {
    pub handle: HANDLE,
    closed: AtomicBool,
}

// The handle is only used through overlapped calls, each with its own event, which Windows allows from any thread.
unsafe impl Send for Pipe {}
unsafe impl Sync for Pipe {}

fn is(error: &windows::core::Error, code: windows::Win32::Foundation::WIN32_ERROR) -> bool {
    error.code() == code.to_hresult()
}

impl Pipe {
    /// A new instance of the service's pipe. The first one also makes sure nobody else got there first.
    pub fn create(first: bool) -> io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(SDDL), SDDL_REVISION_1, &mut descriptor, None) }.map_err(io::Error::other)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let handle = unsafe {
            CreateNamedPipeW(
                &HSTRING::from(vpn_proto::SERVICE_PIPE),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER,
                BUFFER,
                0,
                Some(&attributes),
            )
        };
        unsafe {
            LocalFree(Some(HLOCAL(descriptor.0)));
        }
        if handle.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, closed: AtomicBool::new(false) })
    }

    /// Waits for a client, also one that connected between create and this call.
    pub fn accept(&self) -> io::Result<()> {
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(io::Error::other)?;
        let mut overlapped = OVERLAPPED { hEvent: event, ..Default::default() };
        let started = unsafe { ConnectNamedPipe(self.handle, Some(&mut overlapped)) };
        let result = match started {
            Ok(()) => Ok(()),
            Err(error) if is(&error, ERROR_PIPE_CONNECTED) => Ok(()),
            Err(error) if is(&error, ERROR_IO_PENDING) => {
                let mut transferred = 0u32;
                unsafe { GetOverlappedResult(self.handle, &overlapped, &mut transferred, true) }.map_err(io::Error::other)
            }
            Err(error) => Err(io::Error::other(error)),
        };
        unsafe {
            let _ = CloseHandle(event);
        }
        result
    }

    fn transfer(&self, read: Option<&mut [u8]>, write: Option<&[u8]>) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(io::Error::other)?;
        let mut overlapped = OVERLAPPED { hEvent: event, ..Default::default() };
        let started = unsafe {
            match (read, write) {
                (Some(buf), _) => ReadFile(self.handle, Some(buf), None, Some(&mut overlapped)),
                (None, Some(buf)) => WriteFile(self.handle, Some(buf), None, Some(&mut overlapped)),
                (None, None) => Ok(()),
            }
        };
        let finished = match started {
            Ok(()) => Ok(()),
            Err(error) if is(&error, ERROR_IO_PENDING) => Ok(()),
            Err(error) => Err(error),
        };
        let mut transferred = 0u32;
        let result = finished.and_then(|()| unsafe { GetOverlappedResult(self.handle, &overlapped, &mut transferred, true) });
        unsafe {
            let _ = CloseHandle(event);
        }
        match result {
            Ok(()) => Ok(transferred as usize),
            Err(error) if is(&error, ERROR_BROKEN_PIPE) || is(&error, ERROR_NO_DATA) || is(&error, ERROR_OPERATION_ABORTED) => Ok(0),
            Err(error) => Err(io::Error::other(error)),
        }
    }

    /// Ends whatever is waiting on the pipe, so its session sees the connection close.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        unsafe {
            let _ = CancelIoEx(self.handle, None);
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

pub struct PipeReader(pub Arc<Pipe>);
pub struct PipeWriter(pub Arc<Pipe>);

impl io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.transfer(Some(buf), None)
    }
}

impl io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.transfer(None, Some(buf))? {
            0 if !buf.is_empty() => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            written => Ok(written),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
