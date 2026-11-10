// Windows Hello when it's set up, else the Windows credential dialog checked with LogonUserW.

use std::{ffi::c_void, sync::OnceLock};

use windows_future::IAsyncOperation;
use windows::{
    Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability},
    Win32::{
        Foundation::{CloseHandle, ERROR_ACCOUNT_RESTRICTION, ERROR_CANCELLED, ERROR_LOGON_FAILURE, HANDLE, HWND},
        Graphics::Gdi::HBITMAP,
        Security::{
            Credentials::{
                CRED_PACK_PROTECTED_CREDENTIALS, CREDUI_INFOW, CREDUIWIN_ENUMERATE_CURRENT_USER, CredUIPromptForWindowsCredentialsW,
                CredUnPackAuthenticationBufferW,
            },
            EqualSid, GetTokenInformation, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::{
            Com::CoTaskMemFree,
            Threading::{GetCurrentProcess, OpenProcessToken},
            WinRT::{IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize},
        },
    },
    core::{HRESULT, HSTRING, PCWSTR, PWSTR, factory},
};
use zeroize::Zeroize;

use super::{Outcome, cancelled, failed};
use crate::error::{AppError, AppResult};

const MAX_TRIES: usize = 3;

fn winrt_error(error: windows::core::Error) -> AppError {
    AppError::general(format!("Windows couldn't check who you are: {}", error.message()))
}

pub fn confirm(hwnd: isize, reason: &str) -> AppResult<Outcome> {
    // WinRT calls need the thread set up first. A second call on the same thread only reports that it already is.
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    let window = HWND(hwnd as *mut c_void);

    let availability = UserConsentVerifier::CheckAvailabilityAsync().and_then(|operation| operation.join());
    if availability.ok() == Some(UserConsentVerifierAvailability::Available) {
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>().map_err(winrt_error)?;
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(window, &HSTRING::from(reason)) }.map_err(winrt_error)?;
        return match operation.join().map_err(winrt_error)? {
            UserConsentVerificationResult::Verified => Ok(Outcome::Confirmed),
            UserConsentVerificationResult::Canceled => Err(cancelled()),
            _ => Err(failed()),
        };
    }

    if blank_password() {
        return Ok(Outcome::NoProtection);
    }
    credential_dialog(window, reason)
}

pub fn unprotected() -> bool {
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    let hello = UserConsentVerifier::CheckAvailabilityAsync().and_then(|operation| operation.join());
    hello.ok() != Some(UserConsentVerifierAvailability::Available) && blank_password()
}

// Checked once per run, since a wrong guess counts toward Windows' lockout limit.
fn blank_password() -> bool {
    static BLANK: OnceLock<bool> = OnceLock::new();
    *BLANK.get_or_init(|| {
        let Ok(user) = std::env::var("USERNAME") else {
            return false;
        };
        let mut token = HANDLE::default();
        let result = unsafe {
            LogonUserW(&HSTRING::from(user), &HSTRING::from("."), &HSTRING::new(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &mut token)
        };
        match result {
            Ok(()) => {
                let _ = unsafe { CloseHandle(token) };
                true
            }
            // Windows only allows blank passwords at the console, and says so with this error.
            Err(error) => error.code() == HRESULT::from_win32(ERROR_ACCOUNT_RESTRICTION.0),
        }
    })
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn until_nul(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

fn token_user(token: HANDLE) -> Option<Vec<u8>> {
    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    let mut buffer = vec![0u8; needed as usize];
    unsafe { GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr() as *mut c_void), needed, &mut needed) }.ok()?;
    Some(buffer)
}

/// The account that logged in has to be the one Fran runs as.
fn same_user(token: HANDLE) -> bool {
    let mut own = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own) }.is_err() {
        return false;
    }
    let matches = match (token_user(token), token_user(own)) {
        (Some(theirs), Some(mine)) => unsafe {
            let theirs = &*(theirs.as_ptr() as *const TOKEN_USER);
            let mine = &*(mine.as_ptr() as *const TOKEN_USER);
            EqualSid(theirs.User.Sid, mine.User.Sid).is_ok()
        },
        _ => false,
    };
    let _ = unsafe { CloseHandle(own) };
    matches
}

fn credential_dialog(window: HWND, reason: &str) -> AppResult<Outcome> {
    let caption = wide("Fran");
    let message = wide(reason);
    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: window,
        pszMessageText: PCWSTR(message.as_ptr()),
        pszCaptionText: PCWSTR(caption.as_ptr()),
        hbmBanner: HBITMAP::default(),
    };

    let mut last_error = 0u32;
    for _ in 0..MAX_TRIES {
        let mut package = 0u32;
        let mut buffer: *mut c_void = std::ptr::null_mut();
        let mut size = 0u32;
        let status = unsafe {
            CredUIPromptForWindowsCredentialsW(
                Some(&info),
                last_error,
                &mut package,
                None,
                0,
                &mut buffer,
                &mut size,
                None,
                CREDUIWIN_ENUMERATE_CURRENT_USER,
            )
        };
        if status == ERROR_CANCELLED.0 {
            return Err(cancelled());
        }
        if status != 0 {
            return Ok(Outcome::Unavailable(format!("The Windows sign-in dialog failed with code {status}")));
        }

        let mut user = [0u16; 514];
        let mut domain = [0u16; 338];
        let mut password = [0u16; 514];
        let (mut user_len, mut domain_len, mut password_len) = (user.len() as u32, domain.len() as u32, password.len() as u32);
        let unpacked = unsafe {
            let result = CredUnPackAuthenticationBufferW(
                CRED_PACK_PROTECTED_CREDENTIALS,
                buffer,
                size,
                Some(PWSTR(user.as_mut_ptr())),
                &mut user_len,
                Some(PWSTR(domain.as_mut_ptr())),
                Some(&mut domain_len),
                Some(PWSTR(password.as_mut_ptr())),
                &mut password_len,
            );
            std::slice::from_raw_parts_mut(buffer as *mut u8, size as usize).zeroize();
            CoTaskMemFree(Some(buffer));
            result
        };
        if unpacked.is_err() {
            password.zeroize();
            return Ok(Outcome::Unavailable("Windows sent back a sign-in Fran can't read".to_string()));
        }

        let name = until_nul(&user);
        let mut domain_name = until_nul(&domain);
        let mut account = name.clone();
        if domain_name.is_empty() {
            if let Some((left, right)) = name.split_once('\\') {
                domain_name = left.to_string();
                account = right.to_string();
            }
        }
        let account = wide(&account);
        let domain_name = wide(&domain_name);
        let mut token = HANDLE::default();
        let logon = unsafe {
            LogonUserW(
                PCWSTR(account.as_ptr()),
                PCWSTR(domain_name.as_ptr()),
                PCWSTR(password.as_ptr()),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };
        password.zeroize();
        match logon {
            Ok(()) => {
                let same = same_user(token);
                let _ = unsafe { CloseHandle(token) };
                return if same { Ok(Outcome::Confirmed) } else { Err(failed()) };
            }
            Err(error) if error.code() == HRESULT::from_win32(ERROR_LOGON_FAILURE.0) => last_error = ERROR_LOGON_FAILURE.0,
            Err(error) if error.code() == HRESULT::from_win32(ERROR_ACCOUNT_RESTRICTION.0) => return Ok(Outcome::NoProtection),
            Err(_) => return Err(failed()),
        }
    }
    Err(failed())
}
