// Asks the operating system to confirm the user before a secret leaves the vault.
// The prompt is drawn by the OS (or by Rust on Linux without polkit), never by the webview.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use tauri::WebviewWindow;

use crate::error::{AppError, AppResult, ErrorDetail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Confirmed,
    /// The OS says the account has no password, PIN or biometrics, so there's nothing to check.
    NoProtection,
    /// Nothing on this computer can check, for the given reason.
    Unavailable(String),
}

static PROMPT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn cancelled() -> AppError {
    AppError::new("Cancelled", ErrorDetail::OsAuthCancelled)
}

pub fn failed() -> AppError {
    AppError::general("Your system didn't confirm it's you")
}

/// `action` finishes "Fran is trying to", like "show the password for orders-db".
/// `password_dialog` skips the desktop prompt on Linux and checks the password in Fran's own dialog.
pub async fn confirm(window: &WebviewWindow, action: &str, password_dialog: bool) -> AppResult<Outcome> {
    let _prompt = PROMPT.try_lock().map_err(|_| AppError::general("Fran is already asking you to confirm it's you"))?;
    let _ = password_dialog;
    // macOS writes "Fran is trying to" in front of the text itself.
    let reason = if cfg!(target_os = "macos") { action.to_string() } else { format!("Fran wants to {action}.") };
    let reason = reason.as_str();

    #[cfg(windows)]
    {
        let hwnd = window.hwnd().map_err(|error| AppError::general(error.to_string()))?.0 as isize;
        let reason = reason.to_string();
        return tauri::async_runtime::spawn_blocking(move || windows::confirm(hwnd, &reason))
            .await
            .map_err(|error| AppError::general(error.to_string()))?;
    }

    #[cfg(target_os = "macos")]
    {
        let _ = window;
        let reason = reason.to_string();
        return tauri::async_runtime::spawn_blocking(move || macos::confirm(&reason))
            .await
            .map_err(|error| AppError::general(error.to_string()))?;
    }

    #[cfg(target_os = "linux")]
    {
        return linux::confirm(window, reason, password_dialog).await;
    }

    #[allow(unreachable_code)]
    {
        let _ = (window, reason);
        Ok(Outcome::Unavailable("This system has no way for Fran to check who you are".to_string()))
    }
}

/// True only when the OS clearly says the account has no password, PIN or biometrics.
pub async fn account_unprotected() -> bool {
    tauri::async_runtime::spawn_blocking(|| {
        #[cfg(windows)]
        return windows::unprotected();
        #[cfg(target_os = "macos")]
        return macos::unprotected();
        #[cfg(target_os = "linux")]
        return linux::unprotected();
        #[allow(unreachable_code)]
        false
    })
    .await
    .unwrap_or(false)
}

/// Linux only: registers Fran's polkit action, which asks for an admin password once.
pub async fn install() -> AppResult<()> {
    #[cfg(target_os = "linux")]
    {
        return tauri::async_runtime::spawn_blocking(linux::install)
            .await
            .map_err(|error| AppError::general(error.to_string()))?;
    }
    #[allow(unreachable_code)]
    Err(AppError::general("Only needed on Linux"))
}
