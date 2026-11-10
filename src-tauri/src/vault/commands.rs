use std::{sync::Arc, time::Duration};

use tauri::State;
use zeroize::Zeroizing;

use super::{Vault, VaultStatus};
use crate::agent::AgentHost;
use crate::error::{AppError, AppResult};
use crate::ssh::terminal_log::TerminalLogs;

// A wrong password costs this on top of the Argon2id work, which slows guessing further.
const WRONG_PASSWORD_DELAY: Duration = Duration::from_secs(1);

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|error| AppError::general(format!("The vault task stopped: {error}")))?
}

#[tauri::command]
pub async fn get_vault_status(vault: State<'_, Arc<Vault>>) -> AppResult<VaultStatus> {
    Ok(vault.status())
}

/// Agent history and terminal logs are encrypted with keys kept in the vault, so they go too.
#[tauri::command]
pub async fn reset_vault(
    vault: State<'_, Arc<Vault>>,
    agent: State<'_, Arc<AgentHost>>,
    terminal_logs: State<'_, Arc<TerminalLogs>>,
) -> AppResult<VaultStatus> {
    vault.reset()?;
    agent.history.forget()?;
    terminal_logs.forget()?;
    agent.inner().apply().await;
    Ok(vault.status())
}

#[tauri::command]
pub async fn enable_app_lock(vault: State<'_, Arc<Vault>>, password: String) -> AppResult<VaultStatus> {
    let password = Zeroizing::new(password);
    let vault = vault.inner().clone();
    blocking(move || {
        vault.enable_lock(&password)?;
        Ok(vault.status())
    })
    .await
}

#[tauri::command]
pub async fn disable_app_lock(vault: State<'_, Arc<Vault>>, password: String) -> AppResult<VaultStatus> {
    let password = Zeroizing::new(password);
    let vault = vault.inner().clone();
    let result = blocking({
        let vault = vault.clone();
        move || vault.disable_lock(&password)
    })
    .await;
    if result.is_err() {
        tokio::time::sleep(WRONG_PASSWORD_DELAY).await;
    }
    result?;
    Ok(vault.status())
}

#[tauri::command]
pub async fn change_app_lock_password(vault: State<'_, Arc<Vault>>, current: String, next: String) -> AppResult<()> {
    let current = Zeroizing::new(current);
    let next = Zeroizing::new(next);
    let vault = vault.inner().clone();
    let result = blocking(move || vault.change_lock_password(&current, &next)).await;
    if result.is_err() {
        tokio::time::sleep(WRONG_PASSWORD_DELAY).await;
    }
    result
}

/// Sessions, terminals and forwards keep running. Only what needs the vault waits.
#[tauri::command]
pub async fn lock_app(
    vault: State<'_, Arc<Vault>>,
    agent: State<'_, Arc<AgentHost>>,
    terminal_logs: State<'_, Arc<TerminalLogs>>,
    reveal: State<'_, Arc<super::reveal::RevealSession>>,
) -> AppResult<VaultStatus> {
    reveal.close();
    if vault.lock()? {
        agent.on_locked();
        terminal_logs.seal();
    }
    Ok(vault.status())
}

#[tauri::command]
pub async fn unlock_app(
    vault: State<'_, Arc<Vault>>,
    agent: State<'_, Arc<AgentHost>>,
    terminal_logs: State<'_, Arc<TerminalLogs>>,
    password: String,
) -> AppResult<VaultStatus> {
    let password = Zeroizing::new(password);
    let result = blocking({
        let vault = vault.inner().clone();
        move || vault.unlock_with_password(&password)
    })
    .await;
    if result.is_err() {
        tokio::time::sleep(WRONG_PASSWORD_DELAY).await;
    }
    result?;

    if terminal_logs.is_sealed()
        && let Err(error) = terminal_logs.unlock(&vault)
    {
        eprintln!("terminal log: {}", error.message);
    }
    agent.inner().on_unlocked().await;
    Ok(vault.status())
}
