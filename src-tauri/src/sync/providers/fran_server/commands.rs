use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sync_proto::{
    AccountInfo, AdminInvite, AdminLogEntry, AdminOverview, AdminUserDetail, AdminUsersPage, CreateInvite, CreatedInvite, DeleteAccount, Role, ServerInfo,
    ServerSettings, SessionInfo, TotpRequest, TotpState, TransferOwnership, UpdateSettings,
};
use tauri::State;
use zeroize::Zeroizing;

use super::client::Client;
use super::{Account, Session, recover, sign_in, sign_up, this_device};
use crate::error::{AppError, AppResult};
use crate::sync::engine::Engine;
use crate::sync::providers::CloudKind;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    url: String,
    email: String,
    password: String,
    /// What this cloud is called in Fran. Empty takes the server's address.
    #[serde(default)]
    name: String,
    #[serde(default)]
    device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedAccount {
    cloud_id: String,
    /// Shown once and never stored. It can't be read again from anywhere.
    recovery_key: String,
}

async fn added(engine: &Arc<Engine>, name: &str, session: Session) -> AppResult<String> {
    let host = session.config.url.split("://").nth(1).unwrap_or(&session.config.url).to_string();
    let name = if name.trim().is_empty() { host } else { name.trim().to_string() };
    let config = serde_json::to_value(&session.config)?;
    let vault = engine.stores().vault.clone();
    engine.add_cloud(CloudKind::FranServer, &name, session.config.identity(), config, |cloud_id| session.save(cloud_id, &vault)).await
}

fn account(engine: &Engine, cloud_id: &str) -> AppResult<Account> {
    Account::open(&engine.cloud(cloud_id)?, &engine.stores().vault)
}

#[tauri::command]
pub async fn fran_server_info(url: String) -> AppResult<ServerInfo> {
    Client::new(&url)?.info().await
}

#[tauri::command]
pub async fn fran_server_create_account(engine: State<'_, Arc<Engine>>, login: Login, invite: Option<String>) -> AppResult<CreatedAccount> {
    let password = Zeroizing::new(login.password);
    let signed_up = sign_up(&login.url, &login.email, &password, invite, this_device(&login.device_name)).await?;
    let cloud_id = added(&engine, &login.name, signed_up.session).await?;
    Ok(CreatedAccount { cloud_id, recovery_key: signed_up.recovery_key.to_string() })
}

#[tauri::command]
pub async fn fran_server_sign_in(engine: State<'_, Arc<Engine>>, login: Login, code: Option<String>) -> AppResult<String> {
    let password = Zeroizing::new(login.password);
    let session = sign_in(&login.url, &login.email, &password, code, this_device(&login.device_name)).await?;
    added(&engine, &login.name, session).await
}

/// `login.password` is the new password.
#[tauri::command]
pub async fn fran_server_recover(engine: State<'_, Arc<Engine>>, login: Login, recovery_key: String) -> AppResult<String> {
    let password = Zeroizing::new(login.password);
    let recovery_key = Zeroizing::new(recovery_key);
    let session = recover(&login.url, &login.email, &recovery_key, &password, this_device(&login.device_name)).await?;
    added(&engine, &login.name, session).await
}

/// Ends this computer's session on the server, then forgets the cloud here. An unreachable server doesn't stop it.
#[tauri::command]
pub async fn fran_server_sign_out(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<()> {
    if let Ok(account) = account(&engine, &cloud_id) {
        let _ = account.client.sign_out(&account.token).await;
    }
    engine.remove_cloud(&cloud_id).await
}

#[tauri::command]
pub async fn fran_server_account(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<AccountInfo> {
    let account = account(&engine, &cloud_id)?;
    account.client.account(&account.token).await
}

#[tauri::command]
pub async fn fran_server_devices(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<Vec<SessionInfo>> {
    let account = account(&engine, &cloud_id)?;
    account.client.sessions(&account.token).await
}

#[tauri::command]
pub async fn fran_server_revoke_device(engine: State<'_, Arc<Engine>>, cloud_id: String, session_id: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    account.client.revoke(&account.token, &session_id).await
}

#[tauri::command]
pub async fn fran_server_change_password(engine: State<'_, Arc<Engine>>, cloud_id: String, current: String, next: String) -> AppResult<()> {
    let (current, next) = (Zeroizing::new(current), Zeroizing::new(next));
    account(&engine, &cloud_id)?.change_password(&current, &next).await
}

#[tauri::command]
pub async fn fran_server_new_recovery_key(engine: State<'_, Arc<Engine>>, cloud_id: String, password: String) -> AppResult<String> {
    let password = Zeroizing::new(password);
    Ok(account(&engine, &cloud_id)?.new_recovery_key(&password).await?.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum TotpAction {
    Begin,
    Confirm { code: String },
    Disable { password: String },
}

#[tauri::command]
pub async fn fran_server_totp(engine: State<'_, Arc<Engine>>, cloud_id: String, action: TotpAction) -> AppResult<TotpState> {
    let account = account(&engine, &cloud_id)?;
    let request = match action {
        TotpAction::Begin => TotpRequest::Begin,
        TotpAction::Confirm { code } => TotpRequest::Confirm { code: code.trim().to_string() },
        TotpAction::Disable { password } => TotpRequest::Disable { auth_key: account.auth_key(&Zeroizing::new(password)).await? },
    };
    account.client.totp(&account.token, &request).await
}

const USERS_PAGE: usize = 100;

#[tauri::command]
pub async fn fran_server_admin_claim(engine: State<'_, Arc<Engine>>, cloud_id: String, code: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    account.client.claim(&account.token, code.trim()).await
}

#[tauri::command]
pub async fn fran_server_admin_overview(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<AdminOverview> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_overview(&account.token).await
}

#[tauri::command]
pub async fn fran_server_admin_users(engine: State<'_, Arc<Engine>>, cloud_id: String, search: String, offset: usize) -> AppResult<AdminUsersPage> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_users(&account.token, search.trim(), offset, USERS_PAGE).await
}

#[tauri::command]
pub async fn fran_server_admin_user(engine: State<'_, Arc<Engine>>, cloud_id: String, user_id: String) -> AppResult<AdminUserDetail> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_user(&account.token, &user_id).await
}

/// 0 puts the account back on the server's default.
#[tauri::command]
pub async fn fran_server_admin_set_quota(engine: State<'_, Arc<Engine>>, cloud_id: String, user_id: String, quota_bytes: u64) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_set_quota(&account.token, &user_id, quota_bytes).await
}

#[tauri::command]
pub async fn fran_server_admin_set_role(engine: State<'_, Arc<Engine>>, cloud_id: String, user_id: String, role: Role) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_set_role(&account.token, &user_id, role).await
}

#[tauri::command]
pub async fn fran_server_admin_sign_out_user(engine: State<'_, Arc<Engine>>, cloud_id: String, user_id: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_sign_out_user(&account.token, &user_id).await
}

/// `password` is the admin's own, asked again like deleting your own account.
#[tauri::command]
pub async fn fran_server_admin_delete_user(engine: State<'_, Arc<Engine>>, cloud_id: String, user_id: String, password: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    let auth_key = account.auth_key(&Zeroizing::new(password)).await?;
    account.client.admin_delete_user(&account.token, &user_id, &DeleteAccount { auth_key }).await
}

#[tauri::command]
pub async fn fran_server_admin_transfer(engine: State<'_, Arc<Engine>>, cloud_id: String, user_id: String, password: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    let auth_key = account.auth_key(&Zeroizing::new(password)).await?;
    account.client.admin_transfer(&account.token, &TransferOwnership { to: user_id, auth_key }).await
}

#[tauri::command]
pub async fn fran_server_admin_invites(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<Vec<AdminInvite>> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_invites(&account.token).await
}

/// The code comes back once here, to be shown and copied. The server only keeps its hash.
#[tauri::command]
pub async fn fran_server_admin_create_invite(engine: State<'_, Arc<Engine>>, cloud_id: String, email: String, expires_in_days: u32) -> AppResult<CreatedInvite> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_create_invite(&account.token, &CreateInvite { email: email.trim().to_string(), expires_in_days }).await
}

#[tauri::command]
pub async fn fran_server_admin_delete_invite(engine: State<'_, Arc<Engine>>, cloud_id: String, invite_id: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_delete_invite(&account.token, &invite_id).await
}

#[tauri::command]
pub async fn fran_server_admin_settings(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<ServerSettings> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_settings(&account.token).await
}

#[tauri::command]
pub async fn fran_server_admin_update_settings(engine: State<'_, Arc<Engine>>, cloud_id: String, update: UpdateSettings) -> AppResult<ServerSettings> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_update_settings(&account.token, &update).await
}

#[tauri::command]
pub async fn fran_server_admin_log(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<Vec<AdminLogEntry>> {
    let account = account(&engine, &cloud_id)?;
    account.client.admin_log(&account.token).await
}

/// Deletes the account and everything the server holds for it. This computer keeps its own copy.
#[tauri::command]
pub async fn fran_server_delete_account(engine: State<'_, Arc<Engine>>, cloud_id: String, password: String, typed_email: String) -> AppResult<()> {
    let account = account(&engine, &cloud_id)?;
    if !typed_email.trim().eq_ignore_ascii_case(&account.config.email) {
        return Err(AppError::general("Type the account's email address to delete it"));
    }
    account.delete(&Zeroizing::new(password)).await?;
    engine.remove_cloud(&cloud_id).await
}
