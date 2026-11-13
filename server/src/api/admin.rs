use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use sync_proto::{
    AdminInvite, AdminLogEntry, AdminOverview, AdminUser, AdminUserDetail, AdminUsersPage, ClaimServer, CreateInvite, CreatedInvite, DeleteAccount, Device,
    Role, ServerSettings, SessionInfo, SetQuota, SetRole, TransferOwnership, UpdateSettings,
};

use crate::auth::{ApiJson, ClientIp, Session, account_subject, check_limit, confirm_password, ip_subject, normalize_email, note_failure, signed_in_user};
use crate::crypto;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::settings::{self, Effective, MIN_ACCOUNT_BYTES};
use crate::state::AppState;
use crate::store::{DeviceStats, User, UserSummary};

const LOG_ENTRIES: i64 = 200;
const MAX_PAGE: usize = 200;
const MAX_INVITE_DAYS: u32 = 365;
const DAY_SECS: i64 = 24 * 60 * 60;
// Shared by every address, so guessing from many places is slow too.
const CLAIM_SUBJECT: &str = "claim:any";

async fn admin(state: &AppState, session: &Session) -> AppResult<User> {
    let user = signed_in_user(state, session).await?;
    if !user.role.is_admin() {
        return Err(AppError::forbidden("Only the server's admins can do that"));
    }
    Ok(user)
}

async fn owner(state: &AppState, session: &Session) -> AppResult<User> {
    let user = signed_in_user(state, session).await?;
    if user.role != Role::Owner {
        return Err(AppError::forbidden("Only the server's owner can do that"));
    }
    Ok(user)
}

async fn target(state: &AppState, id: &str) -> AppResult<User> {
    state.db.user_by_id(id).await?.ok_or_else(AppError::not_found)
}

fn shown_user(summary: &UserSummary, stats: DeviceStats, settings: &Effective) -> AdminUser {
    AdminUser {
        id: summary.id.clone(),
        email: summary.email.clone(),
        role: summary.role,
        used_bytes: summary.used_bytes.max(0) as u64,
        own_quota_bytes: summary.quota_bytes.max(0) as u64,
        quota_bytes: settings.quota_for(summary.quota_bytes),
        created_at: summary.created_at,
        totp_enabled: summary.totp_enabled,
        devices: stats.devices.max(0) as u64,
        last_seen_at: stats.last_seen_at,
    }
}

fn summary_of(user: &User) -> UserSummary {
    UserSummary {
        id: user.id.clone(),
        email: user.email.clone(),
        role: user.role,
        used_bytes: user.used_bytes,
        quota_bytes: user.quota_bytes,
        totp_enabled: user.totp_enabled,
        created_at: user.created_at,
    }
}

async fn log(state: &AppState, actor: &User, action: &str, target: &str, detail: &str) -> AppResult<()> {
    state.db.add_log(&actor.email, action, target, detail, now()).await?;
    Ok(())
}

fn bytes_text(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

pub async fn claim(State(state): State<AppState>, ClientIp(ip): ClientIp, session: Session, ApiJson(request): ApiJson<ClaimServer>) -> AppResult<StatusCode> {
    let user = signed_in_user(&state, &session).await?;
    let Some(code) = state.setup_code() else {
        return Err(AppError::forbidden("This server already has an owner"));
    };
    let ip_subject = ip_subject(&ip);
    check_limit(&state, &ip_subject, state.config.rate.per_account).await?;
    check_limit(&state, CLAIM_SUBJECT, state.config.rate.per_ip).await?;
    if !crypto::same_setup_code(&request.code, &code) {
        note_failure(&state, &[&ip_subject, CLAIM_SUBJECT]).await?;
        return Err(AppError::forbidden("That setup code isn't right. It's printed in the server's log each time it starts."));
    }
    if !state.db.make_owner(&user.id).await? {
        state.drop_setup_code();
        return Err(AppError::forbidden("This server already has an owner"));
    }
    state.drop_setup_code();
    log(&state, &user, "claim", &user.email, "Claimed with the setup code").await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn overview(State(state): State<AppState>, session: Session) -> AppResult<Json<AdminOverview>> {
    admin(&state, &session).await?;
    let settings = state.settings();
    Ok(Json(AdminOverview {
        version: crate::VERSION.to_string(),
        started_at: state.started_at,
        accounts: state.db.list_users().await?.len() as u64,
        used_bytes: state.db.total_used().await?,
        server_bytes: settings.server_bytes,
        signup: settings.signup,
    }))
}

#[derive(Deserialize)]
pub struct UsersQuery {
    search: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

pub async fn users(State(state): State<AppState>, session: Session, query: Result<Query<UsersQuery>, QueryRejection>) -> AppResult<Json<AdminUsersPage>> {
    admin(&state, &session).await?;
    let Query(query) = query.map_err(|_| AppError::bad_request("offset and limit must be whole numbers"))?;
    let search = query.search.unwrap_or_default().trim().to_lowercase();
    let all = state.db.list_users().await?;
    let matching: Vec<&UserSummary> = all.iter().filter(|user| search.is_empty() || user.email.contains(&search)).collect();
    let stats = state.db.device_stats(now()).await?;
    let settings = state.settings();
    let users = matching
        .iter()
        .skip(query.offset.unwrap_or(0))
        .take(query.limit.unwrap_or(50).clamp(1, MAX_PAGE))
        .map(|user| shown_user(user, stats.get(&user.id).copied().unwrap_or_default(), &settings))
        .collect();
    Ok(Json(AdminUsersPage { users, total: matching.len() as u64 }))
}

pub async fn user(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> AppResult<Json<AdminUserDetail>> {
    admin(&state, &session).await?;
    let found = target(&state, &id).await?;
    let now = now();
    let stats = state.db.device_stats(now).await?.get(&id).copied().unwrap_or_default();
    let sessions = state
        .db
        .list_sessions(&id, now)
        .await?
        .into_iter()
        .map(|row| SessionInfo {
            id: row.id,
            device: Device { name: row.device_name, os: row.device_os },
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
            current: false,
        })
        .collect();
    Ok(Json(AdminUserDetail { user: shown_user(&summary_of(&found), stats, &state.settings()), sessions }))
}

pub async fn set_quota(State(state): State<AppState>, session: Session, Path(id): Path<String>, ApiJson(request): ApiJson<SetQuota>) -> AppResult<StatusCode> {
    let actor = admin(&state, &session).await?;
    let found = target(&state, &id).await?;
    if request.quota_bytes != 0 && request.quota_bytes < MIN_ACCOUNT_BYTES.max(state.settings().limits.record_bytes) {
        return Err(AppError::bad_request("An account's limit has to hold at least one record of the largest size"));
    }
    state.db.set_quota(&id, i64::try_from(request.quota_bytes).unwrap_or(i64::MAX)).await?;
    let detail = if request.quota_bytes == 0 { "Back to the server's default".to_string() } else { format!("Own limit of {}", bytes_text(request.quota_bytes)) };
    log(&state, &actor, "quota", &found.email, &detail).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn set_role(State(state): State<AppState>, session: Session, Path(id): Path<String>, ApiJson(request): ApiJson<SetRole>) -> AppResult<StatusCode> {
    let actor = owner(&state, &session).await?;
    let found = target(&state, &id).await?;
    if found.id == actor.id {
        return Err(AppError::bad_request("Hand the server to someone else to stop being its owner"));
    }
    if request.role == Role::Owner {
        return Err(AppError::bad_request("Use hand over to make someone the owner"));
    }
    state.db.set_role(&id, request.role).await?;
    log(&state, &actor, "role", &found.email, &format!("Now {}", request.role.as_str())).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sign_out_user(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> AppResult<StatusCode> {
    let actor = admin(&state, &session).await?;
    let found = target(&state, &id).await?;
    if found.role == Role::Owner && actor.role != Role::Owner {
        return Err(AppError::forbidden("Only the owner can sign the owner out"));
    }
    state.db.delete_all_sessions(&id).await?;
    state.sessions_changed(&id);
    log(&state, &actor, "signOut", &found.email, "Signed out of every device").await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_user(State(state): State<AppState>, session: Session, Path(id): Path<String>, ApiJson(request): ApiJson<DeleteAccount>) -> AppResult<StatusCode> {
    let actor = admin(&state, &session).await?;
    confirm_password(&state, &actor, &request.auth_key).await?;
    let found = target(&state, &id).await?;
    if found.id == actor.id {
        return Err(AppError::bad_request("Delete your own account from its account panel"));
    }
    if found.role == Role::Owner {
        return Err(AppError::forbidden("The owner's account can't be deleted by someone else"));
    }
    if found.role == Role::Admin && actor.role != Role::Owner {
        return Err(AppError::forbidden("Only the owner can delete an admin"));
    }
    state.db.delete_user(&id).await?;
    state.db.clear_attempts(&account_subject(&found.email)).await?;
    state.sessions_changed(&id);
    log(&state, &actor, "deleteUser", &found.email, &format!("Deleted with {} stored", bytes_text(found.used_bytes.max(0) as u64))).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn transfer(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<TransferOwnership>) -> AppResult<StatusCode> {
    let actor = owner(&state, &session).await?;
    confirm_password(&state, &actor, &request.auth_key).await?;
    let found = target(&state, &request.to).await?;
    if found.id == actor.id {
        return Err(AppError::bad_request("You already own this server"));
    }
    state.db.transfer_owner(&found.id).await?;
    log(&state, &actor, "transfer", &found.email, "Now the owner, the previous owner is an admin").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn shown_invites(state: &AppState) -> AppResult<Vec<AdminInvite>> {
    let emails: HashMap<String, String> = state.db.list_users().await?.into_iter().map(|user| (user.id, user.email)).collect();
    let rows = state.db.invites().await?;
    Ok(rows
        .into_iter()
        .map(|row| AdminInvite {
            used_by: emails.get(&row.used_by).cloned().unwrap_or_default(),
            id: row.code_hash,
            email: row.email,
            created_at: row.created_at,
            expires_at: row.expires_at,
            used_at: row.used_at,
        })
        .collect())
}

pub async fn invites(State(state): State<AppState>, session: Session) -> AppResult<Json<Vec<AdminInvite>>> {
    admin(&state, &session).await?;
    Ok(Json(shown_invites(&state).await?))
}

pub async fn create_invite(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<CreateInvite>) -> AppResult<(StatusCode, Json<CreatedInvite>)> {
    let actor = admin(&state, &session).await?;
    let email = if request.email.trim().is_empty() { String::new() } else { normalize_email(&request.email)? };
    if !email.is_empty() && state.db.user_by_email(&email).await?.is_some() {
        return Err(AppError::bad_request(format!("{email} already has an account")));
    }
    if request.expires_in_days > MAX_INVITE_DAYS {
        return Err(AppError::bad_request("An invite can last a year at most"));
    }
    let now = now();
    let expires_at = if request.expires_in_days == 0 { 0 } else { now + i64::from(request.expires_in_days) * DAY_SECS };
    let code = crypto::invite_code();
    let hash = crypto::invite_hash(&code);
    state.db.insert_invite(&hash, &email, now, expires_at).await?;
    let who = if email.is_empty() { "Anyone, once".to_string() } else { email.clone() };
    log(&state, &actor, "inviteCreate", &who, &if expires_at == 0 { "Never expires".to_string() } else { format!("Expires in {} days", request.expires_in_days) }).await?;
    let invite = AdminInvite { id: hash, email, created_at: now, expires_at, used_at: 0, used_by: String::new() };
    Ok((StatusCode::CREATED, Json(CreatedInvite { code, invite })))
}

pub async fn delete_invite(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> AppResult<StatusCode> {
    let actor = admin(&state, &session).await?;
    let found = state.db.invites().await?.into_iter().find(|row| row.code_hash == id).ok_or_else(AppError::not_found)?;
    state.db.delete_invite(&id).await?;
    let who = if found.email.is_empty() { "Anyone, once".to_string() } else { found.email };
    log(&state, &actor, "inviteRevoke", &who, "").await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn settings(State(state): State<AppState>, session: Session) -> AppResult<Json<ServerSettings>> {
    admin(&state, &session).await?;
    Ok(Json(settings::shown(&state.settings())))
}

pub async fn update_settings(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<UpdateSettings>) -> AppResult<Json<ServerSettings>> {
    let actor = admin(&state, &session).await?;
    let rows = settings::changes(&state.settings(), &request).map_err(AppError::bad_request)?;
    if !rows.is_empty() {
        state.db.save_settings(&rows).await?;
        state.reload_settings().await?;
        let detail = rows.iter().map(|(name, value)| format!("{name} = {value}")).collect::<Vec<_>>().join(", ");
        log(&state, &actor, "settings", "", &detail).await?;
    }
    Ok(Json(settings::shown(&state.settings())))
}

pub async fn log_entries(State(state): State<AppState>, session: Session) -> AppResult<Json<Vec<AdminLogEntry>>> {
    admin(&state, &session).await?;
    let rows = state.db.log(LOG_ENTRIES).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AdminLogEntry { id: row.id, at: row.created_at, actor: row.actor, action: row.action, target: row.target, detail: row.detail })
            .collect(),
    ))
}
