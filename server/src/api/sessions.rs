use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sync_proto::{Bytes, Device, RecoveryFinish, RecoveryStart, RecoveryStarted, SessionInfo, SignIn, SignedIn};

use crate::auth::{
    ApiJson, ClientIp, Session, account_subject, check_device, check_key, check_limit, check_wrapped, hash_key, ip_subject, key_matches,
    normalize_email, note_failure, open_session,
};
use crate::crypto::{self, AUTH_SALT_LEN};
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::User;

#[derive(Clone, Copy)]
enum Secret {
    Password,
    RecoveryKey,
}

// The same answer and about the same work whether the account exists or the key is wrong.
async fn check_credentials(state: &AppState, ip: &str, email: &str, key: &Bytes, secret: Secret) -> AppResult<User> {
    check_key(key)?;
    let email = normalize_email(email).map_err(|_| AppError::invalid_credentials())?;
    let (ip_subject, account_subject) = (ip_subject(ip), account_subject(&email));
    check_limit(state, &ip_subject, state.config.rate.per_ip).await?;
    check_limit(state, &account_subject, state.config.rate.per_account).await?;
    let user = state.db.user_by_email(&email).await?;
    let matches = match &user {
        Some(user) => match secret {
            Secret::Password => key_matches(state, key, &user.auth_salt, &user.auth_hash).await?,
            Secret::RecoveryKey => key_matches(state, key, &user.recovery_auth_salt, &user.recovery_auth_hash).await?,
        },
        None => {
            hash_key(state, key.as_slice(), &[0; AUTH_SALT_LEN]).await?;
            false
        }
    };
    match user {
        Some(user) if matches => Ok(user),
        _ => {
            note_failure(state, &[&ip_subject, &account_subject]).await?;
            Err(AppError::invalid_credentials())
        }
    }
}

async fn check_totp(state: &AppState, ip: &str, user: &User, code: Option<&str>) -> AppResult<()> {
    if !user.totp_enabled {
        return Ok(());
    }
    let Some(code) = code.filter(|code| !code.trim().is_empty()) else {
        return Err(AppError::totp_required());
    };
    let secret = crypto::open_totp(&state.config.server_key, &user.id, &user.totp_secret)
        .ok_or_else(|| AppError::internal("totp", "the stored secret can't be opened, was SERVER_KEY changed?"))?;
    let fresh = match crypto::totp_matching_step(&secret, code, now()) {
        Some(step) => state.db.use_totp_step(&user.id, step).await?,
        None => false,
    };
    if fresh {
        return Ok(());
    }
    note_failure(state, &[&ip_subject(ip), &account_subject(&user.email)]).await?;
    Err(AppError::totp_invalid())
}

async fn signed_in(state: &AppState, user: &User, device: Device, wrapped_data_key: Bytes) -> AppResult<Json<SignedIn>> {
    state.db.clear_attempts(&account_subject(&user.email)).await?;
    let (token, session) = open_session(state, &user.id, device).await?;
    Ok(Json(SignedIn { token, account_id: user.id.clone(), session_id: session.id, expires_at: session.expires_at, wrapped_data_key }))
}

pub async fn sign_in(State(state): State<AppState>, ClientIp(ip): ClientIp, ApiJson(request): ApiJson<SignIn>) -> AppResult<Json<SignedIn>> {
    let device = check_device(&request.device)?;
    let user = check_credentials(&state, &ip, &request.email, &request.auth_key, Secret::Password).await?;
    check_totp(&state, &ip, &user, request.totp.as_deref()).await?;
    let wrapped_data_key = user.wrapped_data_key.clone().into();
    signed_in(&state, &user, device, wrapped_data_key).await
}

pub async fn list(State(state): State<AppState>, session: Session) -> AppResult<Json<Vec<SessionInfo>>> {
    let rows = state.db.list_sessions(&session.user_id, now()).await?;
    let sessions = rows
        .into_iter()
        .map(|row| SessionInfo {
            current: row.id == session.id,
            id: row.id,
            device: Device { name: row.device_name, os: row.device_os },
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
        })
        .collect();
    Ok(Json(sessions))
}

pub async fn sign_out(State(state): State<AppState>, session: Session) -> AppResult<StatusCode> {
    state.db.delete_session(&session.user_id, &session.id).await?;
    state.sessions_changed(&session.user_id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> AppResult<StatusCode> {
    if !state.db.delete_session(&session.user_id, &id).await? {
        return Err(AppError::not_found());
    }
    state.sessions_changed(&session.user_id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn recovery_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RecoveryStart>,
) -> AppResult<Json<RecoveryStarted>> {
    let user = check_credentials(&state, &ip, &request.email, &request.recovery_auth_key, Secret::RecoveryKey).await?;
    Ok(Json(RecoveryStarted { recovery_wrapped_data_key: user.recovery_wrapped_data_key.into() }))
}

pub async fn recovery_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<RecoveryFinish>,
) -> AppResult<Json<SignedIn>> {
    check_key(&request.auth_key)?;
    check_wrapped(&request.wrapped_data_key)?;
    let device = check_device(&request.device)?;
    let user = check_credentials(&state, &ip, &request.email, &request.recovery_auth_key, Secret::RecoveryKey).await?;
    let auth_salt = crypto::random::<AUTH_SALT_LEN>();
    let auth_hash = hash_key(&state, request.auth_key.as_slice(), &auth_salt).await?;
    state.db.set_password(&user.id, &auth_hash, &auth_salt, request.wrapped_data_key.as_slice()).await?;
    state.db.delete_all_sessions(&user.id).await?;
    state.sessions_changed(&user.id);
    signed_in(&state, &user, device, request.wrapped_data_key).await
}
