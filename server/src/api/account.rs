use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use sync_proto::{AccountInfo, ChangePassword, ChangeRecovery, DeleteAccount, Role, TotpRequest, TotpState};

use crate::auth::{ApiJson, Session, account_subject, check_key, check_wrapped, confirm_password, hash_key, note_failure, signed_in_user};
use crate::crypto::{self, AUTH_SALT_LEN, TOTP_SECRET_LEN};
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub async fn info(State(state): State<AppState>, session: Session) -> AppResult<Json<AccountInfo>> {
    let user = signed_in_user(&state, &session).await?;
    Ok(Json(AccountInfo {
        quota_bytes: state.settings().quota_for(user.quota_bytes),
        id: user.id,
        email: user.email,
        totp_enabled: user.totp_enabled,
        used_bytes: user.used_bytes as u64,
        created_at: user.created_at,
        role: user.role,
    }))
}

pub async fn change_password(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<ChangePassword>) -> AppResult<StatusCode> {
    check_key(&request.new_auth_key)?;
    check_wrapped(&request.new_wrapped_data_key)?;
    let user = signed_in_user(&state, &session).await?;
    confirm_password(&state, &user, &request.auth_key).await?;
    let auth_salt = crypto::random::<AUTH_SALT_LEN>();
    let auth_hash = hash_key(&state, request.new_auth_key.as_slice(), &auth_salt).await?;
    state.db.set_password(&user.id, &auth_hash, &auth_salt, request.new_wrapped_data_key.as_slice()).await?;
    state.db.delete_other_sessions(&user.id, &session.id).await?;
    state.sessions_changed(&user.id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_recovery(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<ChangeRecovery>) -> AppResult<StatusCode> {
    check_key(&request.recovery_auth_key)?;
    check_wrapped(&request.recovery_wrapped_data_key)?;
    let user = signed_in_user(&state, &session).await?;
    confirm_password(&state, &user, &request.auth_key).await?;
    let salt = crypto::random::<AUTH_SALT_LEN>();
    let hash = hash_key(&state, request.recovery_auth_key.as_slice(), &salt).await?;
    state.db.set_recovery(&user.id, &hash, &salt, request.recovery_wrapped_data_key.as_slice()).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn percent_encoded(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn otpauth_uri(email: &str, secret: &str) -> String {
    format!("otpauth://totp/Fran:{}?secret={secret}&issuer=Fran", percent_encoded(email))
}

pub async fn totp(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<TotpRequest>) -> AppResult<Json<TotpState>> {
    let user = signed_in_user(&state, &session).await?;
    let already_on = || AppError::bad_request("Two-step sign-in is already on");
    match request {
        TotpRequest::Begin => {
            if user.totp_enabled {
                return Err(already_on());
            }
            let secret = crypto::random::<TOTP_SECRET_LEN>();
            let sealed = crypto::seal_totp(&state.config.server_key, &user.id, &secret).map_err(|error| AppError::internal("totp", error))?;
            state.db.set_totp(&user.id, &sealed, false).await?;
            let secret = crypto::base32(&secret);
            Ok(Json(TotpState { enabled: false, uri: Some(otpauth_uri(&user.email, &secret)), secret: Some(secret) }))
        }
        TotpRequest::Confirm { code } => {
            if user.totp_enabled {
                return Err(already_on());
            }
            let secret = crypto::open_totp(&state.config.server_key, &user.id, &user.totp_secret)
                .ok_or_else(|| AppError::bad_request("Start setting up two-step sign-in first"))?;
            let Some(step) = crypto::totp_matching_step(&secret, &code, now()) else {
                note_failure(&state, &[&account_subject(&user.email)]).await?;
                return Err(AppError::totp_invalid());
            };
            state.db.enable_totp(&user.id, step).await?;
            Ok(Json(TotpState { enabled: true, secret: None, uri: None }))
        }
        TotpRequest::Disable { auth_key } => {
            confirm_password(&state, &user, &auth_key).await?;
            state.db.set_totp(&user.id, &[], false).await?;
            Ok(Json(TotpState { enabled: false, secret: None, uri: None }))
        }
    }
}

pub async fn delete(State(state): State<AppState>, session: Session, ApiJson(request): ApiJson<DeleteAccount>) -> AppResult<StatusCode> {
    let user = signed_in_user(&state, &session).await?;
    confirm_password(&state, &user, &request.auth_key).await?;
    if user.role == Role::Owner && state.db.list_users().await?.len() > 1 {
        return Err(AppError::forbidden("Hand the server to someone else before deleting the owner's account"));
    }
    state.db.delete_user(&user.id).await?;
    state.db.clear_attempts(&account_subject(&user.email)).await?;
    state.sessions_changed(&user.id);
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authenticator_link_keeps_odd_emails_in_one_piece() {
        assert_eq!(
            otpauth_uri("ada+work@example.com", "MZXW6YTBOI"),
            "otpauth://totp/Fran:ada%2Bwork%40example.com?secret=MZXW6YTBOI&issuer=Fran"
        );
    }
}
