use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Request};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::Json;
use serde::de::DeserializeOwned;
use sync_proto::{Bytes, Device, KEY_LEN};
use uuid::Uuid;

use crate::crypto;
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::{SessionRow, User};

pub const SESSION_SLIDE_SECS: i64 = 30 * 24 * 60 * 60;
pub const SESSION_MAX_SECS: i64 = 365 * 24 * 60 * 60;
const TOUCH_EVERY_SECS: i64 = 60 * 60;
const MAX_WRAPPED_KEY_LEN: usize = 1024;

pub struct Session {
    pub id: String,
    pub user_id: String,
}

fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token.trim())
}

impl FromRequestParts<AppState> for Session {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let token = bearer(parts).ok_or_else(AppError::unauthorized)?;
        let row = state.db.session_by_token_hash(&crypto::sha256_hex(token.as_bytes())).await?.ok_or_else(AppError::unauthorized)?;
        let now = now();
        if row.expires_at <= now {
            return Err(AppError::unauthorized());
        }
        if now - row.last_seen_at >= TOUCH_EVERY_SECS {
            let expires_at = (now + SESSION_SLIDE_SECS).min(row.created_at + SESSION_MAX_SECS);
            state.db.touch_session(&row.id, now, expires_at).await?;
        }
        Ok(Self { id: row.id, user_id: row.user_id })
    }
}

pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        if state.config.trust_proxy {
            // The last entry is the one the proxy in front of this server added.
            let forwarded = parts.headers.get("x-forwarded-for").and_then(|value| value.to_str().ok());
            if let Some(ip) = forwarded.and_then(|list| list.rsplit(',').next()).and_then(|entry| entry.trim().parse::<IpAddr>().ok()) {
                return Ok(Self(ip.to_string()));
            }
        }
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip().to_string());
        Ok(Self(peer.unwrap_or_else(|| "unknown".to_string())))
    }
}

pub struct ApiJson<T>(pub T);

impl<T: DeserializeOwned> FromRequest<AppState> for ApiJson<T> {
    type Rejection = AppError;

    async fn from_request(request: Request, state: &AppState) -> AppResult<Self> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(AppError::too_large("The request is too big")),
            Err(_) => Err(AppError::bad_request("The request isn't valid")),
        }
    }
}

pub fn normalize_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    let shaped = email.split_once('@').is_some_and(|(name, domain)| !name.is_empty() && !domain.is_empty());
    if !shaped || email.len() > 255 || email.chars().any(|character| character.is_control() || character.is_whitespace()) {
        return Err(AppError::bad_request("That email address isn't valid"));
    }
    Ok(email)
}

pub fn check_key(key: &Bytes) -> AppResult<()> {
    if key.len() == KEY_LEN { Ok(()) } else { Err(AppError::bad_request("A key has the wrong length")) }
}

pub fn check_wrapped(key: &Bytes) -> AppResult<()> {
    if key.is_empty() || key.len() > MAX_WRAPPED_KEY_LEN {
        return Err(AppError::bad_request("A wrapped key has the wrong length"));
    }
    Ok(())
}

pub fn check_device(device: &Device) -> AppResult<Device> {
    let name = device.name.trim();
    let os = device.os.trim();
    if name.is_empty() || name.chars().count() > 255 || os.chars().count() > 64 {
        return Err(AppError::bad_request("The device name isn't valid"));
    }
    Ok(Device { name: name.to_string(), os: os.to_string() })
}

pub async fn hash_key(state: &AppState, key: &[u8], salt: &[u8]) -> AppResult<[u8; KEY_LEN]> {
    let _permit = state.hashing.acquire().await.map_err(|error| AppError::internal("hashing", error))?;
    let (key, salt) = (key.to_vec(), salt.to_vec());
    tokio::task::spawn_blocking(move || crypto::hash_auth_key(&key, &salt))
        .await
        .map_err(|error| AppError::internal("hashing", error))?
        .map_err(|error| AppError::internal("hashing", error))
}

pub async fn key_matches(state: &AppState, key: &Bytes, salt: &[u8], hash: &[u8]) -> AppResult<bool> {
    Ok(crypto::constant_eq(&hash_key(state, key.as_slice(), salt).await?, hash))
}

pub fn account_subject(email: &str) -> String {
    format!("account:{email}")
}

pub fn ip_subject(ip: &str) -> String {
    format!("ip:{ip}")
}

pub async fn check_limit(state: &AppState, subject: &str, max: i64) -> AppResult<()> {
    let now = now();
    let since = now - state.config.rate.window_secs;
    if state.db.count_attempts(subject, since).await? < max {
        return Ok(());
    }
    let oldest = state.db.oldest_attempt(subject, since).await?.unwrap_or(now);
    Err(AppError::rate_limited((oldest + state.config.rate.window_secs - now).max(1) as u64))
}

pub async fn note_failure(state: &AppState, subjects: &[&str]) -> AppResult<()> {
    let now = now();
    for subject in subjects {
        state.db.add_attempt(subject, now).await?;
    }
    Ok(())
}

// For calls made while signed in that ask for the password again.
pub async fn confirm_password(state: &AppState, user: &User, auth_key: &Bytes) -> AppResult<()> {
    check_key(auth_key)?;
    let subject = account_subject(&user.email);
    check_limit(state, &subject, state.config.rate.per_account).await?;
    if key_matches(state, auth_key, &user.auth_salt, &user.auth_hash).await? {
        return Ok(());
    }
    note_failure(state, &[&subject]).await?;
    Err(AppError::invalid_credentials())
}

pub async fn signed_in_user(state: &AppState, session: &Session) -> AppResult<User> {
    state.db.user_by_id(&session.user_id).await?.ok_or_else(AppError::unauthorized)
}

pub async fn open_session(state: &AppState, user_id: &str, device: Device) -> AppResult<(String, SessionRow)> {
    let token = crypto::new_token();
    let now = now();
    let row = SessionRow {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        device_name: device.name,
        device_os: device.os,
        created_at: now,
        last_seen_at: now,
        expires_at: now + SESSION_SLIDE_SECS,
    };
    state.db.insert_session(&row, &crypto::sha256_hex(token.as_bytes())).await?;
    Ok((token, row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_trimmed_and_lowercased_and_junk_is_refused() {
        assert_eq!(normalize_email("  Ada@Example.COM ").unwrap(), "ada@example.com");
        assert!(normalize_email("ada").is_err());
        assert!(normalize_email("@example.com").is_err());
        assert!(normalize_email("ada@").is_err());
        assert!(normalize_email("ada lovelace@example.com").is_err());
        assert!(normalize_email("ada@example.com\nbcc: x@y.z").is_err());
    }
}
