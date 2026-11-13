mod account;
mod accounts;
mod admin;
mod events;
mod records;
mod sessions;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use sync_proto::{API_PREFIX, KdfParams, KdfRequest, Limits, PROTOCOL_HEADER, PROTOCOL_VERSION, ServerInfo};

use crate::auth::{ApiJson, normalize_email};
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const SMALL_BODY_BYTES: usize = 64 * 1024;

pub const KDF_MEMORY_KIB: u32 = 64 * 1024;
pub const KDF_PASSES: u32 = 3;
pub const KDF_PARALLELISM: u32 = 1;

// Base64 makes the ciphertext a third bigger, and each record carries its id and revision.
pub fn push_body_bytes(limits: &Limits) -> usize {
    (limits.account_bytes / 3 * 4 + limits.batch_records * 256) as usize + SMALL_BODY_BYTES
}

async fn check_protocol(request: Request, next: Next) -> Response {
    if let Some(value) = request.headers().get(PROTOCOL_HEADER) {
        let version = value.to_str().ok().and_then(|text| text.trim().parse::<u32>().ok());
        if version != Some(PROTOCOL_VERSION) {
            return AppError::unsupported_protocol().into_response();
        }
    }
    next.run(request).await
}

async fn info(State(state): State<AppState>) -> Json<ServerInfo> {
    let settings = state.settings();
    Json(ServerInfo {
        version: crate::VERSION.to_string(),
        protocol_version: PROTOCOL_VERSION,
        signup: settings.signup,
        instance_id: state.instance_id.clone(),
        limits: settings.limits,
        owned: state.setup_code().is_none(),
    })
}

pub fn new_account_kdf(state: &AppState, email: &str) -> KdfParams {
    KdfParams {
        salt: crypto::kdf_salt(&state.config.server_key, email).to_vec().into(),
        memory_kib: KDF_MEMORY_KIB,
        passes: KDF_PASSES,
        parallelism: KDF_PARALLELISM,
    }
}

async fn kdf(State(state): State<AppState>, ApiJson(request): ApiJson<KdfRequest>) -> AppResult<Json<KdfParams>> {
    let email = normalize_email(&request.email)?;
    let params = match state.db.user_by_email(&email).await? {
        Some(user) => KdfParams {
            salt: user.kdf_salt.into(),
            memory_kib: user.kdf_memory_kib as u32,
            passes: user.kdf_passes as u32,
            parallelism: user.kdf_parallelism as u32,
        },
        None => new_account_kdf(&state, &email),
    };
    Ok(Json(params))
}

pub fn router(state: AppState) -> Router {
    let small = Router::new()
        .route("/info", get(info))
        .route("/kdf", post(kdf))
        .route("/accounts", post(accounts::create))
        .route("/sessions", post(sessions::sign_in).get(sessions::list))
        .route("/sessions/current", delete(sessions::sign_out))
        .route("/sessions/{id}", delete(sessions::revoke))
        .route("/recovery/start", post(sessions::recovery_start))
        .route("/recovery/finish", post(sessions::recovery_finish))
        .route("/account", get(account::info).delete(account::delete))
        .route("/account/password", put(account::change_password))
        .route("/account/recovery", put(account::change_recovery))
        .route("/account/totp", post(account::totp))
        .route("/events", get(events::connect))
        .route("/admin/claim", post(admin::claim))
        .route("/admin/overview", get(admin::overview))
        .route("/admin/users", get(admin::users))
        .route("/admin/users/{id}", get(admin::user).delete(admin::delete_user))
        .route("/admin/users/{id}/quota", put(admin::set_quota))
        .route("/admin/users/{id}/role", put(admin::set_role))
        .route("/admin/users/{id}/sessions", delete(admin::sign_out_user))
        .route("/admin/transfer", post(admin::transfer))
        .route("/admin/invites", get(admin::invites).post(admin::create_invite))
        .route("/admin/invites/{id}", delete(admin::delete_invite))
        .route("/admin/settings", get(admin::settings).put(admin::update_settings))
        .route("/admin/log", get(admin::log_entries))
        .layer(DefaultBodyLimit::max(SMALL_BODY_BYTES));
    // The push reads its own body, limited by what that account may store, since limits change at run time.
    let records = Router::new().route("/records", get(records::pull).post(records::push)).layer(DefaultBodyLimit::disable());
    Router::new().nest(API_PREFIX, small.merge(records)).layer(middleware::from_fn(check_protocol)).with_state(state)
}
