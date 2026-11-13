use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use sync_proto::{CreateAccount, Role, SignedIn, SignupMode};

use super::new_account_kdf;
use crate::auth::{ApiJson, ClientIp, check_device, check_key, check_limit, check_wrapped, hash_key, normalize_email, open_session};
use crate::crypto::{self, AUTH_SALT_LEN};
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::store::{InsertUser, InviteRule, NewUser};

pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(request): ApiJson<CreateAccount>,
) -> AppResult<(StatusCode, Json<SignedIn>)> {
    let email = normalize_email(&request.email)?;
    check_key(&request.auth_key)?;
    check_key(&request.recovery_auth_key)?;
    check_wrapped(&request.wrapped_data_key)?;
    check_wrapped(&request.recovery_wrapped_data_key)?;
    let device = check_device(&request.device)?;

    let now = now();
    let subject = format!("signup:{ip}");
    check_limit(&state, &subject, state.config.rate.signups_per_ip).await?;
    state.db.add_attempt(&subject, now).await?;

    // While nobody owns the server, the code it printed at start makes the first account its owner, whatever the sign-up mode.
    let typed = request.invite.as_deref().filter(|code| !code.trim().is_empty());
    let claims = matches!((typed, state.setup_code()), (Some(typed), Some(code)) if crypto::same_setup_code(typed, &code));
    let code_hash = typed.filter(|_| !claims).map(crypto::invite_hash);
    let invite = match (claims, state.settings().signup, code_hash.as_deref()) {
        (true, _, _) | (false, SignupMode::Open, _) => InviteRule::NotNeeded,
        (false, SignupMode::Invite, Some(hash)) => InviteRule::Any(hash),
        (false, SignupMode::Invite, None) => return Err(AppError::invalid_invite()),
        // A closed server still takes the accounts its admin made room for with `users create`.
        (false, SignupMode::Closed, Some(hash)) => InviteRule::ForThisEmail(hash),
        (false, SignupMode::Closed, None) => return Err(AppError::signup_closed()),
    };

    let auth_salt = crypto::random::<AUTH_SALT_LEN>();
    let auth_hash = hash_key(&state, request.auth_key.as_slice(), &auth_salt).await?;
    let recovery_auth_salt = crypto::random::<AUTH_SALT_LEN>();
    let recovery_auth_hash = hash_key(&state, request.recovery_auth_key.as_slice(), &recovery_auth_salt).await?;
    let kdf = new_account_kdf(&state, &email);
    let user = NewUser {
        role: Role::User,
        email: &email,
        auth_hash: &auth_hash,
        auth_salt: &auth_salt,
        recovery_auth_hash: &recovery_auth_hash,
        recovery_auth_salt: &recovery_auth_salt,
        kdf_salt: kdf.salt.as_slice(),
        kdf_memory_kib: i64::from(kdf.memory_kib),
        kdf_passes: i64::from(kdf.passes),
        kdf_parallelism: i64::from(kdf.parallelism),
        wrapped_data_key: request.wrapped_data_key.as_slice(),
        recovery_wrapped_data_key: request.recovery_wrapped_data_key.as_slice(),
    };
    let account_id = match state.db.insert_user(&user, invite, now).await? {
        InsertUser::Created(id) => id,
        InsertUser::EmailTaken => return Err(AppError::email_taken()),
        InsertUser::InvalidInvite => return Err(AppError::invalid_invite()),
    };
    if claims && state.db.make_owner(&account_id).await? {
        state.drop_setup_code();
        state.db.add_log(&email, "claim", &email, "Signed up with the setup code", now).await?;
    }
    let (token, session) = open_session(&state, &account_id, device).await?;
    let signed_in = SignedIn {
        token,
        account_id,
        session_id: session.id,
        expires_at: session.expires_at,
        wrapped_data_key: request.wrapped_data_key,
    };
    Ok((StatusCode::CREATED, Json(signed_in)))
}
