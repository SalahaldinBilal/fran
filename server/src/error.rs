use axum::Json;
use axum::http::{HeaderValue, StatusCode, header::RETRY_AFTER};
use axum::response::{IntoResponse, Response};
use sync_proto::{ApiError, ErrorCode};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub body: ApiError,
}

impl AppError {
    fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self { status, body: ApiError { code, message: message.into(), retry_after_secs: None } }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, "Sign in again")
    }

    pub fn invalid_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials, "Wrong email or password")
    }

    pub fn totp_required() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::TotpRequired, "A code from the authenticator app is needed")
    }

    pub fn totp_invalid() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::TotpInvalid, "That code isn't right")
    }

    pub fn rate_limited(retry_after_secs: u64) -> Self {
        let mut error = Self::new(StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited, "Too many attempts, try again later");
        error.body.retry_after_secs = Some(retry_after_secs);
        error
    }

    pub fn signup_closed() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::SignupClosed, "This server doesn't take new accounts")
    }

    pub fn invalid_invite() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::InvalidInvite, "That invite isn't valid")
    }

    pub fn email_taken() -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::EmailTaken, "An account with that email already exists")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden, message)
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, "Not found")
    }

    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge, message)
    }

    pub fn unsupported_protocol() -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::UnsupportedProtocol, "This server speaks another protocol version")
    }

    // The detail goes to the server's log only, never to the client.
    pub fn internal(context: &str, detail: impl std::fmt::Display) -> Self {
        eprintln!("error: {context}: {detail}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, "The server ran into a problem")
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal("database", error)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let retry_after = self.body.retry_after_secs;
        let mut response = (self.status, Json(self.body)).into_response();
        if let Some(seconds) = retry_after {
            response.headers_mut().insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}
