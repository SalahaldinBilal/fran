use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Method, RequestBuilder, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sync_proto::{
    API_PREFIX, AccountInfo, AdminInvite, AdminLogEntry, AdminOverview, AdminUserDetail, AdminUsersPage, ApiError, ChangePassword, ChangeRecovery,
    ClaimServer, CreateAccount, CreateInvite, CreatedInvite, DeleteAccount, ErrorCode, Event, KdfParams, KdfRequest, PROTOCOL_HEADER, PROTOCOL_VERSION,
    PushRequest, PushResponse, RecordsPage, RecoveryFinish, RecoveryStart, RecoveryStarted, Role, ServerInfo, ServerSettings, SessionInfo, SetQuota,
    SetRole, SignIn, SignedIn, TotpRequest, TotpState, TransferOwnership, UpdateSettings,
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::error::{AppError, AppResult, ErrorDetail};

const TIMEOUT: Duration = Duration::from_secs(30);
// A push can carry a whole account.
const RECORDS_TIMEOUT: Duration = Duration::from_secs(300);

/// The address as typed into one form: no trailing slash, https unless `http://` was typed out.
/// Plain http is for testing only, and the add form warns before it's used.
pub fn checked_url(typed: &str) -> AppResult<String> {
    let typed = typed.trim();
    let with_scheme = if typed.contains("://") { typed.to_string() } else { format!("https://{typed}") };
    let url = Url::parse(&with_scheme).map_err(|_| AppError::general("That isn't a server address"))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(AppError::general("A sync server address starts with https://"));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(AppError::general("That isn't a server address"));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn api_error(status: StatusCode, body: &str) -> AppError {
    let Ok(error) = serde_json::from_str::<ApiError>(body) else {
        return AppError::general(format!("The sync server answered with HTTP {status}"));
    };
    match error.code {
        ErrorCode::Unauthorized => AppError::new("This computer is signed out of that cloud. Sign in again.", ErrorDetail::SyncSignedOut),
        ErrorCode::TotpRequired => AppError::new("Enter the code from your authenticator app", ErrorDetail::SyncCodeRequired),
        ErrorCode::TotpInvalid => AppError::new("That code isn't right", ErrorDetail::SyncCodeRequired),
        ErrorCode::RateLimited => match error.retry_after_secs {
            Some(seconds) => AppError::general(format!("Too many attempts. Try again in {} minutes.", seconds.div_ceil(60).max(1))),
            None => AppError::general("Too many attempts. Try again later."),
        },
        ErrorCode::UnsupportedProtocol => AppError::general("This server speaks another version of sync. Update Fran or the server."),
        _ => AppError::general(error.message),
    }
}

/// Ids go into the path, so anything that could change which address is asked for is refused.
fn path_id(id: &str) -> AppResult<&str> {
    if id.is_empty() || !id.chars().all(|character| character.is_ascii_alphanumeric() || character == '-') {
        return Err(AppError::general("That isn't something this server knows"));
    }
    Ok(id)
}

/// Every request to a Fran sync server goes through here. It only ever carries ciphertext, wrapped keys and auth keys.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    pub fn new(url: &str) -> AppResult<Self> {
        let base = checked_url(url)?;
        let http = reqwest::Client::builder().timeout(TIMEOUT).build().map_err(|error| AppError::general(error.to_string()))?;
        Ok(Self { http, base })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http.request(method, format!("{}{API_PREFIX}{path}", self.base)).header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
    }

    async fn text(&self, request: RequestBuilder) -> AppResult<String> {
        let response = request.send().await.map_err(|error| {
            let reason = if error.is_timeout() { "it took too long to answer" } else { "it can't be reached" };
            AppError::general(format!("Couldn't sync with {}: {reason}", self.base))
        })?;
        let status = response.status();
        let body = response.text().await.map_err(|_| AppError::general("The sync server's answer was cut off"))?;
        if status.is_success() { Ok(body) } else { Err(api_error(status, &body)) }
    }

    async fn send<T: DeserializeOwned>(&self, request: RequestBuilder) -> AppResult<T> {
        let body = self.text(request).await?;
        serde_json::from_str(&body).map_err(|_| AppError::general("The sync server sent an answer this app can't read"))
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, token: Option<&str>, body: &B) -> AppResult<T> {
        let request = self.request(Method::POST, path).json(body);
        self.send(match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        })
        .await
    }

    pub async fn info(&self) -> AppResult<ServerInfo> {
        let info: ServerInfo = self.send(self.request(Method::GET, "/info")).await?;
        if info.protocol_version != PROTOCOL_VERSION {
            return Err(AppError::general("This server speaks another version of sync. Update Fran or the server."));
        }
        Ok(info)
    }

    pub async fn kdf(&self, email: &str) -> AppResult<KdfParams> {
        self.post("/kdf", None, &KdfRequest { email: email.to_string() }).await
    }

    pub async fn create_account(&self, account: &CreateAccount) -> AppResult<SignedIn> {
        self.post("/accounts", None, account).await
    }

    pub async fn sign_in(&self, sign_in: &SignIn) -> AppResult<SignedIn> {
        self.post("/sessions", None, sign_in).await
    }

    pub async fn recovery_start(&self, start: &RecoveryStart) -> AppResult<RecoveryStarted> {
        self.post("/recovery/start", None, start).await
    }

    pub async fn recovery_finish(&self, finish: &RecoveryFinish) -> AppResult<SignedIn> {
        self.post("/recovery/finish", None, finish).await
    }

    pub async fn account(&self, token: &str) -> AppResult<AccountInfo> {
        self.send(self.request(Method::GET, "/account").bearer_auth(token)).await
    }

    pub async fn sessions(&self, token: &str) -> AppResult<Vec<SessionInfo>> {
        self.send(self.request(Method::GET, "/sessions").bearer_auth(token)).await
    }

    pub async fn sign_out(&self, token: &str) -> AppResult<()> {
        self.text(self.request(Method::DELETE, "/sessions/current").bearer_auth(token)).await.map(drop)
    }

    pub async fn revoke(&self, token: &str, session_id: &str) -> AppResult<()> {
        if !session_id.chars().all(|character| character.is_ascii_alphanumeric() || character == '-') {
            return Err(AppError::general("That isn't a device this cloud knows"));
        }
        self.text(self.request(Method::DELETE, &format!("/sessions/{session_id}")).bearer_auth(token)).await.map(drop)
    }

    pub async fn change_password(&self, token: &str, change: &ChangePassword) -> AppResult<()> {
        self.text(self.request(Method::PUT, "/account/password").bearer_auth(token).json(change)).await.map(drop)
    }

    pub async fn change_recovery(&self, token: &str, change: &ChangeRecovery) -> AppResult<()> {
        self.text(self.request(Method::PUT, "/account/recovery").bearer_auth(token).json(change)).await.map(drop)
    }

    pub async fn totp(&self, token: &str, request: &TotpRequest) -> AppResult<TotpState> {
        self.post("/account/totp", Some(token), request).await
    }

    pub async fn delete_account(&self, token: &str, request: &DeleteAccount) -> AppResult<()> {
        self.text(self.request(Method::DELETE, "/account").bearer_auth(token).json(request)).await.map(drop)
    }

    pub async fn pull(&self, token: &str, since: u64) -> AppResult<RecordsPage> {
        self.send(self.request(Method::GET, &format!("/records?since={since}")).bearer_auth(token).timeout(RECORDS_TIMEOUT)).await
    }

    pub async fn push(&self, token: &str, request: &PushRequest) -> AppResult<PushResponse> {
        self.send(self.request(Method::POST, "/records").bearer_auth(token).timeout(RECORDS_TIMEOUT).json(request)).await
    }

    async fn get<T: DeserializeOwned>(&self, token: &str, path: &str) -> AppResult<T> {
        self.send(self.request(Method::GET, path).bearer_auth(token)).await
    }

    async fn call<B: Serialize>(&self, method: Method, token: &str, path: &str, body: Option<&B>) -> AppResult<()> {
        let request = self.request(method, path).bearer_auth(token);
        self.text(match body {
            Some(body) => request.json(body),
            None => request,
        })
        .await
        .map(drop)
    }

    pub async fn claim(&self, token: &str, code: &str) -> AppResult<()> {
        self.call(Method::POST, token, "/admin/claim", Some(&ClaimServer { code: code.to_string() })).await
    }

    pub async fn admin_overview(&self, token: &str) -> AppResult<AdminOverview> {
        self.get(token, "/admin/overview").await
    }

    pub async fn admin_users(&self, token: &str, search: &str, offset: usize, limit: usize) -> AppResult<AdminUsersPage> {
        let address = Url::parse_with_params(
            &format!("{}{API_PREFIX}/admin/users", self.base),
            [("search", search.to_string()), ("offset", offset.to_string()), ("limit", limit.to_string())],
        )
        .map_err(|_| AppError::general("That search can't be sent"))?;
        let request = self.http.get(address).header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string()).bearer_auth(token);
        self.send(request).await
    }

    pub async fn admin_user(&self, token: &str, user_id: &str) -> AppResult<AdminUserDetail> {
        self.get(token, &format!("/admin/users/{}", path_id(user_id)?)).await
    }

    pub async fn admin_set_quota(&self, token: &str, user_id: &str, quota_bytes: u64) -> AppResult<()> {
        self.call(Method::PUT, token, &format!("/admin/users/{}/quota", path_id(user_id)?), Some(&SetQuota { quota_bytes })).await
    }

    pub async fn admin_set_role(&self, token: &str, user_id: &str, role: Role) -> AppResult<()> {
        self.call(Method::PUT, token, &format!("/admin/users/{}/role", path_id(user_id)?), Some(&SetRole { role })).await
    }

    pub async fn admin_sign_out_user(&self, token: &str, user_id: &str) -> AppResult<()> {
        self.call::<()>(Method::DELETE, token, &format!("/admin/users/{}/sessions", path_id(user_id)?), None).await
    }

    pub async fn admin_delete_user(&self, token: &str, user_id: &str, request: &DeleteAccount) -> AppResult<()> {
        self.call(Method::DELETE, token, &format!("/admin/users/{}", path_id(user_id)?), Some(request)).await
    }

    pub async fn admin_transfer(&self, token: &str, request: &TransferOwnership) -> AppResult<()> {
        path_id(&request.to)?;
        self.call(Method::POST, token, "/admin/transfer", Some(request)).await
    }

    pub async fn admin_invites(&self, token: &str) -> AppResult<Vec<AdminInvite>> {
        self.get(token, "/admin/invites").await
    }

    pub async fn admin_create_invite(&self, token: &str, request: &CreateInvite) -> AppResult<CreatedInvite> {
        self.post("/admin/invites", Some(token), request).await
    }

    pub async fn admin_delete_invite(&self, token: &str, id: &str) -> AppResult<()> {
        self.call::<()>(Method::DELETE, token, &format!("/admin/invites/{}", path_id(id)?), None).await
    }

    pub async fn admin_settings(&self, token: &str) -> AppResult<ServerSettings> {
        self.get(token, "/admin/settings").await
    }

    pub async fn admin_update_settings(&self, token: &str, update: &UpdateSettings) -> AppResult<ServerSettings> {
        self.send(self.request(Method::PUT, "/admin/settings").bearer_auth(token).json(update)).await
    }

    pub async fn admin_log(&self, token: &str) -> AppResult<Vec<AdminLogEntry>> {
        self.get(token, "/admin/log").await
    }

    /// The server only ever sends cursors here. Each one means "pull".
    pub async fn events(&self, token: &str) -> AppResult<mpsc::Receiver<()>> {
        let address = format!("{}{API_PREFIX}/events", self.base.replacen("http", "ws", 1));
        let unreachable = |_| AppError::general(format!("Couldn't open the live connection to {}", self.base));
        let mut request = address.into_client_request().map_err(unreachable)?;
        let bearer = format!("Bearer {token}").parse().map_err(|_| AppError::general("The saved session for this cloud is damaged"))?;
        request.headers_mut().insert("authorization", bearer);
        request.headers_mut().insert(PROTOCOL_HEADER, PROTOCOL_VERSION.into());
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.map_err(unreachable)?;

        let (sender, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(Ok(message)) = socket.next().await {
                let changed = match message {
                    Message::Text(text) => serde_json::from_str::<Event>(text.as_str()).is_ok(),
                    Message::Close(_) => break,
                    _ => false,
                };
                // A full channel already has a pull waiting.
                if changed && matches!(sender.try_send(()), Err(mpsc::error::TrySendError::Closed(()))) {
                    break;
                }
            }
        });
        Ok(receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_unless_http_is_typed_out() {
        assert_eq!(checked_url("sync.example.com").unwrap(), "https://sync.example.com");
        assert_eq!(checked_url("192.168.1.10:8787").unwrap(), "https://192.168.1.10:8787");
        assert_eq!(checked_url(" https://sync.example.com/fran/ ").unwrap(), "https://sync.example.com/fran");
        assert_eq!(checked_url("http://127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(checked_url("http://192.168.1.10:8787/").unwrap(), "http://192.168.1.10:8787");

        for refused in [
            "ftp://sync.example.com",
            "ws://sync.example.com",
            "https://user:secret@sync.example.com",
            "https://sync.example.com/?next=1",
            "",
        ] {
            assert!(checked_url(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_revoked_session_and_a_wanted_code_are_told_apart_from_other_errors() {
        let signed_out = api_error(StatusCode::UNAUTHORIZED, r#"{"code":"unauthorized","message":"Sign in again"}"#);
        assert!(matches!(signed_out.detail, ErrorDetail::SyncSignedOut));
        let code = api_error(StatusCode::UNAUTHORIZED, r#"{"code":"totpRequired","message":"A code is needed"}"#);
        assert!(matches!(code.detail, ErrorDetail::SyncCodeRequired));
        let limited = api_error(StatusCode::TOO_MANY_REQUESTS, r#"{"code":"rateLimited","message":"Slow down","retryAfterSecs":840}"#);
        assert!(limited.message.contains("14 minutes"), "{}", limited.message);
        let proxy_page = api_error(StatusCode::BAD_GATEWAY, "<html>502</html>");
        assert!(proxy_page.message.contains("502"), "{}", proxy_page.message);
    }
}
