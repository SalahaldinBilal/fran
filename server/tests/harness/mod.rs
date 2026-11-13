use std::net::SocketAddr;
use std::path::PathBuf;

use base64::Engine;
use fran_sync_server::config::{Config, RateLimits};
use fran_sync_server::state::AppState;
use fran_sync_server::{api, crypto, db};
use reqwest::{Response, StatusCode};
use serde_json::json;
use sqlx::{AnyPool, Row};
use sync_proto::{ApiError, Bytes, KdfParams, Limits, PushRecord, PushRequest, PushResponse, RecordsPage, SignedIn, SignupMode};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone, Copy)]
pub enum Backend {
    Sqlite,
    Mysql,
    Mariadb,
}

// A running server without a database name, like mysql://root:secret@127.0.0.1:3306. Each test makes its own database on it.
pub fn server_url(backend: Backend) -> Option<String> {
    let variable = match backend {
        Backend::Sqlite => return None,
        Backend::Mysql => "FRAN_SYNC_MYSQL_URL",
        Backend::Mariadb => "FRAN_SYNC_MARIADB_URL",
    };
    std::env::var(variable).ok().filter(|url| !url.is_empty())
}

pub fn skipped(backend: Backend) -> bool {
    let skipped = server_url(backend).is_none();
    if skipped {
        eprintln!("skipped: no server given for this database");
    }
    skipped
}

pub struct Account {
    pub id: String,
    pub email: String,
    pub token: String,
    pub session_id: String,
    pub auth_key: Vec<u8>,
    pub recovery_auth_key: Vec<u8>,
    pub wrapped_data_key: Vec<u8>,
    pub recovery_wrapped_data_key: Vec<u8>,
}

pub struct Server {
    pub http: reqwest::Client,
    address: SocketAddr,
    config: Config,
    state: AppState,
    task: JoinHandle<()>,
    sqlite_file: Option<PathBuf>,
}

pub fn key() -> Vec<u8> {
    crypto::random::<32>().to_vec()
}

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn record_id(number: u8) -> String {
    crypto::sha256_hex(&[number])
}

pub fn record(number: u8, base_revision: u64, ciphertext: &[u8]) -> PushRecord {
    PushRecord { id: record_id(number), base_revision, deleted: false, ciphertext: Bytes::from(ciphertext) }
}

pub fn base32_decoded(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for character in text.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'2'..=b'7' => character - b'2' + 26,
            _ => panic!("{text} isn't base32"),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    bytes
}

pub fn totp_step() -> i64 {
    db::now() / crypto::TOTP_STEP_SECS
}

pub fn code(secret: &[u8], step: i64) -> String {
    crypto::totp_code(secret, step)
}

pub fn wrong_code(secret: &[u8], step: i64) -> String {
    let near: Vec<String> = (step - 2..=step + 2).map(|step| code(secret, step)).collect();
    (0..10).map(|digit| digit.to_string().repeat(6)).find(|candidate| !near.contains(candidate)).unwrap()
}

pub async fn error_of(response: Response) -> (StatusCode, ApiError) {
    let status = response.status();
    let text = response.text().await.unwrap();
    let error = serde_json::from_str(&text).unwrap_or_else(|_| panic!("{status} didn't carry an API error: {text}"));
    (status, error)
}

async fn database_url(backend: Backend) -> (String, Option<PathBuf>) {
    let name = format!("fran_sync_test_{}", hex::encode(crypto::random::<8>()));
    match backend {
        Backend::Sqlite => {
            let file = std::env::temp_dir().join(format!("{name}.db"));
            (format!("sqlite:{}", file.to_string_lossy().replace('\\', "/")), Some(file))
        }
        Backend::Mysql | Backend::Mariadb => {
            let base = server_url(backend).expect("the env variable for this database");
            sqlx::any::install_default_drivers();
            let admin = AnyPool::connect(&base).await.expect("the database server for tests isn't reachable");
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
            admin.close().await;
            (format!("{}/{name}", base.trim_end_matches('/')), None)
        }
    }
}

pub async fn start(backend: Backend) -> Server {
    start_with(backend, |_| {}).await
}

pub async fn start_with(backend: Backend, change: impl FnOnce(&mut Config)) -> Server {
    let (database_url, sqlite_file) = database_url(backend).await;
    let mut config = Config {
        database_url,
        bind: "127.0.0.1:0".parse().unwrap(),
        public_url: None,
        signup: SignupMode::Open,
        server_key: crypto::random::<32>(),
        limits: Limits { record_bytes: 256 * 1024, account_bytes: 50 * 1024 * 1024, batch_records: 5000 },
        server_bytes: 0,
        rate: RateLimits { signups_per_ip: 1000, ..RateLimits::default() },
        tls: None,
        trust_proxy: false,
    };
    change(&mut config);
    serve(config, sqlite_file).await
}

async fn serve(config: Config, sqlite_file: Option<PathBuf>) -> Server {
    let state = AppState::new(config.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = api::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server { http: reqwest::Client::new(), address, config, state, task, sqlite_file }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(file) = &self.sqlite_file {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", file.to_string_lossy()));
            }
        }
    }
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}/v1{path}", self.address)
    }

    pub async fn restarted(mut self) -> Server {
        self.task.abort();
        self.state.db.close().await;
        serve(self.config.clone(), self.sqlite_file.take()).await
    }

    pub async fn get(&self, path: &str, token: &str) -> Response {
        self.http.get(self.url(path)).bearer_auth(token).send().await.unwrap()
    }

    pub async fn delete(&self, path: &str, token: &str) -> Response {
        self.http.delete(self.url(path)).bearer_auth(token).send().await.unwrap()
    }

    /// What the server would print at start while nobody owns it.
    pub fn setup_code(&self) -> Option<String> {
        self.state.setup_code()
    }

    pub async fn sign_up_with(&self, email: &str, invite: &str) -> Account {
        let (response, mut account) = self.create_account(email, Some(invite)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let signed_in: SignedIn = response.json().await.unwrap();
        account.id = signed_in.account_id;
        account.token = signed_in.token;
        account.session_id = signed_in.session_id;
        account
    }

    pub async fn post(&self, path: &str, token: &str, body: serde_json::Value) -> Response {
        self.http.post(self.url(path)).bearer_auth(token).json(&body).send().await.unwrap()
    }

    pub async fn put(&self, path: &str, token: &str, body: serde_json::Value) -> Response {
        self.http.put(self.url(path)).bearer_auth(token).json(&body).send().await.unwrap()
    }

    pub async fn delete_with(&self, path: &str, token: &str, body: serde_json::Value) -> Response {
        self.http.delete(self.url(path)).bearer_auth(token).json(&body).send().await.unwrap()
    }

    pub async fn kdf(&self, email: &str) -> KdfParams {
        self.http.post(self.url("/kdf")).json(&json!({ "email": email })).send().await.unwrap().json().await.unwrap()
    }

    pub async fn invite(&self, email: &str) -> String {
        let code = crypto::invite_code();
        self.state.db.insert_invite(&crypto::invite_hash(&code), email, db::now(), 0).await.unwrap();
        code
    }

    async fn create_account(&self, email: &str, invite: Option<&str>) -> (Response, Account) {
        let mut account = Account {
            id: String::new(),
            email: email.to_string(),
            token: String::new(),
            session_id: String::new(),
            auth_key: key(),
            recovery_auth_key: key(),
            wrapped_data_key: crypto::random::<72>().to_vec(),
            recovery_wrapped_data_key: crypto::random::<72>().to_vec(),
        };
        let body = json!({
            "email": email,
            "authKey": b64(&account.auth_key),
            "wrappedDataKey": b64(&account.wrapped_data_key),
            "recoveryAuthKey": b64(&account.recovery_auth_key),
            "recoveryWrappedDataKey": b64(&account.recovery_wrapped_data_key),
            "invite": invite,
            "device": { "name": "Ada's laptop", "os": "windows" },
        });
        let response = self.http.post(self.url("/accounts")).json(&body).send().await.unwrap();
        account.email = email.trim().to_lowercase();
        (response, account)
    }

    pub async fn try_sign_up(&self, email: &str, invite: Option<&str>) -> Response {
        self.create_account(email, invite).await.0
    }

    pub async fn sign_up(&self, email: &str) -> Account {
        let (response, mut account) = self.create_account(email, None).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let signed_in: SignedIn = response.json().await.unwrap();
        account.id = signed_in.account_id;
        account.token = signed_in.token;
        account.session_id = signed_in.session_id;
        account
    }

    pub async fn sign_in(&self, email: &str, auth_key: &[u8], totp: Option<&str>) -> Response {
        let body = json!({ "email": email, "authKey": b64(auth_key), "totp": totp, "device": { "name": "Ada's desktop", "os": "linux" } });
        self.http.post(self.url("/sessions")).json(&body).send().await.unwrap()
    }

    pub async fn failed_sign_in_from(&self, forwarded_for: &str) -> StatusCode {
        let body = json!({ "email": "nobody@example.com", "authKey": b64(&key()), "device": { "name": "Somewhere", "os": "linux" } });
        self.http.post(self.url("/sessions")).header("x-forwarded-for", forwarded_for).json(&body).send().await.unwrap().status()
    }

    // Changes rows directly, for things only time would do otherwise.
    pub async fn execute(&self, statement: String) {
        let pool = AnyPool::connect(&self.config.database_url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(statement)).execute(&pool).await.unwrap();
        pool.close().await;
    }

    pub async fn push_raw(&self, token: &str, records: Vec<PushRecord>) -> Response {
        self.http.post(self.url("/records")).bearer_auth(token).json(&PushRequest { records }).send().await.unwrap()
    }

    pub async fn push(&self, token: &str, records: Vec<PushRecord>) -> PushResponse {
        let response = self.push_raw(token, records).await;
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }

    pub async fn pull(&self, token: &str, since: u64, limit: Option<u64>) -> RecordsPage {
        let mut url = format!("{}?since={since}", self.url("/records"));
        if let Some(limit) = limit {
            url.push_str(&format!("&limit={limit}"));
        }
        let response = self.http.get(url).bearer_auth(token).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }

    pub async fn change_password(&self, token: &str, auth_key: &[u8], new_auth_key: &[u8], new_wrapped: &[u8]) -> Response {
        let body = json!({ "authKey": b64(auth_key), "newAuthKey": b64(new_auth_key), "newWrappedDataKey": b64(new_wrapped) });
        self.http.put(self.url("/account/password")).bearer_auth(token).json(&body).send().await.unwrap()
    }

    pub async fn recovery_start(&self, email: &str, recovery_auth_key: &[u8]) -> Response {
        let body = json!({ "email": email, "recoveryAuthKey": b64(recovery_auth_key) });
        self.http.post(self.url("/recovery/start")).json(&body).send().await.unwrap()
    }

    pub async fn recovery_finish(&self, email: &str, recovery_auth_key: &[u8], auth_key: &[u8], wrapped: &[u8]) -> Response {
        let body = json!({
            "email": email,
            "recoveryAuthKey": b64(recovery_auth_key),
            "authKey": b64(auth_key),
            "wrappedDataKey": b64(wrapped),
            "device": { "name": "Ada's new laptop", "os": "macos" },
        });
        self.http.post(self.url("/recovery/finish")).json(&body).send().await.unwrap()
    }

    pub async fn totp(&self, token: &str, body: serde_json::Value) -> Response {
        self.http.post(self.url("/account/totp")).bearer_auth(token).json(&body).send().await.unwrap()
    }

    pub async fn delete_account(&self, token: &str, auth_key: &[u8]) -> Response {
        self.http.delete(self.url("/account")).bearer_auth(token).json(&json!({ "authKey": b64(auth_key) })).send().await.unwrap()
    }

    pub async fn events(&self, token: &str) -> Result<Socket, StatusCode> {
        let mut request = format!("ws://{}/v1/events", self.address).into_client_request().unwrap();
        request.headers_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => Ok(socket),
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => Err(StatusCode::from_u16(response.status().as_u16()).unwrap()),
            Err(error) => panic!("the socket didn't connect: {error}"),
        }
    }

    // Reads straight from the database, past the API.
    pub async fn pairs(&self, query: &'static str) -> Vec<(String, String)> {
        let pool = AnyPool::connect(&self.config.database_url).await.unwrap();
        let rows = sqlx::query(query).fetch_all(&pool).await.unwrap();
        pool.close().await;
        let text = |row: &sqlx::any::AnyRow, index: usize| {
            row.try_get::<String, _>(index)
                .or_else(|_| row.try_get::<Vec<u8>, _>(index).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
                .unwrap()
        };
        rows.iter()
            .map(|row| (text(row, 0), if row.len() > 1 { text(row, 1) } else { String::new() }))
            .filter(|(table, _)| !table.starts_with("_sqlx") && !table.starts_with("sqlite_"))
            .collect()
    }

    pub async fn column(&self, query: &'static str) -> Vec<String> {
        self.pairs(query).await.into_iter().map(|(value, _)| value).collect()
    }
}
