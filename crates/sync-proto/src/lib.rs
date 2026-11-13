mod bytes;
mod error;

pub use bytes::Bytes;
pub use error::{ApiError, ErrorCode};

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const PROTOCOL_HEADER: &str = "x-fran-protocol";
pub const API_PREFIX: &str = "/v1";

pub const KEY_LEN: usize = 32;
pub const RECORD_ID_LEN: usize = 64;

pub fn is_record_id(id: &str) -> bool {
    id.len() == RECORD_ID_LEN && id.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignupMode {
    Open,
    Invite,
    Closed,
}

fn yes() -> bool {
    true
}

fn is_yes(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub version: String,
    pub protocol_version: u32,
    pub signup: SignupMode,
    pub instance_id: String,
    pub limits: Limits,
    /// Only sent, as false, while nobody has claimed the server.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub owned: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    #[default]
    User,
    Admin,
    Owner,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    pub fn is_admin(self) -> bool {
        self >= Self::Admin
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub record_bytes: u64,
    pub account_bytes: u64,
    pub batch_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfRequest {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub salt: Bytes,
    pub memory_kib: u32,
    pub passes: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub name: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccount {
    pub email: String,
    pub auth_key: Bytes,
    pub wrapped_data_key: Bytes,
    pub recovery_auth_key: Bytes,
    pub recovery_wrapped_data_key: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<String>,
    pub device: Device,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignIn {
    pub email: String,
    pub auth_key: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    pub device: Device,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedIn {
    pub token: String,
    pub account_id: String,
    pub session_id: String,
    pub expires_at: i64,
    pub wrapped_data_key: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub device: Device,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub id: String,
    pub email: String,
    pub totp_enabled: bool,
    pub used_bytes: u64,
    pub created_at: i64,
    #[serde(default)]
    pub role: Role,
    /// What this account may store, its own limit or the server's default.
    #[serde(default)]
    pub quota_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStart {
    pub email: String,
    pub recovery_auth_key: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStarted {
    pub recovery_wrapped_data_key: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryFinish {
    pub email: String,
    pub recovery_auth_key: Bytes,
    pub auth_key: Bytes,
    pub wrapped_data_key: Bytes,
    pub device: Device,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassword {
    pub auth_key: Bytes,
    pub new_auth_key: Bytes,
    pub new_wrapped_data_key: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRecovery {
    pub auth_key: Bytes,
    pub recovery_auth_key: Bytes,
    pub recovery_wrapped_data_key: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum TotpRequest {
    Begin,
    Confirm { code: String },
    #[serde(rename_all = "camelCase")]
    Disable { auth_key: Bytes },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpState {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccount {
    pub auth_key: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub id: String,
    pub revision: u64,
    pub deleted: bool,
    pub ciphertext: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordsPage {
    pub records: Vec<Record>,
    pub cursor: u64,
    pub more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushRecord {
    pub id: String,
    pub base_revision: u64,
    pub deleted: bool,
    pub ciphertext: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushRequest {
    pub records: Vec<PushRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PushStatus {
    Accepted,
    Conflict,
    TooLarge,
    QuotaExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResult {
    pub id: String,
    pub status: PushStatus,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResponse {
    pub results: Vec<PushResult>,
    pub cursor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    Changed { cursor: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimServer {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminOverview {
    pub version: String,
    pub started_at: i64,
    pub accounts: u64,
    pub used_bytes: u64,
    /// 0 when the server has no total limit.
    pub server_bytes: u64,
    pub signup: SignupMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub role: Role,
    pub used_bytes: u64,
    /// 0 when the account follows the server's default.
    pub own_quota_bytes: u64,
    pub quota_bytes: u64,
    pub created_at: i64,
    pub totp_enabled: bool,
    pub devices: u64,
    /// 0 when no device is signed in.
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUsersPage {
    pub users: Vec<AdminUser>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserDetail {
    pub user: AdminUser,
    pub sessions: Vec<SessionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetQuota {
    /// 0 puts the account back on the server's default.
    pub quota_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRole {
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferOwnership {
    pub to: String,
    pub auth_key: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminInvite {
    /// The hash of the code. The code itself is only shown once.
    pub id: String,
    pub email: String,
    pub created_at: i64,
    /// 0 when it never expires.
    pub expires_at: i64,
    /// 0 while unused.
    pub used_at: i64,
    pub used_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvite {
    #[serde(default)]
    pub email: String,
    /// 0 for an invite that never expires.
    #[serde(default)]
    pub expires_in_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedInvite {
    pub code: String,
    pub invite: AdminInvite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSettings {
    pub signup: SignupMode,
    pub account_bytes: u64,
    pub record_bytes: u64,
    pub batch_records: u64,
    /// 0 for no total limit.
    pub server_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signup: Option<SignupMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_records: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminLogEntry {
    pub id: String,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_ids_are_lowercase_hex_of_a_sha256() {
        assert!(is_record_id(&"0f".repeat(32)));
        assert!(!is_record_id(&"0F".repeat(32)));
        assert!(!is_record_id(&"0f".repeat(31)));
        assert!(!is_record_id("../../etc/passwd"));
    }

    #[test]
    fn bytes_refuse_text_that_is_not_base64() {
        let parsed: Result<Record, _> =
            serde_json::from_str(r#"{"id":"a","revision":1,"deleted":false,"ciphertext":"not base64!"}"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn debug_output_never_holds_key_bytes() {
        let request = DeleteAccount { auth_key: Bytes::from(vec![0xAB; 32]) };
        let shown = format!("{request:?}");
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("ab, "));
    }
}
