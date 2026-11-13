use std::fmt::Display;

use serde::Serialize;

use crate::connections::SecretSlot;
use crate::ssh::{HopPosition, HostKeyInfo};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub message: String,
    pub detail: ErrorDetail,
    /// The failed connect used a secret whose value lives in a cloud, so fetching it again may help.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub linked_secret: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ErrorDetail {
    General,
    NotFound,
    Vault,
    /// The app lock is on and the vault hasn't been unlocked with the password yet.
    AppLocked,
    /// The user closed the OS prompt that confirms it's them.
    OsAuthCancelled,
    /// The OS has nothing to check against, so the app lock password is asked for instead.
    LockPasswordRequired,
    /// Linux: polkit doesn't know Fran's action yet. `canInstall` says whether pkexec can add it.
    #[serde(rename_all = "camelCase")]
    OsAuthSetup { can_install: bool },
    Ssh,
    /// A cloud no longer accepts this computer's session.
    SyncSignedOut,
    /// The cloud account has two-step sign-in on and wants a code.
    SyncCodeRequired,
    #[serde(rename_all = "camelCase")]
    Database {
        code: Option<u16>,
        sql_state: Option<String>,
    },
    SecretsRequired {
        slots: Vec<SecretSlot>,
    },
    #[serde(rename_all = "camelCase")]
    UnknownHostKey {
        key: HostKeyInfo,
        hop: Option<HopPosition>,
        /// OpenSSH's own known_hosts already has this key.
        openssh_trusted: bool,
    },
    #[serde(rename_all = "camelCase")]
    HostKeyChanged {
        key: HostKeyInfo,
        known_fingerprint: String,
        known_algorithm: String,
        known_added: Option<i64>,
        hop: Option<HopPosition>,
    },
}

impl AppError {
    pub fn new(message: impl Into<String>, detail: ErrorDetail) -> Self {
        Self {
            message: message.into(),
            detail,
            linked_secret: false,
        }
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(message, ErrorDetail::General)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(message, ErrorDetail::NotFound)
    }

    pub fn vault(message: impl Into<String>) -> Self {
        Self::new(message, ErrorDetail::Vault)
    }

    pub fn app_locked() -> Self {
        Self::new("Fran is locked. Unlock it to use saved passwords and keys.", ErrorDetail::AppLocked)
    }

    pub fn ssh(message: impl Into<String>) -> Self {
        Self::new(message, ErrorDetail::Ssh)
    }

    pub fn secrets_required(slots: Vec<SecretSlot>) -> Self {
        let names = slots
            .iter()
            .map(|slot| slot.label.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Self::new(
            format!("Missing credentials: {names}"),
            ErrorDetail::SecretsRequired { slots },
        )
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::general(error.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::general(error.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
