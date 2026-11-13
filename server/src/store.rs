use std::collections::HashMap;

use sqlx::Row;
use sqlx::any::AnyRow;
use sync_proto::{Limits, PushRecord, PushResult, PushStatus, Record, Role};
use uuid::Uuid;

use crate::db::Db;

pub struct User {
    pub id: String,
    pub email: String,
    pub auth_hash: Vec<u8>,
    pub auth_salt: Vec<u8>,
    pub recovery_auth_hash: Vec<u8>,
    pub recovery_auth_salt: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_memory_kib: i64,
    pub kdf_passes: i64,
    pub kdf_parallelism: i64,
    pub wrapped_data_key: Vec<u8>,
    pub recovery_wrapped_data_key: Vec<u8>,
    pub totp_secret: Vec<u8>,
    pub totp_enabled: bool,
    pub totp_last_step: i64,
    pub change_seq: i64,
    pub used_bytes: i64,
    pub created_at: i64,
    pub role: Role,
    /// 0 when the account follows the server's default.
    pub quota_bytes: i64,
}

pub struct NewUser<'a> {
    pub role: Role,
    pub email: &'a str,
    pub auth_hash: &'a [u8],
    pub auth_salt: &'a [u8],
    pub recovery_auth_hash: &'a [u8],
    pub recovery_auth_salt: &'a [u8],
    pub kdf_salt: &'a [u8],
    pub kdf_memory_kib: i64,
    pub kdf_passes: i64,
    pub kdf_parallelism: i64,
    pub wrapped_data_key: &'a [u8],
    pub recovery_wrapped_data_key: &'a [u8],
}

pub enum InsertUser {
    Created(String),
    EmailTaken,
    InvalidInvite,
}

// What an invite has to be for a sign-up to go through.
pub enum InviteRule<'a> {
    NotNeeded,
    Any(&'a str),
    ForThisEmail(&'a str),
}

pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub device_name: String,
    pub device_os: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
}

pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub role: Role,
    pub used_bytes: i64,
    pub quota_bytes: i64,
    pub totp_enabled: bool,
    pub created_at: i64,
}

#[derive(Default, Clone, Copy)]
pub struct DeviceStats {
    pub devices: i64,
    pub last_seen_at: i64,
}

pub struct InviteRow {
    pub code_hash: String,
    pub email: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: i64,
    pub used_by: String,
}

pub struct LogRow {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: i64,
}

pub struct Pulled {
    pub records: Vec<Record>,
    pub cursor: u64,
    pub more: bool,
}

pub struct Pushed {
    pub results: Vec<PushResult>,
    pub cursor: u64,
    pub changed: bool,
}

macro_rules! select_user {
    ($tail:literal) => {
        concat!(
            "SELECT id, email, auth_hash, auth_salt, recovery_auth_hash, recovery_auth_salt, kdf_salt, kdf_memory_kib, ",
            "kdf_passes, kdf_parallelism, wrapped_data_key, recovery_wrapped_data_key, totp_secret, totp_enabled, ",
            "totp_last_step, change_seq, used_bytes, created_at, role, quota_bytes FROM users ",
            $tail
        )
    };
}

macro_rules! select_session {
    ($tail:literal) => {
        concat!("SELECT id, user_id, device_name, device_os, created_at, last_seen_at, expires_at FROM sessions ", $tail)
    };
}

fn user_from(row: &AnyRow) -> sqlx::Result<User> {
    Ok(User {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        auth_hash: row.try_get("auth_hash")?,
        auth_salt: row.try_get("auth_salt")?,
        recovery_auth_hash: row.try_get("recovery_auth_hash")?,
        recovery_auth_salt: row.try_get("recovery_auth_salt")?,
        kdf_salt: row.try_get("kdf_salt")?,
        kdf_memory_kib: row.try_get("kdf_memory_kib")?,
        kdf_passes: row.try_get("kdf_passes")?,
        kdf_parallelism: row.try_get("kdf_parallelism")?,
        wrapped_data_key: row.try_get("wrapped_data_key")?,
        recovery_wrapped_data_key: row.try_get("recovery_wrapped_data_key")?,
        totp_secret: row.try_get("totp_secret")?,
        totp_enabled: row.try_get::<i64, _>("totp_enabled")? != 0,
        totp_last_step: row.try_get("totp_last_step")?,
        change_seq: row.try_get("change_seq")?,
        used_bytes: row.try_get("used_bytes")?,
        created_at: row.try_get("created_at")?,
        role: role_from(row)?,
        quota_bytes: row.try_get("quota_bytes")?,
    })
}

fn role_from(row: &AnyRow) -> sqlx::Result<Role> {
    let text: String = row.try_get("role")?;
    Role::parse(&text).ok_or_else(|| sqlx::Error::Decode(format!("unknown role {text}").into()))
}

fn session_from(row: &AnyRow) -> sqlx::Result<SessionRow> {
    Ok(SessionRow {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        device_name: row.try_get("device_name")?,
        device_os: row.try_get("device_os")?,
        created_at: row.try_get("created_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| database.is_unique_violation())
}

impl Db {
    pub async fn instance_id(&self) -> sqlx::Result<String> {
        let read = "SELECT value FROM meta WHERE name = 'instance_id'";
        if let Some(row) = sqlx::query(read).fetch_optional(&self.pool).await? {
            return row.try_get("value");
        }
        let id = Uuid::new_v4().to_string();
        match sqlx::query("INSERT INTO meta (name, value) VALUES ('instance_id', ?)").bind(&id).execute(&self.pool).await {
            Ok(_) => Ok(id),
            // Another server process on the same database got there first.
            Err(error) if is_unique_violation(&error) => sqlx::query(read).fetch_one(&self.pool).await?.try_get("value"),
            Err(error) => Err(error),
        }
    }

    pub async fn user_by_email(&self, email: &str) -> sqlx::Result<Option<User>> {
        let row = sqlx::query(select_user!("WHERE email = ?")).bind(email).fetch_optional(&self.pool).await?;
        row.as_ref().map(user_from).transpose()
    }

    pub async fn user_by_id(&self, id: &str) -> sqlx::Result<Option<User>> {
        let row = sqlx::query(select_user!("WHERE id = ?")).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(user_from).transpose()
    }

    pub async fn list_users(&self) -> sqlx::Result<Vec<UserSummary>> {
        let rows = sqlx::query("SELECT id, email, role, used_bytes, quota_bytes, totp_enabled, created_at FROM users ORDER BY email")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(UserSummary {
                    id: row.try_get("id")?,
                    email: row.try_get("email")?,
                    role: role_from(row)?,
                    used_bytes: row.try_get("used_bytes")?,
                    quota_bytes: row.try_get("quota_bytes")?,
                    totp_enabled: row.try_get::<i64, _>("totp_enabled")? != 0,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn device_stats(&self, now: i64) -> sqlx::Result<HashMap<String, DeviceStats>> {
        let rows = sqlx::query("SELECT user_id, last_seen_at FROM sessions WHERE expires_at > ?").bind(now).fetch_all(&self.pool).await?;
        let mut stats: HashMap<String, DeviceStats> = HashMap::new();
        for row in &rows {
            let entry = stats.entry(row.try_get("user_id")?).or_default();
            entry.devices += 1;
            entry.last_seen_at = entry.last_seen_at.max(row.try_get("last_seen_at")?);
        }
        Ok(stats)
    }

    pub async fn has_owner(&self) -> sqlx::Result<bool> {
        Ok(sqlx::query("SELECT id FROM users WHERE role = 'owner' LIMIT 1").fetch_optional(&self.pool).await?.is_some())
    }

    /// Every account's storage added up. Done here since MySQL's SUM comes back as a DECIMAL the `Any` driver can't read.
    pub async fn total_used(&self) -> sqlx::Result<u64> {
        let rows = sqlx::query("SELECT used_bytes FROM users").fetch_all(&self.pool).await?;
        rows.iter().try_fold(0u64, |total, row| Ok(total + row.try_get::<i64, _>("used_bytes")?.max(0) as u64))
    }

    /// False when the server already has an owner. A write on the instance id row comes first, so two claims at once can't both win.
    pub async fn make_owner(&self, user_id: &str) -> sqlx::Result<bool> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("UPDATE meta SET value = value WHERE name = 'instance_id'").execute(&mut *transaction).await?;
        if sqlx::query("SELECT id FROM users WHERE role = 'owner' LIMIT 1").fetch_optional(&mut *transaction).await?.is_some() {
            return Ok(false);
        }
        sqlx::query("UPDATE users SET role = 'owner' WHERE id = ?").bind(user_id).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn set_role(&self, user_id: &str, role: Role) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET role = ? WHERE id = ?").bind(role.as_str()).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    /// The old owner becomes an admin in the same step, so there's never zero or two owners.
    pub async fn transfer_owner(&self, to: &str) -> sqlx::Result<()> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("UPDATE users SET role = 'admin' WHERE role = 'owner'").execute(&mut *transaction).await?;
        sqlx::query("UPDATE users SET role = 'owner' WHERE id = ?").bind(to).execute(&mut *transaction).await?;
        transaction.commit().await
    }

    pub async fn set_quota(&self, user_id: &str, quota_bytes: i64) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET quota_bytes = ? WHERE id = ?").bind(quota_bytes).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn saved_settings(&self) -> sqlx::Result<HashMap<String, String>> {
        let rows = sqlx::query("SELECT name, value FROM settings").fetch_all(&self.pool).await?;
        rows.iter().map(|row| Ok((row.try_get("name")?, row.try_get("value")?))).collect()
    }

    /// No upserts, they're written differently on each database. A delete and an insert in one transaction do the same.
    pub async fn save_settings(&self, rows: &[(&str, String)]) -> sqlx::Result<()> {
        let mut transaction = self.pool.begin().await?;
        for (name, value) in rows {
            sqlx::query("DELETE FROM settings WHERE name = ?").bind(*name).execute(&mut *transaction).await?;
            sqlx::query("INSERT INTO settings (name, value) VALUES (?, ?)").bind(*name).bind(value).execute(&mut *transaction).await?;
        }
        transaction.commit().await
    }

    pub async fn add_log(&self, actor: &str, action: &str, target: &str, detail: &str, now: i64) -> sqlx::Result<()> {
        // Starts with the time in nanoseconds, so entries from the same second still sort in the order they happened.
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|elapsed| elapsed.as_nanos()).unwrap_or(0);
        let id = format!("{nanos:020}{}", &Uuid::new_v4().simple().to_string()[..16]);
        sqlx::query("INSERT INTO admin_log (id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(actor)
            .bind(action)
            .bind(target)
            .bind(detail)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn log(&self, limit: i64) -> sqlx::Result<Vec<LogRow>> {
        let rows = sqlx::query("SELECT id, actor, action, target, detail, created_at FROM admin_log ORDER BY id DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(LogRow {
                    id: row.try_get("id")?,
                    actor: row.try_get("actor")?,
                    action: row.try_get("action")?,
                    target: row.try_get("target")?,
                    detail: row.try_get("detail")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn invites(&self) -> sqlx::Result<Vec<InviteRow>> {
        let rows = sqlx::query("SELECT code_hash, email, created_at, expires_at, used_at, used_by FROM invites ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(InviteRow {
                    code_hash: row.try_get("code_hash")?,
                    email: row.try_get("email")?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                    used_at: row.try_get("used_at")?,
                    used_by: row.try_get("used_by")?,
                })
            })
            .collect()
    }

    pub async fn delete_invite(&self, code_hash: &str) -> sqlx::Result<bool> {
        let deleted = sqlx::query("DELETE FROM invites WHERE code_hash = ?").bind(code_hash).execute(&self.pool).await?;
        Ok(deleted.rows_affected() == 1)
    }

    pub async fn insert_user(&self, user: &NewUser<'_>, invite: InviteRule<'_>, now: i64) -> sqlx::Result<InsertUser> {
        let id = Uuid::new_v4().to_string();
        let mut transaction = self.pool.begin().await?;
        let code_hash = match invite {
            InviteRule::NotNeeded => None,
            InviteRule::Any(hash) | InviteRule::ForThisEmail(hash) => Some(hash),
        };
        if let Some(code_hash) = code_hash {
            // Claimed first, so two sign-ups can't both use one invite.
            let claimed = sqlx::query("UPDATE invites SET used_at = ?, used_by = ? WHERE code_hash = ? AND used_at = 0 AND (expires_at = 0 OR expires_at > ?)")
                .bind(now)
                .bind(&id)
                .bind(code_hash)
                .bind(now)
                .execute(&mut *transaction)
                .await?;
            if claimed.rows_affected() != 1 {
                return Ok(InsertUser::InvalidInvite);
            }
            let row = sqlx::query("SELECT email FROM invites WHERE code_hash = ?").bind(code_hash).fetch_one(&mut *transaction).await?;
            let invited: String = row.try_get("email")?;
            let fits = match invite {
                InviteRule::ForThisEmail(_) => invited == user.email,
                _ => invited.is_empty() || invited == user.email,
            };
            if !fits {
                return Ok(InsertUser::InvalidInvite);
            }
        }
        let inserted = sqlx::query(concat!(
            "INSERT INTO users (id, email, auth_hash, auth_salt, recovery_auth_hash, recovery_auth_salt, kdf_salt, ",
            "kdf_memory_kib, kdf_passes, kdf_parallelism, wrapped_data_key, recovery_wrapped_data_key, totp_secret, ",
            "totp_enabled, totp_last_step, change_seq, used_bytes, created_at, role, quota_bytes) ",
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?, 0)"
        ))
        .bind(&id)
        .bind(user.email)
        .bind(user.auth_hash)
        .bind(user.auth_salt)
        .bind(user.recovery_auth_hash)
        .bind(user.recovery_auth_salt)
        .bind(user.kdf_salt)
        .bind(user.kdf_memory_kib)
        .bind(user.kdf_passes)
        .bind(user.kdf_parallelism)
        .bind(user.wrapped_data_key)
        .bind(user.recovery_wrapped_data_key)
        .bind(&[] as &[u8])
        .bind(now)
        .bind(user.role.as_str())
        .execute(&mut *transaction)
        .await;
        match inserted {
            Ok(_) => {
                transaction.commit().await?;
                Ok(InsertUser::Created(id))
            }
            Err(error) if is_unique_violation(&error) => Ok(InsertUser::EmailTaken),
            Err(error) => Err(error),
        }
    }

    pub async fn set_password(&self, user_id: &str, auth_hash: &[u8], auth_salt: &[u8], wrapped_data_key: &[u8]) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET auth_hash = ?, auth_salt = ?, wrapped_data_key = ? WHERE id = ?")
            .bind(auth_hash)
            .bind(auth_salt)
            .bind(wrapped_data_key)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_recovery(&self, user_id: &str, auth_hash: &[u8], auth_salt: &[u8], wrapped_data_key: &[u8]) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET recovery_auth_hash = ?, recovery_auth_salt = ?, recovery_wrapped_data_key = ? WHERE id = ?")
            .bind(auth_hash)
            .bind(auth_salt)
            .bind(wrapped_data_key)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_totp(&self, user_id: &str, sealed_secret: &[u8], enabled: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET totp_secret = ?, totp_enabled = ?, totp_last_step = 0 WHERE id = ?")
            .bind(sealed_secret)
            .bind(i64::from(enabled))
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn enable_totp(&self, user_id: &str, step: i64) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?").bind(step).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    // False when that step or a later one was already used, so a code works once.
    pub async fn use_totp_step(&self, user_id: &str, step: i64) -> sqlx::Result<bool> {
        let used = sqlx::query("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?")
            .bind(step)
            .bind(user_id)
            .bind(step)
            .execute(&self.pool)
            .await?;
        Ok(used.rows_affected() == 1)
    }

    pub async fn delete_user(&self, user_id: &str) -> sqlx::Result<()> {
        let mut transaction = self.pool.begin().await?;
        for statement in ["DELETE FROM records WHERE user_id = ?", "DELETE FROM sessions WHERE user_id = ?", "DELETE FROM users WHERE id = ?"] {
            sqlx::query(statement).bind(user_id).execute(&mut *transaction).await?;
        }
        transaction.commit().await
    }

    pub async fn insert_session(&self, session: &SessionRow, token_hash: &str) -> sqlx::Result<()> {
        sqlx::query(concat!(
            "INSERT INTO sessions (id, user_id, token_hash, device_name, device_os, created_at, last_seen_at, expires_at) ",
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind(&session.id)
        .bind(&session.user_id)
        .bind(token_hash)
        .bind(&session.device_name)
        .bind(&session.device_os)
        .bind(session.created_at)
        .bind(session.last_seen_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn session_by_token_hash(&self, token_hash: &str) -> sqlx::Result<Option<SessionRow>> {
        let row = sqlx::query(select_session!("WHERE token_hash = ?")).bind(token_hash).fetch_optional(&self.pool).await?;
        row.as_ref().map(session_from).transpose()
    }

    pub async fn session_exists(&self, id: &str, now: i64) -> sqlx::Result<bool> {
        let row = sqlx::query("SELECT id FROM sessions WHERE id = ? AND expires_at > ?").bind(id).bind(now).fetch_optional(&self.pool).await?;
        Ok(row.is_some())
    }

    pub async fn touch_session(&self, id: &str, last_seen_at: i64, expires_at: i64) -> sqlx::Result<()> {
        sqlx::query("UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?")
            .bind(last_seen_at)
            .bind(expires_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_sessions(&self, user_id: &str, now: i64) -> sqlx::Result<Vec<SessionRow>> {
        let rows = sqlx::query(select_session!("WHERE user_id = ? AND expires_at > ? ORDER BY created_at"))
            .bind(user_id)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(session_from).collect()
    }

    pub async fn delete_session(&self, user_id: &str, id: &str) -> sqlx::Result<bool> {
        let deleted = sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id = ?").bind(user_id).bind(id).execute(&self.pool).await?;
        Ok(deleted.rows_affected() == 1)
    }

    pub async fn delete_other_sessions(&self, user_id: &str, keep: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id <> ?").bind(user_id).bind(keep).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn delete_all_sessions(&self, user_id: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn purge(&self, now: i64, attempts_before: i64) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?").bind(now).execute(&self.pool).await?;
        sqlx::query("DELETE FROM login_attempts WHERE created_at <= ?").bind(attempts_before).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn count_attempts(&self, subject: &str, since: i64) -> sqlx::Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS attempts FROM login_attempts WHERE subject = ? AND created_at > ?")
            .bind(subject)
            .bind(since)
            .fetch_one(&self.pool)
            .await?;
        row.try_get("attempts")
    }

    pub async fn oldest_attempt(&self, subject: &str, since: i64) -> sqlx::Result<Option<i64>> {
        let row = sqlx::query("SELECT created_at FROM login_attempts WHERE subject = ? AND created_at > ? ORDER BY created_at LIMIT 1")
            .bind(subject)
            .bind(since)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| row.try_get("created_at")).transpose()
    }

    pub async fn add_attempt(&self, subject: &str, now: i64) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO login_attempts (id, subject, created_at) VALUES (?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(subject)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear_attempts(&self, subject: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM login_attempts WHERE subject = ?").bind(subject).execute(&self.pool).await?;
        Ok(())
    }

    /// `expires_at` 0 for an invite that never expires.
    pub async fn insert_invite(&self, code_hash: &str, email: &str, now: i64, expires_at: i64) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO invites (code_hash, email, created_at, expires_at, used_at, used_by) VALUES (?, ?, ?, ?, 0, '')")
            .bind(code_hash)
            .bind(email)
            .bind(now)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn change_seq(&self, user_id: &str) -> sqlx::Result<u64> {
        let row = sqlx::query("SELECT change_seq FROM users WHERE id = ?").bind(user_id).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| row.try_get::<i64, _>("change_seq")).transpose()?.unwrap_or(0) as u64)
    }

    pub async fn pull(&self, user_id: &str, since: u64, limit: u64, byte_budget: u64) -> sqlx::Result<Pulled> {
        let since = i64::try_from(since).unwrap_or(i64::MAX);
        let sizes = sqlx::query("SELECT seq, size FROM records WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ?")
            .bind(user_id)
            .bind(since)
            .bind(limit as i64 + 1)
            .fetch_all(&self.pool)
            .await?;
        let mut more = sizes.len() as u64 > limit;
        let mut last_seq = None;
        let mut total = 0u64;
        for row in sizes.iter().take(limit as usize) {
            let size = row.try_get::<i64, _>("size")? as u64;
            // A page always holds at least one record, however big.
            if last_seq.is_some() && total + size > byte_budget {
                more = true;
                break;
            }
            total += size;
            last_seq = Some(row.try_get::<i64, _>("seq")?);
        }
        let Some(last_seq) = last_seq else {
            let cursor = self.change_seq(user_id).await?.min(since as u64);
            return Ok(Pulled { records: Vec::new(), cursor, more: false });
        };
        let rows = sqlx::query("SELECT id, revision, deleted, ciphertext FROM records WHERE user_id = ? AND seq > ? AND seq <= ? ORDER BY seq")
            .bind(user_id)
            .bind(since)
            .bind(last_seq)
            .fetch_all(&self.pool)
            .await?;
        let records = rows
            .iter()
            .map(|row| {
                Ok(Record {
                    id: row.try_get("id")?,
                    revision: row.try_get::<i64, _>("revision")? as u64,
                    deleted: row.try_get::<i64, _>("deleted")? != 0,
                    ciphertext: row.try_get::<Vec<u8>, _>("ciphertext")?.into(),
                })
            })
            .collect::<sqlx::Result<Vec<_>>>()?;
        Ok(Pulled { records, cursor: last_seq as u64, more })
    }

    /// `limits.account_bytes` is this account's own allowance. `server_bytes` is the whole server's, 0 for none.
    pub async fn push(&self, user_id: &str, records: &[PushRecord], limits: &Limits, server_bytes: u64, now: i64) -> sqlx::Result<Pushed> {
        let mut transaction = self.pool.begin().await?;
        // A write first takes the account's lock on both databases, so two pushes for one account never interleave.
        sqlx::query("UPDATE users SET used_bytes = used_bytes WHERE id = ?").bind(user_id).execute(&mut *transaction).await?;
        let account = sqlx::query("SELECT change_seq, used_bytes FROM users WHERE id = ?").bind(user_id).fetch_one(&mut *transaction).await?;
        let mut seq: i64 = account.try_get("change_seq")?;
        let mut used: i64 = account.try_get("used_bytes")?;
        // Other accounts can push at the same moment, so this can go a little over. It's a limit for planning, not a guarantee.
        let others = if server_bytes == 0 {
            0
        } else {
            let rows = sqlx::query("SELECT used_bytes FROM users WHERE id <> ?").bind(user_id).fetch_all(&mut *transaction).await?;
            rows.iter().try_fold(0i64, |total, row| Ok::<_, sqlx::Error>(total + row.try_get::<i64, _>("used_bytes")?))?
        };
        let start_seq = seq;
        let mut results = Vec::with_capacity(records.len());
        for record in records {
            let existing = sqlx::query("SELECT revision, size FROM records WHERE user_id = ? AND id = ?")
                .bind(user_id)
                .bind(&record.id)
                .fetch_optional(&mut *transaction)
                .await?;
            let (current, old_size) = match &existing {
                Some(row) => (row.try_get::<i64, _>("revision")? as u64, row.try_get::<i64, _>("size")?),
                None => (0, 0),
            };
            let size = record.ciphertext.len() as i64;
            let status = if size as u64 > limits.record_bytes {
                PushStatus::TooLarge
            } else if current != record.base_revision {
                PushStatus::Conflict
            } else if size > old_size
                && ((used - old_size + size) as u64 > limits.account_bytes || (server_bytes > 0 && (others + used - old_size + size) as u64 > server_bytes))
            {
                PushStatus::QuotaExceeded
            } else {
                PushStatus::Accepted
            };
            if status != PushStatus::Accepted {
                results.push(PushResult { id: record.id.clone(), status, revision: current });
                continue;
            }
            seq += 1;
            used += size - old_size;
            let revision = current + 1;
            if existing.is_some() {
                sqlx::query("UPDATE records SET revision = ?, deleted = ?, ciphertext = ?, size = ?, seq = ?, updated_at = ? WHERE user_id = ? AND id = ?")
                    .bind(revision as i64)
                    .bind(i64::from(record.deleted))
                    .bind(record.ciphertext.as_slice())
                    .bind(size)
                    .bind(seq)
                    .bind(now)
                    .bind(user_id)
                    .bind(&record.id)
                    .execute(&mut *transaction)
                    .await?;
            } else {
                sqlx::query("INSERT INTO records (user_id, id, revision, deleted, ciphertext, size, seq, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                    .bind(user_id)
                    .bind(&record.id)
                    .bind(revision as i64)
                    .bind(i64::from(record.deleted))
                    .bind(record.ciphertext.as_slice())
                    .bind(size)
                    .bind(seq)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await?;
            }
            results.push(PushResult { id: record.id.clone(), status, revision });
        }
        let changed = seq != start_seq;
        if changed {
            sqlx::query("UPDATE users SET change_seq = ?, used_bytes = ? WHERE id = ?")
                .bind(seq)
                .bind(used)
                .bind(user_id)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(Pushed { results, cursor: seq as u64, changed })
    }
}
