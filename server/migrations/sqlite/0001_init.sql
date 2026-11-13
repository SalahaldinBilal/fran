CREATE TABLE meta (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARCHAR(255) NOT NULL
);

CREATE TABLE users (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    auth_hash BLOB NOT NULL,
    auth_salt BLOB NOT NULL,
    recovery_auth_hash BLOB NOT NULL,
    recovery_auth_salt BLOB NOT NULL,
    kdf_salt BLOB NOT NULL,
    kdf_memory_kib BIGINT NOT NULL,
    kdf_passes BIGINT NOT NULL,
    kdf_parallelism BIGINT NOT NULL,
    wrapped_data_key BLOB NOT NULL,
    recovery_wrapped_data_key BLOB NOT NULL,
    totp_secret BLOB NOT NULL,
    totp_enabled BIGINT NOT NULL,
    totp_last_step BIGINT NOT NULL,
    change_seq BIGINT NOT NULL,
    used_bytes BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    role VARCHAR(16) NOT NULL,
    quota_bytes BIGINT NOT NULL
);

CREATE TABLE sessions (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    device_name VARCHAR(255) NOT NULL,
    device_os VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE records (
    user_id VARCHAR(36) NOT NULL,
    id VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL,
    deleted BIGINT NOT NULL,
    ciphertext BLOB NOT NULL,
    size BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, id)
);
CREATE INDEX records_user_seq ON records (user_id, seq);

CREATE TABLE login_attempts (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX login_attempts_subject ON login_attempts (subject, created_at);

CREATE TABLE invites (
    code_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT NOT NULL,
    used_by VARCHAR(36) NOT NULL
);

CREATE TABLE settings (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARCHAR(255) NOT NULL
);

CREATE TABLE admin_log (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    detail VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX admin_log_created ON admin_log (created_at);
