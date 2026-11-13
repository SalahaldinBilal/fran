CREATE TABLE meta (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sessions (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    device_name VARCHAR(255) NOT NULL,
    device_os VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    INDEX sessions_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE records (
    user_id VARCHAR(36) NOT NULL,
    id VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL,
    deleted BIGINT NOT NULL,
    ciphertext MEDIUMBLOB NOT NULL,
    size BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, id),
    INDEX records_user_seq (user_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE login_attempts (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL,
    INDEX login_attempts_subject (subject, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE invites (
    code_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT NOT NULL,
    used_by VARCHAR(36) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE settings (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE admin_log (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    detail VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL,
    INDEX admin_log_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
