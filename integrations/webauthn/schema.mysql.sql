CREATE TABLE sosecurity_webauthn_user (
    scope_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    active_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_hash, user_key),
    CONSTRAINT sosecurity_webauthn_user_count CHECK (active_count <= 32)
) ENGINE=InnoDB;

CREATE TABLE sosecurity_webauthn_credential (
    scope_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    credential_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record_json BLOB NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at BIGINT UNSIGNED NOT NULL,
    updated_at BIGINT UNSIGNED NOT NULL,
    revoked_at BIGINT UNSIGNED NULL,
    PRIMARY KEY (scope_hash, credential_key),
    KEY sosecurity_webauthn_credential_user (scope_hash, user_key, revoked_at, credential_key)
) ENGINE=InnoDB;
