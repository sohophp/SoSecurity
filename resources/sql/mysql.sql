CREATE TABLE IF NOT EXISTS sosecurity_state (
    namespace_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    state_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    payload MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
    expires_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace_hash, state_key),
    KEY sosecurity_expiry (namespace_hash, expires_at)
) ENGINE=InnoDB;
