-- Explicit deployment only. Retain root rows and key tombstones; do not clear them to reset capacity.
CREATE TABLE sosecurity_idempotency_roots (
    namespace CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    format BIGINT UNSIGNED NOT NULL,
    epoch CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    entries BIGINT UNSIGNED NOT NULL,
    history_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    revision BIGINT UNSIGNED NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    observed_at BIGINT UNSIGNED NOT NULL,
    seal_key VARBINARY(32) NOT NULL,
    seal CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY(namespace)
) ENGINE=InnoDB;
CREATE TABLE sosecurity_idempotency_records (
    namespace CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    format BIGINT UNSIGNED NOT NULL,
    epoch CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    execution_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARBINARY(16) NOT NULL,
    status_code BIGINT UNSIGNED NOT NULL,
    response_bytes BIGINT UNSIGNED NOT NULL,
    response_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    response_body MEDIUMBLOB NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    updated_at BIGINT UNSIGNED NOT NULL,
    seal_key VARBINARY(32) NOT NULL,
    seal CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY(namespace,key_hash)
) ENGINE=InnoDB;
CREATE UNIQUE INDEX sosecurity_idempotency_execution ON sosecurity_idempotency_records(execution_id);
CREATE INDEX sosecurity_idempotency_retention ON sosecurity_idempotency_records(namespace,expires_at,key_hash);
