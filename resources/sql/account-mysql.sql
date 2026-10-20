-- Explicit deployment only, in the same database as host account tables. No foreign keys or triggers.
CREATE TABLE sosecurity_account_roots (
    namespace CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    format BIGINT UNSIGNED NOT NULL,
    epoch CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    entries BIGINT UNSIGNED NOT NULL,
    revision BIGINT UNSIGNED NOT NULL,
    history_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    observed_at BIGINT UNSIGNED NOT NULL,
    seal_key VARBINARY(32) NOT NULL,
    seal CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (namespace)
) ENGINE=InnoDB;
CREATE TABLE sosecurity_account_records (
    namespace CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    owner CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    kind VARBINARY(16) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    retire_at BIGINT UNSIGNED NOT NULL,
    updated_at BIGINT UNSIGNED NOT NULL,
    payload_bytes BIGINT UNSIGNED NOT NULL,
    payload_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    seal_key VARBINARY(32) NOT NULL,
    seal CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    payload MEDIUMBLOB NOT NULL,
    PRIMARY KEY (namespace,record_id),
    INDEX sosecurity_account_owner (namespace,owner,kind,created_at,record_id),
    INDEX sosecurity_account_retention (namespace,retire_at,record_id)
) ENGINE=InnoDB;
