-- Explicit deployment artifact. Existing tables are never silently altered.
CREATE TABLE sosecurity_webhook_inbox (
    endpoint_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    receipt_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_id VARBINARY(256) NOT NULL,
    event_type VARBINARY(64) NOT NULL,
    resource_id VARBINARY(256) NOT NULL,
    descriptor CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    body_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    payload MEDIUMBLOB NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    seen_at BIGINT UNSIGNED NOT NULL,
    source_key VARBINARY(32) NOT NULL,
    source_time BIGINT UNSIGNED NULL,
    seal_key VARBINARY(32) NOT NULL,
    seal CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (endpoint_key, event_key),
    KEY sosecurity_webhook_retention (endpoint_key, created_at, event_key)
) ENGINE=InnoDB;
