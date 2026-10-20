-- Explicit deployment only. Preserves the existing receive schema and payloads.
CREATE INDEX sosecurity_webhook_receipt ON sosecurity_webhook_inbox (endpoint_key, receipt_id, event_key);
CREATE TABLE sosecurity_webhook_processing (
    endpoint_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    receipt_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    event_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    body_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    descriptor CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARBINARY(16) NOT NULL,
    attempt BIGINT UNSIGNED NOT NULL,
    total_attempts BIGINT UNSIGNED NOT NULL,
    manual_retries BIGINT UNSIGNED NOT NULL,
    revision BIGINT UNSIGNED NOT NULL,
    due_at BIGINT UNSIGNED NOT NULL,
    lease_until BIGINT UNSIGNED NOT NULL,
    claim_digest VARBINARY(64) NOT NULL,
    worker_digest VARBINARY(64) NOT NULL,
    error_code VARBINARY(64) NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    updated_at BIGINT UNSIGNED NOT NULL,
    seal_key VARBINARY(32) NOT NULL,
    seal CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (endpoint_key, receipt_id)
) ENGINE=InnoDB;
CREATE INDEX sosecurity_webhook_pending ON sosecurity_webhook_processing (endpoint_key, status, due_at, receipt_id);
CREATE INDEX sosecurity_webhook_expired ON sosecurity_webhook_processing (endpoint_key, status, lease_until, receipt_id);
CREATE UNIQUE INDEX sosecurity_webhook_processed_event ON sosecurity_webhook_processing (endpoint_key, event_key);
