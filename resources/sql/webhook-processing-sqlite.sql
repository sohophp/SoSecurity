-- Explicit deployment only. Preserves the existing receive schema and payloads.
CREATE INDEX sosecurity_webhook_receipt ON sosecurity_webhook_inbox (endpoint_key, receipt_id, event_key);
CREATE TABLE sosecurity_webhook_processing (
    endpoint_key TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    event_key TEXT NOT NULL,
    body_digest TEXT NOT NULL,
    descriptor TEXT NOT NULL,
    policy TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    total_attempts INTEGER NOT NULL,
    manual_retries INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    due_at INTEGER NOT NULL,
    lease_until INTEGER NOT NULL,
    claim_digest TEXT NOT NULL,
    worker_digest TEXT NOT NULL,
    error_code TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    PRIMARY KEY (endpoint_key, receipt_id)
);
CREATE INDEX sosecurity_webhook_pending ON sosecurity_webhook_processing (endpoint_key, status, due_at, receipt_id);
CREATE INDEX sosecurity_webhook_expired ON sosecurity_webhook_processing (endpoint_key, status, lease_until, receipt_id);
CREATE UNIQUE INDEX sosecurity_webhook_processed_event ON sosecurity_webhook_processing (endpoint_key, event_key);
