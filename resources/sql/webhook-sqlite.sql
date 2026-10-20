-- Explicit deployment artifact. No request-time schema creation or business-table migration.
CREATE TABLE sosecurity_webhook_inbox (
    endpoint_key TEXT NOT NULL,
    event_key TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    descriptor TEXT NOT NULL,
    body_digest TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    seen_at INTEGER NOT NULL,
    source_key TEXT NOT NULL,
    source_time INTEGER,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    PRIMARY KEY (endpoint_key, event_key)
);
CREATE INDEX sosecurity_webhook_retention ON sosecurity_webhook_inbox (endpoint_key, created_at, event_key);
