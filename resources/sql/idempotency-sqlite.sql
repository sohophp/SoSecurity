-- Explicit deployment only. Retain root rows and key tombstones; do not clear them to reset capacity.
CREATE TABLE sosecurity_idempotency_roots (
    namespace TEXT NOT NULL PRIMARY KEY,
    format INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    policy TEXT NOT NULL,
    entries INTEGER NOT NULL,
    history_digest TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
CREATE TABLE sosecurity_idempotency_records (
    namespace TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    format INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    policy TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_bytes INTEGER NOT NULL,
    response_digest TEXT NOT NULL,
    response_body BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    PRIMARY KEY(namespace,key_hash)
);
CREATE UNIQUE INDEX sosecurity_idempotency_execution ON sosecurity_idempotency_records(execution_id);
CREATE INDEX sosecurity_idempotency_retention ON sosecurity_idempotency_records(namespace,expires_at,key_hash);
