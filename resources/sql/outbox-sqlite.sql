-- Explicit deployment only. Same transaction database/connection as the business tables.

CREATE TABLE sosecurity_outbox_roots (
    namespace TEXT NOT NULL,
    format INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    policy TEXT NOT NULL,
    entries INTEGER NOT NULL,
    history_digest TEXT NOT NULL,
    last_order INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    PRIMARY KEY (namespace)
);

CREATE TABLE sosecurity_outbox_records (
    namespace TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    message_id TEXT NOT NULL,
    format INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    policy TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    order_no INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    destination TEXT NOT NULL,
    topic TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_hash TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_present INTEGER NOT NULL,
    payload_body BLOB NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    cycle_attempts INTEGER NOT NULL,
    manual_retries INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    admit_until INTEGER NOT NULL,
    deliver_until INTEGER NOT NULL,
    available_at INTEGER NOT NULL,
    lease_until INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    worker_hash TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    last_error TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    sent_at INTEGER NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    PRIMARY KEY (namespace,key_hash)
);

CREATE UNIQUE INDEX sosecurity_outbox_order ON sosecurity_outbox_records (namespace,order_no);

CREATE INDEX sosecurity_outbox_aggregate ON sosecurity_outbox_records (namespace,aggregate_hash,order_no);

CREATE INDEX sosecurity_outbox_due ON sosecurity_outbox_records (namespace,status,available_at,order_no);
