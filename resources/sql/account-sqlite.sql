-- Explicit deployment only, in the same persistent database as host account tables.
CREATE TABLE sosecurity_account_roots (
    namespace TEXT NOT NULL,
    format INTEGER NOT NULL,
    epoch TEXT NOT NULL,
    policy TEXT NOT NULL,
    entries INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    history_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    PRIMARY KEY (namespace)
);
CREATE TABLE sosecurity_account_records (
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    kind TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    retire_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    payload_bytes INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (namespace,record_id)
);
CREATE INDEX sosecurity_account_owner ON sosecurity_account_records (namespace,owner,kind,created_at,record_id);
CREATE INDEX sosecurity_account_retention ON sosecurity_account_records (namespace,retire_at,record_id);
