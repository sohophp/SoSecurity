-- Explicit additive migration for an existing native sender. Stop old workers first.
-- New installations use outbox-example-sender-sqlite.sql instead.
CREATE TABLE outbox_example_resolution_root (
    slot INTEGER NOT NULL PRIMARY KEY,
    payload BLOB NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
CREATE TABLE outbox_example_resolutions (
    event_id TEXT NOT NULL PRIMARY KEY,
    payload BLOB NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
