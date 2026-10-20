-- Explicit host migration. No accounts, keys or queue roots are created by requests.
CREATE TABLE outbox_example_actors (
    subject TEXT NOT NULL PRIMARY KEY,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    roles TEXT NOT NULL
);
CREATE TABLE outbox_example_orders (
    subject TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    order_id TEXT NOT NULL UNIQUE,
    amount INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL,
    PRIMARY KEY(subject,reference_id)
);
-- Explicitly initialized native reconciliation audit; never created by requests.
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
-- Optional format-2 audit tier; activation is an explicit management operation.
CREATE TABLE outbox_example_resolution_archives (
    event_id TEXT NOT NULL PRIMARY KEY,
    payload BLOB NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
