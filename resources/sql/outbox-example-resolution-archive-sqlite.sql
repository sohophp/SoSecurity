-- Explicit additive sender migration. Enable resolution_archive and initialize its version-2 root separately.
-- Retains complete signed evidence in the same database/transaction as the active audit.
CREATE TABLE outbox_example_resolution_archives (
    event_id TEXT NOT NULL PRIMARY KEY,
    payload BLOB NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
