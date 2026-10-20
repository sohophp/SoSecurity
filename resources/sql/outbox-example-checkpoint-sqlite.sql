-- Independent durable witness, excluded from receiver business-database backup/restore.
-- Install explicitly in its own private SQLite database.
CREATE TABLE outbox_example_receiver_checkpoint (
    slot INTEGER NOT NULL PRIMARY KEY,
    payload BLOB NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
