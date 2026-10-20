-- Explicit host-managed authority, independent of sender/receiver business backup and restore.
-- Populate from the current authority source; never adopt permissions from a restored business DB.
CREATE TABLE outbox_example_actors (
    subject TEXT NOT NULL PRIMARY KEY,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    roles TEXT NOT NULL
);
CREATE TABLE outbox_example_routes (
    publisher TEXT NOT NULL PRIMARY KEY,
    tenant TEXT NOT NULL,
    enabled INTEGER NOT NULL
);
CREATE TABLE outbox_example_owners (
    subject TEXT NOT NULL PRIMARY KEY,
    enabled INTEGER NOT NULL
);
