-- Host-owned example schema. Apply explicitly to a private test/deployment SQLite database.
CREATE TABLE quarantine_example_accounts (
    site TEXT NOT NULL,
    subject TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    roles TEXT NOT NULL,
    mfa_required INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (site, subject),
    UNIQUE (site, username)
);
CREATE TABLE quarantine_example_files (
    site TEXT NOT NULL,
    id TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (site, id)
);
CREATE INDEX quarantine_example_files_owner ON quarantine_example_files(site, owner);
