-- Explicit deployment into a separate audit database. Not a business transaction participant.
CREATE TABLE sosecurity_audit_roots (
    site TEXT NOT NULL,
    policy TEXT NOT NULL,
    next_sequence INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (site)
);
CREATE TABLE sosecurity_audit_records (
    site TEXT NOT NULL,
    sequence_no INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (site,sequence_no)
);
CREATE INDEX sosecurity_audit_expiry ON sosecurity_audit_records(site,expires_at,sequence_no);
