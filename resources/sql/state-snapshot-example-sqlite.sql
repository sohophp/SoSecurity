-- Optional isolated example schema. Never installed automatically.
CREATE TABLE snapshot_example (
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    PRIMARY KEY (scope, subject)
);
