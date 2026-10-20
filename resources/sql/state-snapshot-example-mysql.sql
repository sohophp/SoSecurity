-- Optional isolated example schema. Never installed automatically.
CREATE TABLE snapshot_example (
    scope VARBINARY(64) NOT NULL,
    subject VARBINARY(64) NOT NULL,
    enabled BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (scope, subject)
) ENGINE=InnoDB;
