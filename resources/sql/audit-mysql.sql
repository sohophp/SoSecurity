-- Explicit deployment into a separate audit database. Not a business transaction participant.
CREATE TABLE sosecurity_audit_roots (
    site CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    next_sequence BIGINT UNSIGNED NOT NULL,
    observed_at BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (site)
) ENGINE=InnoDB;
CREATE TABLE sosecurity_audit_records (
    site CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    sequence_no BIGINT UNSIGNED NOT NULL,
    recorded_at BIGINT UNSIGNED NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    record MEDIUMBLOB NOT NULL,
    PRIMARY KEY (site,sequence_no),
    INDEX sosecurity_audit_expiry (site,expires_at,sequence_no)
) ENGINE=InnoDB;
