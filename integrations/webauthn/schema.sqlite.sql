CREATE TABLE sosecurity_webauthn_user (
    scope_hash TEXT NOT NULL,
    user_key TEXT NOT NULL,
    active_count INTEGER NOT NULL DEFAULT 0 CHECK (active_count >= 0 AND active_count <= 32),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    PRIMARY KEY (scope_hash, user_key)
);

CREATE TABLE sosecurity_webauthn_credential (
    scope_hash TEXT NOT NULL,
    credential_key TEXT NOT NULL,
    user_key TEXT NOT NULL,
    record_json BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    revoked_at INTEGER NULL,
    PRIMARY KEY (scope_hash, credential_key)
);

CREATE INDEX sosecurity_webauthn_credential_user
    ON sosecurity_webauthn_credential (scope_hash, user_key, revoked_at, credential_key);
