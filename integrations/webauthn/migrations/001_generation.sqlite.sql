-- Apply once, under maintenance, to a pre-generation draft WebAuthn user table.
ALTER TABLE sosecurity_webauthn_user
    ADD COLUMN generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0);
