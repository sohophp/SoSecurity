-- Apply once, under maintenance, to a pre-generation draft WebAuthn user table.
ALTER TABLE sosecurity_webauthn_user
    ADD COLUMN generation BIGINT UNSIGNED NOT NULL DEFAULT 0;
