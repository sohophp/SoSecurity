-- Host-owned demonstration schema; independent from private ledger tables.
CREATE TABLE account_example (
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    credential_version TEXT NOT NULL,
    address_version TEXT NOT NULL,
    address TEXT NOT NULL COLLATE BINARY,
    password TEXT NULL,
    status TEXT NOT NULL,
    verified INTEGER NOT NULL,
    mfa_required INTEGER NOT NULL,
    roles TEXT NOT NULL,
    PRIMARY KEY (scope,subject),
    UNIQUE (scope,address)
);
