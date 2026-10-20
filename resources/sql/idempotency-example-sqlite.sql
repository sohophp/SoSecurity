-- Host-owned example tables. Install explicitly; the HTTP endpoint never runs this DDL.
CREATE TABLE idempotency_example_accounts (
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    roles TEXT NOT NULL,
    PRIMARY KEY(tenant,subject)
);
CREATE TABLE idempotency_example_orders (
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    order_id TEXT NOT NULL UNIQUE,
    amount INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(tenant,subject,reference_id)
);
CREATE TABLE idempotency_example_executions (
    execution_id TEXT NOT NULL PRIMARY KEY,
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    order_id TEXT NOT NULL
);
