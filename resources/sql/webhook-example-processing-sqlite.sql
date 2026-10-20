-- Example host business schema only. Install explicitly after receipt and processing schemas.
-- Keep these business tables in the same private transactional SQLite database.
CREATE TABLE webhook_example_effects (
    tenant TEXT NOT NULL,
    account TEXT NOT NULL,
    event_key CHAR(64) NOT NULL,
    body_digest CHAR(64) NOT NULL,
    resource_id TEXT NOT NULL,
    resource_version TEXT NOT NULL,
    receipt_id CHAR(32) NOT NULL,
    PRIMARY KEY (tenant, account, event_key)
);
CREATE TABLE webhook_example_projection (
    tenant TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_version TEXT NOT NULL,
    event_count INTEGER NOT NULL CHECK(event_count BETWEEN 1 AND 1000000000),
    last_event CHAR(64) NOT NULL,
    PRIMARY KEY (tenant, account, resource_id)
);
