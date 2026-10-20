-- Independent receiver database. Retain business deduplication across receipt-history recovery.
CREATE TABLE outbox_example_receiver_root (
    slot INTEGER NOT NULL PRIMARY KEY,
    payload BLOB NOT NULL,
    seal_key TEXT NOT NULL,
    seal TEXT NOT NULL
);
CREATE TABLE outbox_example_actors (
    subject TEXT NOT NULL PRIMARY KEY,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    roles TEXT NOT NULL
);
CREATE TABLE outbox_example_routes (
    publisher TEXT NOT NULL PRIMARY KEY,
    tenant TEXT NOT NULL,
    enabled INTEGER NOT NULL
);
CREATE TABLE outbox_example_owners (
    subject TEXT NOT NULL PRIMARY KEY,
    enabled INTEGER NOT NULL
);
CREATE TABLE outbox_example_effects (
    publisher TEXT NOT NULL,
    event_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    body_digest TEXT NOT NULL,
    order_id TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    amount INTEGER NOT NULL,
    PRIMARY KEY(publisher,event_id),
    UNIQUE(publisher,delivery_id)
);
CREATE TABLE outbox_example_projection (
    subject TEXT NOT NULL,
    order_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    deliveries INTEGER NOT NULL,
    PRIMARY KEY(subject,order_id)
);
-- Permanent terminal fences. They are part of the receiver root/checkpoint history.
CREATE TABLE outbox_example_cancellations (
    publisher TEXT NOT NULL,
    event_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    body_digest TEXT NOT NULL,
    order_id TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    amount INTEGER NOT NULL,
    PRIMARY KEY(publisher,event_id),
    UNIQUE(publisher,delivery_id)
);
