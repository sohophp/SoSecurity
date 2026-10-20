-- Explicit additive migration for an existing native receiver. Stop old workers first.
-- New installations use outbox-example-receiver-sqlite.sql instead.
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
