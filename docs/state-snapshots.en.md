# Bounded read-only state snapshots

The SDK now includes SQL, FileStore-directory and composite snapshots as standalone Composer APIs. A digest is data, not authorization or independent freshness. Recovery approvals and safe-generation transitions remain separate work in the full roadmap.

Declare every SQL column, the exact primary key, fixed filters and row limits explicitly. `SqlStateSnapshot::capture()` returns selected rows or pages from the same full scan as its digest. NUL bytes count toward limits and hashes; NULL differs from an empty value. Wrong SQLite storage classes, schema mismatches and capacity violations fail closed. Paging requires a nonempty primary-key prefix. Pass the complete returned cursor back, and compare observations when consistency across separate calls matters.

Snapshots own their transaction and reject an already active host transaction. SQLite needs a persistent database with journaling and FULL/EXTRA synchronization; it can block concurrent writers while observing. MySQL needs InnoDB, native prepared statements and REPEATABLE-READ.

`FileStateSnapshot` uses separate canonical private 0700 state and scratch directories. Files are limited to 65536 bytes. Links, unexpected entries, wrong permissions and directory replacement are rejected. At most four files can be captured. FileStore's `snapshotBinding()` identifies only its directory; use `snapshotReference($key)` to bind the namespace-derived filename as well.

A composite capture uses the exact same PDO object for its concrete SQL and file sources, repeats complete observations, and rejects changed digests or selected bytes. It supports four selected sources and 1MiB of selected data. SQL supports 32 tables, 64 columns per table and four primary-key columns, with a 2MiB declared per-row budget. Captures allow eight aliases, 16 selected columns and 64KiB per record, 256KiB in total, and eight rows per page. Real elapsed-time budgets range from 1 to 30000 milliseconds.

All relevant writers must obey the host's shared lock protocol. Two matching observations do not create cross-system atomicity or stop a writer that bypasses that protocol. Custom trusted `StateSnapshot` implementations can participate in digest composition; capture accepts only concrete built-in sources.

Include the [portable example](../examples/state-snapshot.php) after the consumer's Composer autoloader. It returns a builder and never installs SQL tables. Example DDL is provided separately for an explicitly created test environment. Captures redact normal debug output and reject serialization, but their explicit row/page/file accessors return raw data that must be protected and excluded from logs.

The SDK checks include malformed, oversized and binary values, paging and concurrent changes. See the [Chinese guide](state-snapshots.md) and [verification record](verification.md) for current results and limits. No production or recovery-authority acceptance is implied.

## Verification for this integration

All 159 invocations across PHP 7.2–8.5 passed, including 13 new snapshot groups per runtime, API/syntax and existing core/storage checks. Existing members of 211 public types were preserved; the SDK now has 219 public types and 261 source files. Two private no-TCP MySQL runs passed ten groups and 317 assertions each and were cleaned up. Static analysis, two 10,000-file capacity runs, fresh Composer consumers and 412-file archives passed. All 291 frozen inputs remained unchanged. Full current-SDK HTTP/browser/CI, production, publication and independent review were not performed for this stage.
