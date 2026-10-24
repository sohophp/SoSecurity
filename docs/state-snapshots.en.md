# Bounded read-only state snapshots

Strict native drivers without a readable STRINGIFY_FETCHES attribute use fixed text/NULL snapshot metadata. Closed statements are reusable only after exact SQL and canonical parameter matching. Drivers with a readable attribute and custom dependencies retain the original SQL. At most eight code templates and eight closed statements are retained; table-name values, databases, rows and authorization results are not cached. Database identity is probed and metadata executed afresh. See the [validation and limits](snapshot-text-pool-2026-10-24.md).

MySQL can resolve both aliases of up to four tables in one zero-row statement on the strict native path. Custom PDO, Statement and entry-guard paths retain separate observations. Both paths require successful cursor cleanup; false returns and cleanup exceptions are rejected as sql.cleanup. No authorization decision or observation result is cached. Digest inputs and deadlines remain unchanged; see the [validation and compatibility record](snapshot-resolution-2026-10-24.md).

MySQL SQL snapshots hash the raw database-name bytes. One fresh query observes isolation and database identity, and its cursor must close successfully before either value is used. The existing 1–64 byte bound and normal ASCII/UTF-8 digests remain unchanged. Previously lossy result encodings may have produced incorrect digests; these are not automatically migrated or accepted. Do not rebuild an existing witness to bypass a mismatch. See the [fix and compatibility evidence](sql-snapshot-context-2026-10-24.md).

[Scoped proof epoch retirement](state-proof-retirement-2026-10-22.md) adds permanent markers for operation grants, signed links, and password-reset tokens. Cover every actual ledger and marker in the complete source; retain consumed nonces. Independent approval binds one to four fixed native marker effects, checks aggregate file capacity, and requires a fresh approval to continue unknown results. Completion still leaves the witness quarantined.

New credential installations use manifest format 4 (or 5 with session retirement). Approval binds the authenticated directory’s exact prior factor bytes and a permanent authenticated tombstone; see the [prior-factor retirement record](state-installation-retirement-2026-10-22.md). Formats 2/3 retain their original effects and do not silently gain unapproved destructive writes. Upgrade all relevant readers together. Completion still leaves the account disabled and the witness quarantined; final safe activation remains required.

File source fingerprints now use `FileSnapshot.Profile.3`: exactly 64 private staging slots (`stage-0` through `stage-63`), each bounded to 64 KiB, are validated but never adopted as authentication state. Protected FileStore and recovery writes reuse these slots; committed bytes remain covered. Older source declarations cannot be mixed, and deleting or initializing an existing witness is not migration. Three installation boundaries now have real SIGKILL and fresh-process continuation tests; see the [crash record](state-crash-integration-2026-10-21.md).

For independent freshness checks and explicit authentication wiring, see [state boundaries](state-boundary.en.md). Snapshots alone remain bounded complete observations and do not prevent old-backup restoration. Full F01 acceptance is unfinished.

The SDK now includes SQL, FileStore-directory and composite snapshots as standalone Composer APIs. A digest is data, not authorization or independent freshness. Recovery approvals and safe-generation transitions remain separate work in the full roadmap.

Declare every SQL column, the exact primary key, fixed filters and row limits explicitly. `SqlStateSnapshot::capture()` returns selected rows or pages from the same full scan as its digest. NUL bytes count toward limits and hashes; NULL differs from an empty value. Wrong SQLite storage classes, schema mismatches and capacity violations fail closed. Paging requires a nonempty primary-key prefix. Pass the complete returned cursor back, and compare observations when consistency across separate calls matters.

Snapshots own their transaction and reject an already active host transaction. SQLite needs a persistent database with journaling and FULL/EXTRA synchronization; it can block concurrent writers while observing. MySQL needs InnoDB, native prepared statements and REPEATABLE-READ.

`FileStateSnapshot` uses separate canonical private 0700 state and scratch directories. Files are limited to 65536 bytes. Links, unexpected entries, wrong permissions and directory replacement are rejected. At most four files can be captured. FileStore's `snapshotBinding()` identifies only its directory; use `snapshotReference($key)` to bind the namespace-derived filename as well.

With fewer than 256 state files, the complete sorted chunk is hashed directly without a sorting run file; larger inputs retain external sorting. The source fingerprint, digest protocol, per-file checks and capacity budgets are unchanged. A private temporary work directory is still created and its cleanup confirmed; the configured scratch directory remains required. See the [focused evidence and limits](file-snapshot-memory-2026-10-24.md).

A composite capture uses the exact same PDO object for its concrete SQL and file sources, repeats complete observations, and rejects changed digests or selected bytes. It supports four selected sources and 1MiB of selected data. SQL supports 32 tables, 64 columns per table and four primary-key columns, with a 2MiB declared per-row budget. Captures allow eight aliases, 16 selected columns and 64KiB per record, 256KiB in total, and eight rows per page. Real elapsed-time budgets range from 1 to 30000 milliseconds.

All relevant writers must obey the host's shared lock protocol. Two matching observations do not create cross-system atomicity or stop a writer that bypasses that protocol. Custom trusted `StateSnapshot` implementations can participate in digest composition; capture accepts only concrete built-in sources.

Include the [portable example](../examples/state-snapshot.php) after the consumer's Composer autoloader. It returns a builder and never installs SQL tables. Example DDL is provided separately for an explicitly created test environment. Captures redact normal debug output and reject serialization, but their explicit row/page/file accessors return raw data that must be protected and excluded from logs.

The SDK checks include malformed, oversized and binary values, paging and concurrent changes. See the [Chinese guide](state-snapshots.md) and [verification record](verification.md) for current results and limits. No production or recovery-authority acceptance is implied.

## Verification for this integration

All 159 invocations across PHP 7.2–8.5 passed, including 13 new snapshot groups per runtime, API/syntax and existing core/storage checks. Existing members of 211 public types were preserved; the SDK now has 219 public types and 261 source files. Two private no-TCP MySQL runs passed ten groups and 317 assertions each and were cleaned up. Static analysis, two 10,000-file capacity runs, fresh Composer consumers and 412-file archives passed. All 291 frozen inputs remained unchanged. Full current-SDK HTTP/browser/CI, production, publication and independent review were not performed for this stage.


Native signed links now accept an explicit state policy through `Security::signedLinks($policy)`. Native For methods reload server targets during read-only admission, and `withVerification` owns proof consumption and business SQL inside one witness boundary. See [scope and evidence](state-native-links-integration-2026-10-22.md). Final activation and full R1–R6 acceptance remain open.


Native reset proofs accept explicit state/request authority through `resetTokens(ttl, statePolicy, requestGuard)`. For methods derive current password/factor/mailbox-version bindings; `withConsumption` owns the proof and declared SQL effects in one witness boundary. The request guard is explicit host recovery authority; this primitive does not replace Account\Recovery or prove MFA/mail delivery. See [scope/evidence](state-native-reset-integration-2026-10-22.md).


`KeyRingStateSnapshot(PDO, profile, KeyRing, SignaturePolicy)` now covers actual immutable HMAC key material/identity/scopes and signing policy. Its source identity stays stable while configuration contents change the digest, so restoring old configuration fails freshness checks. Native verification requires this exact covered source; online providers, source/key rotation, HTTP and final recovery remain open. See [scope/evidence](state-native-hmac-integration-2026-10-22.md).


Native Links, ResetTokens, Grants and CredentialRegistry now check physical file headroom before pending when allocating a ledger. Expired physical files still count, existing-ledger updates remain allowed, and releasing one owned record permits retry on the same graph. See the [reproduction and bounded checks](state-admission-capacity-2026-10-22.md). This does not cover every byte/SQL/disk capacity or final recovery.

## Physical worker fence sources

A state-bound `LocalEpochFence` must have its actual directory covered by a `FenceStateSnapshot` in the same `CompositeStateSnapshot`; otherwise construction fails with `configuration.state_coverage`. The native authentication factory checks this as well. Declare every legacy, current and planned authority directory before first witness provisioning, rather than selecting only the currently active file.

`FenceStateSnapshot(PDO, profile, directory, maximumFiles=128, milliseconds=10000)` reads a canonical private 0700 directory. Its stable directory identity contributes to the source fingerprint; all file names and complete raw fence records contribute to the content digest. Files must be 0600, single-link, same-owner records of at most 128 bytes. The fixed file bound is 1–4096, default 128. Unknown entries, malformed records, exceeded limits and directory replacement fail closed. The source validates record structure; `LocalEpochFence` remains responsible for authenticating each context-specific signature.

Add the concrete source to the complete composite before constructing the witness and boundary. It never creates or reopens authority files and takes no extra fence lock, so observation also works while the caller owns the shared lock or closed exclusive lock. Writers must still follow the witness → fence → SQL → physical storage lock order. Repeated reads do not replace coordinated locking.

Adding this source changes the source fingerprint. Existing roots must not be deleted, reprovisioned or silently adopted to accept it. Final recovery activation and worker handoff between security generations remain incomplete. See the [physical fence source evidence](state-fence-source-2026-10-22.md).
