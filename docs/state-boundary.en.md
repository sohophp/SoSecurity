# Independent witnesses and authentication state boundaries

The local protected host now has both-runtime MySQL HTTP/TLS evidence and continuous `SystemClock` checks. Eight observations confirm a credential was live at callback start and expired at callback end, with no authentication-source or witness write. Joint SQL/auth-file/PHP-session replay remains rejected. Business PDO composition and final recovery are still incomplete. See the [backend and clock record](state-http-mysql-integration-2026-10-21.md).

The managed authentication example supports an explicit private `Security` / `state_policy` bundle. CSRF admission precedes authoritative session updates, and Cookie management is separate from a session-free Bearer route. Both runtimes have local SQLite HTTP/TLS and real Chromium evidence; joint SQL/auth-file/PHP-session replay still rejects old authority. This does not complete all hosts or final recovery. See the [host record](state-http-integration-2026-10-21.md), including the HTML referrer-policy and test-certificate qualifications.

Native account API pending/current roots now retain the same exact intent: actor, target, verified credential digest, normalized arguments, actual identities/scopes, full source and exact policy. `StateOperation::credential()` describes intent and never grants authentication or approval. Role policy fingerprints cover all rules. Root formats 2/3 retain their existing structure; unknown effects never replay automatically. See the [intent and process-death record](state-api-intent-integration-2026-10-21.md).

The protected account credential factory now accepts `Security::apiCredentials($stateAccountPolicy)`. Its eight public paths validate native account, factor, session and credential snapshots before pending; ordinary rejection leaves authentication state unchanged. Existing construction and ordinary modes remain. Native requests must not be wrapped in `run()`. Delegation requires the same provider and a pure `RolePolicy`; custom or audited delegation, other API factories and final recovery remain incomplete. See the [public integration record](state-api-entry-integration-2026-10-21.md); prior fixed-epoch retirement evidence remains in its [historical record](state-managed-api-integration-2026-10-21.md).

Legacy `ApiKeys` now supports native subject epoch retirement through `StateApiKeyRetirement`, `apiKeyRetirementReview()` / `retireApiKeys()` and freshly approved continuation. A permanent marker rejects legacy records and mismatched new epochs; the marker alone does not establish freshness. Account fields and quarantine remain unchanged. Protected API factories still reject unsupported wiring, and older API workers must not join mixed deployments. See the [focused record](state-api-retirement-integration-2026-10-21.md).

Installation `prepare()` / `resume()` accept optional trailing `SessionRegistry` and its exact `FileStore`. Manifest 3 binds clearing sessions and remembered grants plus a fixed new epoch to the same approval; pending old logins cannot continue. Recovery must rebuild the matching graph. Manifest 2 retains its original installation semantics and does not claim session retirement. Accounts remain quarantined; legacy `ApiKeys` and other authorization effects remain open. See the [focused record](state-session-retirement-integration-2026-10-21.md).

File source fingerprints now use `FileSnapshot.Profile.3`: exactly 64 private staging slots (`stage-0` through `stage-63`), each bounded to 64 KiB, are validated but never adopted as authentication state. Protected FileStore and recovery writes reuse these slots; committed bytes remain covered. Older source declarations cannot be mixed, and deleting or initializing an existing witness is not migration. Three installation boundaries now have real SIGKILL and fresh-process continuation tests; see the [crash record](state-crash-integration-2026-10-21.md).

`StateCredentialInstallation` installs the fixed new factor and atomically replaces the account, directory record and ledger root after fresh independent strong approval. Unknown effects require the original persisted manifest, `credentialResolutionReview()` and a new purpose-bound grant. Completion retains disabled accounts and quarantine. Installation manifests use format 2; new audit records use format 2 while readers retain format 1 support. Older readers cannot join mixed deployments. See the [current installation record](state-installation-integration-2026-10-21.md).

`StateRecoveryCredentials` persistently prepares a fresh random password and encrypted TOTP in an independent protected FileStore. Candidates bind an exactly audited contained row, full sources and quarantined root, with at most four live candidates, 300 seconds and five proof attempts. Service reconstruction retains state; the independent witness rejects restored old files. `confirm()` requires the new password and a real TOTP, while `describe()` returns non-secret candidate metadata. Neither installs credentials nor reactivates an account; separately approved fixed installation and final recovery remain required. See the [candidate preparation record](state-credentials-integration-2026-10-21.md).

An explicit `StateRecoveryAudit` can now be passed as the final optional witness constructor argument. Retirement and quarantine transitions durably append signed records before publishing root references; missing, tampered or rolled-back history is rejected. `recoveryHistory()` returns at most four events per page and retains approvals and repeated resolution attempts across reloads. Capacity is fixed at 256 records, including orphans; no automatic adoption or pruning occurs. Legacy incomplete history stays marked incomplete, and audit availability does not imply final recovery. Formats 2/3 add a root field; older readers must not be mixed. See the [durable audit record](state-recovery-audit-integration-2026-10-21.md).

Unknown account-containment results can now continue through `accountResolutionReview()` / `resolveAccounts()` with a fresh `state.accounts.resolve` approval. Only row hashes durably recorded before the original SQL effects are accepted; old grants, legacy roots without a manifest and unreviewed bytes are rejected. Resolution retains the original disabling versions, trusted digest and quarantine. Format 3 field semantics are extended; mixed older readers are unsupported. See the [account resolution record](state-account-resolution-integration-2026-10-21.md).

Stale current and pending require separate retirement approvals. `staleReview()` / `retireStale()` require `state.retire_stale`; existing `retirementReview()` / `retirePending()` retain `state.retire_unknown`. Configure exact resource fields and recovery-operator roles explicitly. The new path preserves the trusted digest and only closes the authority for successor quarantine; it never adopts the backup digest or reactivates accounts. Valid format 2/3 state semantics are extended: older readers may reject new receipts, so mixed deployments are unsupported. See the [focused record](state-stale-integration-2026-10-21.md).

These explicit APIs are an unreleased candidate. The main SDK contains a witness, authentication boundaries and staged quarantine recovery. Complete factory and entrypoint integration, and final safe reactivation, remain unfinished. F01 and release acceptance remain open. See the [integration record](state-boundary-integration-2026-10-21.md) for exact snapshots and results. [简体中文](state-boundary.md).

## Independent state and declared coverage

An HMAC establishes integrity, not freshness. Restoring old account SQL, sessions and factor files together can restore old permissions and valid signatures. `LocalStateWitness` stores a signed checkpoint outside those backups. An entrypoint compares the complete sources, persists pending, then permits effects. A mismatch rejects the operation before identity-provider or business calls.

The host must declare all enabled account fields, directories, intents, audits, sessions, factors, persistent login and other authorization effects, and register every writer. Undeclared services do not become protected merely because a witness exists. Protected physical storage currently accepts only exactly covered `FileStore` instances, including namespace wrappers. Ordinary SDK support for other backends is unchanged; their protected adapters remain unfinished. An arbitrary digest callback cannot replace the required concrete adapter.

The witness, SQL/authentication files and capture scratch directories need independent physical domains. The SDK checks obvious overlap, the exact PDO, fixed sources and file identities. Deployment must also prevent restoring the witness with the business backup. Use concrete `SqlStateSnapshot`, `FileStateSnapshot` and `CompositeStateSnapshot` sources, with format 2 or recovery format 3. Format 1 is rejected for protected authentication.

Initialization is a separately approved first adoption, not application startup. Stop writers, review complete state and obtain its expected digest before explicitly calling `initialize($expectedDigest)`. Never automatically initialize from a newly observed digest after an error.

## Explicit authentication graph

This shows construction order after dependencies have been prepared; it does not declare sources, initialize state or provide a complete deployment. `$witness` must describe the exact approved graph. `$store` is its covered raw FileStore. Reuse the exact provider, managed factor, clock and keys; managed-factor workers also need a fence bound to this boundary. The explicit authentication configuration below now supports factory wiring; ordinary configuration does not automatically enable protection.

```php
$boundary = new SoSecurity\Account\StateBoundary($witness, $operationBudgets);
$requests = new SoSecurity\Account\StateRequests($publicRequestCheck, $currentAdmission);

$sessions = new SoSecurity\Auth\SessionRegistry(
    $store, $provider, $managedFactor, $clock, 1800, 28800, 16, $boundary
);
$authentication = new SoSecurity\Auth\AuthenticationFlow(
    $store, $provider, $sessions, $requests, $managedFactor, $clock,
    300, 10, 5, $boundary
);
$remember = new SoSecurity\Auth\RememberedLogin(
    $store, $provider, $sessions, $rememberKeys, $requests, $managedFactor, $clock,
    2592000, 8, 300, 5, $riskGuard, $boundary
);
```

`$operationBudgets($phase, $action)` must return exactly `true` for the `public` and `final` phases. Public request checks confirm origin, CSRF and request budgets before locking. `$currentAdmission($action, $scope)` performs read-only admission under the lock before pending. It must not mutate protected state, consume factors or issue permissions, and does not replace account authorization. Independent budgets must not write into the captured physical directory. Older unbound services cannot continue accessing a registered directory.

Nested session and factor calls share the outer checkpoint. Do not independently finalize a witness for each internal SQL transaction. Long-lived processes must reuse the exact boundary rather than replace a directory's authority by constructing another object. A process supports at most 128 physical-directory bindings. Generation changes require stopping old writers and bootstrapping processes again; hot unbinding is not provided.

Protected one-use grants also require the same explicit boundary:

```php
$grants = new SoSecurity\Operation\Grants(
    $store, $sessions, $authorizer, $grantRequestGuard, $grantPolicy, $clock, $boundary
);
```

`$grantRequestGuard` is the grant component's existing no-argument request check; do not directly pass `StateRequests`, which requires action and scope arguments. The host must complete public CSRF/origin and budget checks before entering the outer boundary. Defensive checks within an active context do not replace that phase. `SessionRegistry::requiresStateBoundary()` reports the mode only, not current permission. Protected sessions cannot be mixed with unprotected challenge or grant storage. See the [entry repair](state-entry-fix-2026-10-21.md).

## Explicit authentication factory

With the managed-factor configuration and exact services already prepared, add the following opt-in configuration. `$store` is the exact raw FileStore declared by the complete source. The identity service must be a `PasswordIdentityProvider`, the request guard implements `StateRequestGuard`, and the worker fence is bound to this same boundary and context. The current pure-policy profile requires one complete session/factor file domain and a matching factory/factor clock. This fragment does not create SQL schemas, witnesses or fences and is not a complete deployment:

```php
$config['authentication']['managed_factors'] = true;
$config['authentication']['state_boundary'] = [
    'authority' => 'state_authority',
    'store' => 'authentication_files',
    'scope' => $scope,
    'epoch' => $trustedEpoch,
];
$services['state_authority'] = $boundary;
$services['authentication_files'] = $store;
$sdk = SoSecurity\Security::fromArray($config, $services, $clock);
$policy = $sdk->stateAccountPolicy(
    $witness, $source, $sqlSource, $fileSource,
    $sqlName, $fileName, $accountTable, $columns
);
```

`$columns` is the fixed account table's eight-field mapping. Sources and names must match the exact witness. The factory reuses sessions, authentication, persistent login, directories, factor adapters and grants. Its pure policy uses those actual instances rather than reconstructed factor objects. Ordinary unprotected factory construction is preserved.

Configure a separate no-argument `operations.request_guard` and keep independent public budgets outside the authentication file domain. Diagnostics report matching dependencies as `manual`; they do not read the current witness, initialize state or prove deployment acceptance. Lifecycle services now accept an explicit `StateAccountConnection` covering the complete SQL source and require the exact outer boundary for execution; undeclared access refuses. See the [lifecycle integration record](state-lifecycle-integration-2026-10-21.md). Native request admission and complete workflow acceptance remain unfinished. Legacy reset-proof and other authorization/replay entrypoints that are not integrated still explicitly refuse this protected configuration. They remain requirements of the full plan. See the [factory integration record](state-factory-integration-2026-10-21.md) for exact capabilities, failures and limits.

## Public lifecycle admission

Registration, password recovery and lost-mailbox recovery can additionally configure `accounts.state_request_guard`, which must implement `StateRequestGuard`, after constructing the exact `StateAccountConnection`. Their `request`, `confirm` and `cancel` methods then own the outer operation; do not wrap them in another `run()`. Bounded input validation and public budget reservation finish before pending, the same reservation continues through later stages, and the request guard is rechecked under the lock. Business authority, managed recovery codes and independent approval remain required.

Address changes, private approval previews, initialization, notification reads and maintenance are outside this public entrypoint. A budget denial can complete pending only with confirmed owned rollback, a fresh execution context and unchanged complete sources; see the [budget refusal record](state-budget-integration-2026-10-21.md). Already committed progress, final witness budget denial and actual HTTP/CSRF acceptance remain unfinished. Request admission does not replace account or one-use operation authorization. See the [integration record](state-request-integration-2026-10-21.md) for exact ordering, the MySQL repair and remaining requirements.

## Current account authorization

For privileged operations, construct `StateAccountPolicy` from the exact graph, build a server-owned `StatePermission`, then call `StateBoundary::authorized($action, $scope, $target, $policy, $permission, $operation)`. Action, scope and target must match exactly. Required roles, strength, authentication age and methods are server policy, not copied request options.

The policy reads account, session, ledger and physical-factor state from the same witness-matching capture. It does not call another identity provider or consume a proof. Ordinary authorization denial occurs before pending and leaves subsequent valid requests usable. A `StatePermission` is not an approval by itself. `run()` does not replace request identity or object authorization; never map arbitrary client actions to executable closures.

## Persistence and failure handling

`LocalStatePersistence($canonicalDirectory, $milliseconds, $python)` is an optional Linux/Python 3 adapter. It requires the exact private 0700 directory, same-owner 0600 single-link files and process-control functions. Construction creates no state and starts no process. Invocation validates the exact inherited file and directory descriptors and calls `fsync`, including after atomic rename. Neither `fflush()` nor an always-true callback is a substitute. Basic password and CSRF components do not depend on this adapter.

| Outcome | Host action |
| --- | --- |
| Ordinary admission or authorization denial | Return a uniform denial; do not clear or recreate the witness |
| `account.witness_stale` | Stop business effects for the affected graph, inspect restores and out-of-bound writes, enter independent recovery |
| `account.witness_pending` | Retain unresolved state; do not replay the original operation or adopt the database |
| `account.completion_unknown` | Retain the original root, error and actual SQL/physical effects for independent review and reconciliation |
| `storage.clock` or a budget timeout | Retain refusal; if pending was entered, treat completion as unknown rather than extending the deadline |

A SQL rollback does not prove that mail, external approvals or files were rolled back. AtomicStore transaction callbacks remain pure and retry-safe: keep I/O, randomness and witness operations outside them. Return success only after completion; unknown effects must not be automatically retried.

`StateRetirementControl` and the review/fixed-remediation types support independent current administrators, recent strong authentication, one-use approval, closing the old root, quarantining a successor and exact account/factor remediation with continuation. **These steps still leave the successor quarantined. There is no final business-reactivation commit API yet.** Disabled accounts or removed factors are not complete successful recovery.

Local checks include actual joint backup restores and dangerous controls that deliberately omit protection. They cover the declared test graph, not every enabled capability or real power-loss durability. The private PHP7.2 monotonic-clock qualifier, Fiber differences, MySQL metadata privileges and unexecuted checks are recorded in [verification](verification.md). Complete acceptance follows the [finite-cycle plan](full-plan-2026-10-21.md).

## Bearer authorization and an owned business PDO transaction

Native protected registries expose `withAuthorization(scope, authorizationHeader, requiredScope, pdo, tables, businessPolicy, prepare, work)`. Call it directly without an outer boundary or a host transaction. Use the exact PDO from the complete SQL snapshot and declare one to four complete business table definitions (`columns`, `primary`, optional `where`) already covered by that source.

The witness lock spans read-only native bearer admission, `prepare(PDO, VerifiedCredential)` loading a server-owned `Operation\Intent`, pure `RolePolicy` object and requested-field checks, durable pending, actual credential revalidation/usage recording, an SDK-owned SQL transaction and final source/current confirmation. Read-only admission failures precede pending; actual credentials are revalidated in the effect phase. `work(PDO, VerifiedCredential, Intent)` executes once; its result becomes successful only when the entire method returns successfully. The receipt binds the intent, business policy, table names, credential digest and complete source without storing plaintext business parameters.

These are trusted host callbacks, not a PHP/SQL sandbox. `prepare` must only read; `work` must use the supplied PDO and validated intent with version comparison updates. Do not perform DDL, transaction control, independent-connection writes or external effects. All relevant writers must share the witness and fence. Check expiry/backwards time before and after commit. A SQL rollback does not undo credential-file usage; effect-stage failures, lost transaction ownership and final confirmation failures retain pending with no automatic replay. [StateDocuments.php](../examples/StateDocuments.php) demonstrates server-loaded ownership, editor/title policy and compare-and-update; it provisions no schema.

## Native business HTTP host

The private managed-authentication bootstrap may return exactly `security`, `state_policy`, `business_connection`, in that order; the final value is the same PDO used by the complete SQL source. The original two-field protected bundle and ordinary Security object remain available. Provision and declare business tables through an independently controlled migration before first trusted witness initialization, never during a request.

`POST /managed-authentication.php?api=document` accepts a bounded URL-encoded form containing only `action=rename`, `id`, `version`, `title`. Require JSON Accept and actual Authorization Bearer with `records:write`; Cookie, CSRF and client-asserted ownership cannot replace permission. A supplied Origin must match the configured fixed origin. The server loads the document and checks editor/owner/title policy, then compare-and-updates its version. The response contains the id and new version, starts no PHP session and issues no Cookie or CSRF token. [Host evidence](state-business-host-integration-2026-10-21.md) records the finite format-3 TLS/browser, joint restore, three actual SIGKILL points and concurrent-writer refusal. Pending never triggers automatic replay or exposes recovery/maintenance over HTTP.

## Native one-use operations

`Security::operations(stateAccountPolicy)` opts into native read-only admission using the exact authentication store/session/clock graph and a matching pure RolePolicy. A mismatching provider, custom policy or effectful audit is rejected at construction. The default `operations()` preserves manual outer-authorized composition; the two cached modes are separate and native instances cannot be enlisted as manual recovery-control dependencies.

Call begin/confirm/consume/revoke/revokeAll directly without an outer boundary. Ordinary current-session/object/field/capacity refusals precede pending. Existing one-use semantics remain: confirmation requires a new secret in the same registry session, and an authentic bound proof with authorized but changed parameters is intentionally burned. A consumed Permit is an immediate result, never a reusable credential.

For protected business work use `execute(scope, subject, sessionToken, grant, pdo, tables, prepare, work)`: read-only prepare receives the exact PDO and current VerifiedSession and returns a validated server Intent; policy and proof checks precede pending, then proof consumption, one owned SQL transaction and final complete-source/current confirmation share the same witness. work(PDO, Permit) runs once. Declare complete covered tables; no DDL, transaction control, other connections or external effects. Check expiry/backwards time around commit. Rollback does not restore the file-backed proof, and unknown effects retain pending without replay. [StateDocumentGrants.php](../examples/StateDocumentGrants.php) is the concrete compare-and-update consumer. [Evidence and open requirements](state-grants-integration-2026-10-22.md) distinguish actual SDK password/TOTP and SQL from unexecuted HTTP/device, process-death and final-recovery acceptance.

Native operation factories pin the cached service to its semantic account-policy binding: equivalent new policy objects reuse it; changed column mappings are rejected before I/O. Initial and corrected inputs and targeted checks are recorded separately.
