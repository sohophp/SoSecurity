#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_runtime=${1:-php}
"$task_runtime" bin/lint.php
"$task_runtime" bin/api-contract.php
python3 tests/lock_inventory.py "$task_runtime"
"$task_runtime" tests/portable-core.php
"$task_runtime" -d memory_limit=8M tests/state-budget-context.php
"$task_runtime" -d memory_limit=8M tests/deadline-clock.php
"$task_runtime" -d memory_limit=8M tests/deadline-failure-kind.php
"$task_runtime" -d memory_limit=8M tests/audit-budget.php
"$task_runtime" -d memory_limit=8M tests/audit-budgeted-sink.php
python3 tests/audit_budgeted_process.py "$task_runtime"
"$task_runtime" -d memory_limit=8M tests/audit-metrics.php
"$task_runtime" -d memory_limit=8M tests/audit-diagnostics.php
"$task_runtime" -d memory_limit=8M tests/audit-recent-events.php
python3 tests/audit_recent_process.py "$task_runtime" file
python3 tests/audit_metrics_process.py "$task_runtime"
"$task_runtime" tests/run.php
if "$task_runtime" -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
    "$task_runtime" -d memory_limit=8M tests/key-export.php
    "$task_runtime" tests/mfa-enrollment-export.php
else
    "$task_runtime" tests/hmac-no-sodium.php
fi
"$task_runtime" tests/captcha.php
"$task_runtime" tests/csrf-time.php
"$task_runtime" tests/captcha-providers.php
"$task_runtime" -d memory_limit=8M tests/secret-config-export.php
"$task_runtime" -d memory_limit=8M tests/bearer-object-export.php
"$task_runtime" -d memory_limit=8M tests/transport-value-export.php
"$task_runtime" tests/mfa.php
"$task_runtime" tests/mfa-authority-clock.php
"$task_runtime" tests/auth.php
"$task_runtime" -d memory_limit=32M tests/session-current-authority.php
"$task_runtime" -d memory_limit=8M tests/auth-export.php
"$task_runtime" tests/remember.php
"$task_runtime" tests/device-risk.php
"$task_runtime" -d memory_limit=16M tests/remember-risk-boundary.php memory
"$task_runtime" -d memory_limit=16M tests/remember-risk-boundary.php file
"$task_runtime" tests/password.php
"$task_runtime" tests/password-dependencies.php
"$task_runtime" tests/authorization.php
for task_case in revoked unsupported fault fields expanded resource denied same batch; do
    "$task_runtime" tests/authorization-audit-policy.php "$task_case"
done
for task_case in projection audit; do
    "$task_runtime" tests/authorization-callback-boundary.php "$task_case"
done
for task_case in validation role session quarantine bcrypt argon2id webhook config outbound upload credential signature account idempotency outbox download processing html processing_backoff; do
    "$task_runtime" -d memory_limit=8M tests/schema-option-budget.php "$task_case"
done
for task_case in export dump print serialize wakeup; do
    "$task_runtime" -d memory_limit=32M tests/storage-change-privacy.php "$task_case"
done
for task_case in value key aggregate; do
    "$task_runtime" -d memory_limit=32M tests/storage-encode-budget.php "$task_case"
done
"$task_runtime" -d memory_limit=32M tests/permission-list-budget.php
for task_case in root record; do
    "$task_runtime" -d memory_limit=32M tests/credential-state-budget.php "$task_case"
done
for task_case in scopes allowlist methods; do
    "$task_runtime" -d memory_limit=32M tests/credential-list-budget.php "$task_case"
done
"$task_runtime" tests/policy-option-boundaries.php
"$task_runtime" tests/budgets.php
"$task_runtime" tests/native-report-budget.php
"$task_runtime" tests/leases.php
"$task_runtime" tests/proof-epoch.php
"$task_runtime" tests/operations.php
"$task_runtime" tests/links.php
for task_clock_entry in issue verify; do
    "$task_runtime" tests/link-clock-failure.php "$task_clock_entry"
done
"$task_runtime" tests/downloads.php
for download_case in normal writer-send writer-read writer-send-swallow reader-read reader-read-swallow reload-read reload-read-swallow grant-read grant-read-swallow closer-send closer-send-swallow writer-headers writer-status; do
    "$task_runtime" -d memory_limit=8M tests/download-reentry.php "$download_case"
done
for download_case in close-denial close-expiry close-version close-error head-denial writer-denial writer-version writer-expiry normal; do
    "$task_runtime" tests/download-completion.php "$download_case"
done
"$task_runtime" -d memory_limit=8M tests/download-stream.php
"$task_runtime" tests/session.php
"$task_runtime" tests/hardening.php
"$task_runtime" -d memory_limit=8M tests/cookie-budget.php
for task_case in uri_host cookie_domain cookie_path ip_rule; do
    "$task_runtime" -d memory_limit=8M tests/input-normalization-budget.php "$task_case"
done
for task_case in validation uri; do
    "$task_runtime" -d memory_limit=8M tests/value-container-privacy.php "$task_case"
done
for task_case in diagnostics recent; do
    "$task_runtime" -d memory_limit=8M tests/audit-read-revocation.php "$task_case"
done
"$task_runtime" -d memory_limit=8M tests/input-boundaries.php
"$task_runtime" -d memory_limit=8M tests/device-risk-budget.php
"$task_runtime" tests/storage-failure.php
"$task_runtime" tests/file-store-integrity.php
"$task_runtime" tests/file-store-lock-metadata.php
python3 tests/file_store_nodes.py "$task_runtime"
"$task_runtime" tests/configuration.php
"$task_runtime" tests/configuration-presets.php
"$task_runtime" tests/preset-shared-budget.php file
"$task_runtime" tests/validation.php
"$task_runtime" tests/http-policy.php
"$task_runtime" tests/outbound.php
for outbound_case in normal doh-normal resolver-fault transport-fault transport-known transport-unknown doh-fault doh-late doh-first-late doh-headers; do
    "$task_runtime" -d memory_limit=8M tests/outbound-adapter.php "$outbound_case"
done
"$task_runtime" tests/api.php
"$task_runtime" tests/hmac-state.php
"$task_runtime" tests/api-epoch.php
"$task_runtime" tests/api-key-time.php
"$task_runtime" tests/credentials.php
"$task_runtime" tests/credential-extra-arguments.php authenticate
"$task_runtime" tests/credential-extra-arguments.php fromAuthorization
"$task_runtime" tests/credential-management-scope.php
"$task_runtime" -d memory_limit=8M tests/snapshot-policy.php
"$task_runtime" tests/webhooks.php
"$task_runtime" -d memory_limit=8M tests/webhook-key-export.php
"$task_runtime" tests/signed-csrf.php
if [[ -f integrations/htmlpurifier/vendor/autoload.php ]]; then
    "$task_runtime" tests/html.php
    "$task_runtime" tests/html-provider-errors.php exception
    "$task_runtime" tests/html-provider-errors.php output
else
    echo 'NOT RUN optional HTML cleaner: install integrations/htmlpurifier Composer project'
    if [[ ${SOSECURITY_REQUIRE_HTML:-0} == 1 ]]; then exit 1; fi
fi
"$task_runtime" tests/html-dependencies.php
"$task_runtime" tests/html-dependencies.php old
"$task_runtime" tests/upload.php
"$task_runtime" tests/upload-export.php
"$task_runtime" -d memory_limit=8M tests/upload-read-budget.php
python3 tests/archive_inspection.py "$task_runtime"
"$task_runtime" -d memory_limit=8M tests/upload-quarantine.php
"$task_runtime" -d memory_limit=8M tests/upload-quarantine-factory.php
python3 tests/upload_clamav.py "$task_runtime"
if [[ ${SOSECURITY_REQUIRE_QUARANTINE_HTTP:-0} == 1 ]]; then
    python3 tests/upload_quarantine_http.py "$task_runtime" --tls
fi
if "$task_runtime" -r 'exit(extension_loaded("pdo_sqlite") ? 0 : 1);'; then
    "$task_runtime" -d memory_limit=8M tests/sql-caught-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-read-in-fallback.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-read-in-readonly.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-policy-drift.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-read-in-owner.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-read-wait-restore.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-read-wait-restore-failure.php sqlite
    "$task_runtime" -d memory_limit=8M tests/sql-caught-cleanup-reentrant.php sqlite
    "$task_runtime" -d memory_limit=8M tests/private-schema-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/ledger-read-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/ledger-read-values.php sqlite
    "$task_runtime" -d memory_limit=8M tests/ledger-write-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/queued-write-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/outbox-sent-purge.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-pending-read.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-pending-authority.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-processing-budget.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-processing-read-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-schema-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-metadata-budget.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-receive-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/audit-sql-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/idempotency-observation-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/queued-page-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/queued-read-cleanup.php sqlite
    "$task_runtime" -d memory_limit=8M tests/snapshot-stream-cleanup.php sqlite
    for task_snapshot_test in schema-batch schema-batch-bounds schema-roundtrips sql capture capture-commit files file-view file-headroom composite-view composite-references example slot-pages slot-page-bounds slot-page-bytes slot-page-race slot-page-filter; do
        "$task_runtime" -d memory_limit=8M "tests/state-snapshot/${task_snapshot_test}.php" sqlite
    done
    "$task_runtime" -d memory_limit=8M tests/fence-state.php
    "$task_runtime" -d memory_limit=8M tests/account-foundation.php
    for task_checkpoint_mode in normal missing changed other-corrupt deleted-other body-corrupt paged; do
        "$task_runtime" -d memory_limit=8M tests/ledger-checkpoint-read.php sqlite "$task_checkpoint_mode"
    done
    for task_initial_mode in normal missing other-corrupt deleted-other body-corrupt paged; do
        "$task_runtime" -d memory_limit=8M tests/ledger-initial-checkpoint.php sqlite "$task_initial_mode"
    done
    if "$task_runtime" -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
        python3 tests/native_credential_cold.py "$task_runtime" sqlite native
        for task_checkpoint_mode in normal binding return-denial return-account-change return-body-change; do
            "$task_runtime" -d memory_limit=32M tests/factor-checkpoint-read.php sqlite "$task_checkpoint_mode"
        done
        for task_initial_mode in normal binding account-disabled account-unverified account-valid-write account-delete account-body account-root initial-root-corrupt initial-body-corrupt before-denial current-denial; do
            "$task_runtime" -d memory_limit=32M tests/factor-initial-read.php sqlite "$task_initial_mode"
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/fresh-provision.php
        "$task_runtime" -d memory_limit=32M tests/state-boundary/fresh-authentication.php
        "$task_runtime" -d memory_limit=32M tests/state-boundary/fresh-webhook-shared.php
        for task_account_test in mailbox-recovery mailbox-recovery-approvals mailbox-recovery-safety mailbox-recovery-maintenance mailbox-recovery-dispatch mailbox-recovery-factory mailbox-recovery-wrong-target mailbox-recovery-wrong-purpose mailbox-recovery-concurrency account-send-budgets account-dispatch account-factor-notices account-mail-factory password-baseline account-recovery account-recovery-maintenance account-recovery-factory account-recovery-clock account-recovery-concurrency account-budgets account-budget-sql account-factory account-ledger registration-authority account-request-budget registration registration-capacity registration-maintenance maintenance-completion-authority registration-ledger-maintenance address-lock-order address-change-maintenance address-change; do
            "$task_runtime" -d memory_limit=8M "tests/${task_account_test}.php"
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite
        "$task_runtime" -d memory_limit=32M tests/proof-state.php sqlite normal
        "$task_runtime" -d memory_limit=32M tests/proof-state.php sqlite race
        "$task_runtime" -d memory_limit=32M tests/proof-deadline-construction.php
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory proofs
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory audit_write sink-budget
        "$task_runtime" -d memory_limit=32M tests/current-worker-context.php sqlite all
        "$task_runtime" -d memory_limit=32M tests/current-worker-read.php sqlite all
        for task_address_captured_case in normal role deny fields fault selector-fault reentry effect-deny return-deny effect-fault return-fault changed effect-reentry request-late-before request-late-commit request-late-complete complete-late-before complete-late-commit complete-late-complete request-final-guard complete-final-guard request-final-fault complete-final-fault request-final-expiry complete-final-expiry request-final-reentry complete-final-reentry proposal-final-guard completion-proposal-final-guard request-flow-final-expiry; do
            "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory address_actions "captured-$task_address_captured_case"
        done
        for task_business_budget in business-budget-before business-budget-after; do
            "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory audit_delegation "$task_business_budget"
        done
        for task_captured_feature in links grants; do
            for task_captured_mode in normal deny fields fault selectors-fault reentry effect-deny return-deny; do
                "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory audit_delegation "captured-permission-$task_captured_feature-$task_captured_mode"
            done
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory audit_delegation captured-permission-grants-changed
        for task_audit_mode in reset-proof-return-issue-normal reset-proof-return-consume-guard reset-proof-return-execute-expiry reset-proof-return-revoke-guard link-return-issue-normal link-return-issue-guard link-return-verify-guard link-return-execute-expiry link-return-all-guard link-return-revoke-guard hmac-return-verify-normal hmac-return-verify-guard hmac-return-verify-fault hmac-return-verify-clock hmac-return-execute-normal hmac-return-execute-expiry operation-return-begin-normal operation-return-begin-guard operation-return-confirm-normal operation-return-confirm-fault operation-return-consume-guard operation-return-execute-normal operation-return-execute-expiry policy-business-normal policy-business-denied policy-business-fields policy-business-foreign policy-business-before-fault policy-business-return-fault policy-business-return-denied bearer-auth-normal bearer-auth-guard bearer-auth-scope bearer-auth-expiry bearer-auth-narrow bearer-auth-grow bearer-auth-invalid bearer-auth-guard-fault bearer-auth-scope-fault bearer-auth-reentry bearer-auth-budget bearer-auth-extra-scalar bearer-auth-extra-object bearer-header-normal bearer-header-guard bearer-header-scope bearer-header-expiry bearer-header-narrow bearer-header-grow bearer-header-invalid bearer-header-guard-fault bearer-header-scope-fault bearer-header-reentry bearer-header-budget bearer-header-extra-scalar bearer-header-extra-object business-normal business-guard business-scope business-expiry custom-data-denied custom-selector-write custom-selector-fault custom-selector-invalid custom-before-fault custom-return-fault custom-audit custom-plain custom-denied custom-denied-plain custom-return custom-return-plain custom-fault custom-write custom-reentry read-factor-locations read-pair audit-admission-timeout post-audit-delay post-audit-denial post-audit-timeout normal return-denial return-expiry return-scope return-fault return-clock defaults; do
            "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory audit_delegation "$task_audit_mode"
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory factor_notices
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory outbox_rotation
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory dispatch_budgets
        "$task_runtime" -d memory_limit=32M tests/outbox-rotation.php sqlite
        "$task_runtime" -d memory_limit=32M tests/state-boundary/operation-deadline.php sqlite
        "$task_runtime" -d memory_limit=32M tests/outbox-initial-claim.php sqlite
        for task_initial_mode in normal expiry budget prewrite defaults current current-expiry current-late-expiry ack ack-expiry ack-late-role ack-late-expiry reject reject-expiry reject-late-role reject-late-expiry; do
            "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory outbox_initial "$task_initial_mode"
        done
        "$task_runtime" -d memory_limit=32M tests/sql-observation-schema.php
        "$task_runtime" -d memory_limit=32M tests/sql-schema-queries.php
        "$task_runtime" -d memory_limit=8M tests/sql-schema-index-batch.php
        "$task_runtime" -d memory_limit=32M tests/outbox-initial-race.php
        "$task_runtime" -d memory_limit=32M tests/factor-notice-completion.php sqlite
        "$task_runtime" -d memory_limit=32M tests/proof-state.php sqlite restore
        "$task_runtime" -d memory_limit=32M tests/proof-state.php sqlite late
        "$task_runtime" -d memory_limit=32M tests/proof-state.php sqlite expiry-admission
        "$task_runtime" -d memory_limit=32M tests/proof-state.php sqlite expiry-late
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory mapping
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory clock
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory recovery
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php sqlite factory mailbox_recovery
        "$task_runtime" -d memory_limit=8M tests/account-state-codecs.php
        python3 tests/state_boundary.py "$task_runtime"
        python3 tests/account_factor.py "$task_runtime"
        python3 tests/managed_auth_http.py "$task_runtime"
        task_state_browser=()
        if [[ ${SOSECURITY_REQUIRE_STATE_BROWSER:-0} == 1 ]]; then task_state_browser+=(--browser); fi
        python3 tests/state_http.py "$task_runtime" "${task_state_browser[@]}"
        if command -v openssl >/dev/null; then
            python3 tests/state_http.py "$task_runtime" --tls "${task_state_browser[@]}"
            python3 tests/state_http.py "$task_runtime" --tls --business "${task_state_browser[@]}"
        else
            python3 tests/state_http.py "$task_runtime" --business "${task_state_browser[@]}"
        fi
        python3 tests/mailbox_recovery_smtp.py "$task_runtime"
        python3 tests/account_smtp_local.py "$task_runtime"
        python3 tests/account_mail_pipeline.py "$task_runtime"
        python3 tests/account_factor_smtp.py "$task_runtime"
        python3 tests/account_send_budget_race.py "$task_runtime"
        python3 tests/account_mail_cli.py "$task_runtime"
        python3 tests/account_change_concurrency.py "$task_runtime" sqlite
    else
        echo 'NOT RUN account lifecycle SQL: sodium unavailable'
        if [[ ${SOSECURITY_REQUIRE_CRYPTO:-0} == 1 ]]; then exit 1; fi
    fi
    "$task_runtime" tests/sql-enlistment.php
    "$task_runtime" -d memory_limit=16M tests/sql-context.php
    "$task_runtime" tests/sql-operation-budget.php sqlite
    "$task_runtime" tests/sql-lock-timeout.php sqlite
    "$task_runtime" tests/sql-zero-lock.php
    "$task_runtime" tests/sql-projection-alias.php
    "$task_runtime" tests/sql-projection-text.php
    "$task_runtime" -d memory_limit=8M tests/file-snapshot-memory.php
    "$task_runtime" -d memory_limit=16M tests/sql-schema-reuse.php
    "$task_runtime" -d memory_limit=16M tests/sql-schema-pair.php
    "$task_runtime" -d memory_limit=16M tests/sql-schema-unexpected-unique.php
    "$task_runtime" -d memory_limit=16M tests/sql-schema-consumers.php
    "$task_runtime" -d memory_limit=16M tests/sql-schema-trigger-case.php
    "$task_runtime" -d memory_limit=8M tests/sql-schema-dependencies.php
    "$task_runtime" tests/outbox.php
    "$task_runtime" -d memory_limit=8M tests/audit-alert-outbox.php
    "$task_runtime" -d memory_limit=8M tests/audit-alert-retained.php
    "$task_runtime" -d memory_limit=32M tests/audit-window-archive.php sqlite all
    "$task_runtime" -d memory_limit=8M tests/audit-alert-worker.php
    "$task_runtime" -d memory_limit=8M tests/account-checkpoint-budget.php normal
    "$task_runtime" -d memory_limit=8M tests/account-checkpoint-budget.php oversize
    for task_audit_sink in budgeted metrics recent sql; do
        "$task_runtime" -d memory_limit=8M tests/audit-record-budget.php "$task_audit_sink"
    done
    "$task_runtime" -d memory_limit=8M tests/audit-sql.php
    "$task_runtime" -d memory_limit=8M tests/audit-sql-history.php
    "$task_runtime" -d memory_limit=8M tests/audit-sql-fault.php
    "$task_runtime" -d memory_limit=8M tests/audit-sql-pipeline.php
    python3 tests/audit_sql_process.py "$task_runtime"
    "$task_runtime" tests/outbox-safety.php
    "$task_runtime" -d memory_limit=8M tests/outbox-reconciliation.php
    "$task_runtime" tests/outbox-reconciliation-concurrency.php
    "$task_runtime" tests/outbox-factory.php
    "$task_runtime" -d memory_limit=8M tests/outbox-native.php
    "$task_runtime" -d memory_limit=8M tests/outbox-authority.php
    "$task_runtime" -d memory_limit=8M tests/outbox-recovery.php
    "$task_runtime" -d memory_limit=8M tests/outbox-resolution.php
    "$task_runtime" -d memory_limit=8M tests/outbox-resolution-archive.php
    "$task_runtime" -d memory_limit=8M tests/outbox-archive-budget.php
    "$task_runtime" -d memory_limit=8M tests/outbox-archive-schema.php
    "$task_runtime" -d memory_limit=8M tests/outbox-index-budget.php
    "$task_runtime" tests/outbox-concurrency.php
    "$task_runtime" -d memory_limit=8M tests/outbox-input-bounds.php
    "$task_runtime" -d memory_limit=8M tests/outbox-private-export.php
    "$task_runtime" -d memory_limit=8M tests/outbox-body-budget.php
    "$task_runtime" -d memory_limit=32M tests/outbox-hard-limit.php
    "$task_runtime" tests/reset-flow.php
    "$task_runtime" tests/authorization-audit-policy-sql.php sqlite
    "$task_runtime" tests/authorization-sql.php
    "$task_runtime" tests/lease-sql.php
    "$task_runtime" tests/operation-sql.php
    "$task_runtime" -d memory_limit=16M tests/webhook-schema.php sqlite
    "$task_runtime" tests/webhook-inbox.php
    "$task_runtime" -d memory_limit=16M tests/webhook-lock-timeout.php sqlite
    "$task_runtime" -d memory_limit=16M tests/webhook-lock-policy.php sqlite
    "$task_runtime" -d memory_limit=8M tests/webhook-request-authority.php
    "$task_runtime" -d memory_limit=8M tests/webhook-clock-failure.php
    "$task_runtime" tests/webhook-inbox-concurrency.php
    "$task_runtime" tests/webhook-completion-authority.php
    for task_api_mode in normal epoch late-deny late-expiry budget race; do
        "$task_runtime" -d memory_limit=32M tests/api-key-state.php sqlite "$task_api_mode"
    done
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php sqlite mapping-change
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php sqlite completion-revoke
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php sqlite processing-failure
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php sqlite processing-late-revoke
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php sqlite processing-race
    "$task_runtime" -d memory_limit=16M tests/webhook-state-source.php
    "$task_runtime" -d memory_limit=16M tests/webhook-state-access.php
    "$task_runtime" tests/webhook-processing.php
    "$task_runtime" -d memory_limit=8M tests/webhook-body-budget.php
    "$task_runtime" tests/webhook-processing-factory.php
    "$task_runtime" tests/webhook-processing-concurrency.php
    "$task_runtime" tests/webhook-processing-ownership.php
    "$task_runtime" tests/webhook-processing-ownership.php sqlite inbox
    "$task_runtime" tests/idempotency.php
    "$task_runtime" tests/idempotency-safety.php
    "$task_runtime" -d memory_limit=8M tests/idempotency-input-bounds.php
    "$task_runtime" -d memory_limit=8M tests/idempotency-body-budget.php
    "$task_runtime" tests/idempotency-factory.php
    "$task_runtime" tests/idempotency-concurrency.php
else
    echo 'NOT RUN reset host integration: test-only ext-pdo_sqlite required'
    if [[ ${SOSECURITY_REQUIRE_RESET:-0} == 1 ]]; then exit 1; fi
fi
if command -v redis-server >/dev/null && command -v redis-cli >/dev/null && "$task_runtime" -r 'exit(extension_loaded("redis") ? 0 : 1);'; then
    task_redis_dir=$(mktemp -d /tmp/sosecurity-redis.XXXXXXXX)
    task_redis_socket="$task_redis_dir/redis.sock"
    printf 'owned SDK audit metrics test\n' > "$task_redis_dir/audit-metrics-owner"
    cleanup() {
        redis-cli -s "$task_redis_socket" shutdown nosave >/dev/null 2>&1 || true
        rm -rf -- "$task_redis_dir"
    }
    trap cleanup EXIT
    redis-server --port 0 --unixsocket "$task_redis_socket" --unixsocketperm 700 --dir "$task_redis_dir" --save '' --appendonly no --daemonize yes --pidfile "$task_redis_dir/redis.pid" --logfile "$task_redis_dir/redis.log"
    export SOSECURITY_TEST_REDIS_SOCKET="$task_redis_socket"
    "$task_runtime" tests/redis.php
    "$task_runtime" tests/api.php
"$task_runtime" tests/api-epoch.php
    if command -v python3 >/dev/null; then
        python3 tests/preset_redis.py "$task_runtime"
        python3 tests/audit_metrics_process.py "$task_runtime" redis
        "$task_runtime" -d memory_limit=8M tests/audit-metrics-fault.php redis
        "$task_runtime" -d memory_limit=8M tests/audit-recent-events.php redis
        python3 tests/audit_recent_process.py "$task_runtime" redis
        python3 tests/redis_restart.py "$task_runtime"
        python3 tests/quarantine_redis.py "$task_runtime" budget
        python3 tests/quarantine_redis.py "$task_runtime" quarantine
    fi
else
    if [[ ${SOSECURITY_REQUIRE_REDIS:-0} == 1 ]]; then
        echo 'FAIL Redis integration prerequisites missing' >&2
        exit 1
    fi
    echo 'NOT RUN Redis integration: redis-server, redis-cli and ext-redis required'
fi
if [[ -n ${SOSECURITY_TEST_MYSQL_SOCKET:-} ]]; then
    python3 tests/mysql_check.py --ledger-shared-visibility "$task_runtime"
    python3 tests/mysql_check.py --ledger-durable-context "$task_runtime"
    python3 tests/mysql_check.py --sql-policy-drift "$task_runtime"
    python3 tests/mysql_check.py --ledger-final-structure "$task_runtime"
    python3 tests/mysql_check.py --ledger-context-pool "$task_runtime"
    python3 tests/mysql_check.py --fixed-variable-format "$task_runtime"
    python3 tests/mysql_check.py --private-schema-cleanup "$task_runtime"
    python3 tests/mysql_check.py --ledger-read-cleanup "$task_runtime"
    python3 tests/mysql_check.py --ledger-read-values "$task_runtime"
    python3 tests/mysql_check.py --ledger-write-cleanup "$task_runtime"
    python3 tests/mysql_check.py --queued-write-cleanup "$task_runtime"
    python3 tests/mysql_check.py --outbox-sent-purge "$task_runtime"
    python3 tests/mysql_check.py --webhook-pending-read "$task_runtime"
    python3 tests/mysql_check.py --webhook-pending-authority "$task_runtime"
    python3 tests/mysql_check.py --webhook-processing-budget "$task_runtime"
    python3 tests/mysql_check.py --webhook-processing-read-cleanup "$task_runtime"
    python3 tests/mysql_check.py --webhook-schema-cleanup "$task_runtime"
    python3 tests/mysql_check.py --webhook-metadata-budget "$task_runtime"
    python3 tests/mysql_check.py --webhook-receive-cleanup "$task_runtime"
    python3 tests/mysql_check.py --audit-sql-cleanup "$task_runtime"
    python3 tests/mysql_check.py --idempotency-observation-cleanup "$task_runtime"
    python3 tests/mysql_check.py --queued-page-cleanup "$task_runtime"
    python3 tests/mysql_check.py --queued-read-cleanup "$task_runtime"
    python3 tests/mysql_check.py --snapshot-locked-schema "$task_runtime"
    python3 tests/mysql_check.py --snapshot-stream-cleanup "$task_runtime"
    python3 tests/mysql_check.py --snapshot-text-pool "$task_runtime"
    python3 tests/mysql_check.py --snapshot-resolution "$task_runtime"
    python3 tests/mysql_check.py --snapshot-resolution-locks "$task_runtime"
    python3 tests/mysql_check.py --sql-snapshot-context "$task_runtime"
    python3 tests/mysql_check.py --sql-database-bytes "$task_runtime"
    python3 tests/mysql_check.py --ledger-shared-permissions "$task_runtime"
    python3 tests/mysql_check.py --ledger-partial-revokes-cleanup "$task_runtime"
    python3 tests/mysql_check.py --sql-read-wait-pair "$task_runtime"
    python3 tests/mysql_check.py --sql-read-wait-restore "$task_runtime"
    python3 tests/mysql_check.py --sql-wait-native-delay "$task_runtime"
    python3 tests/mysql_check.py --sql-read-in-readonly "$task_runtime"
    python3 tests/mysql_check.py --sql-cleanup-regression "$task_runtime"
    if "$task_runtime" -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
        python3 tests/native_credential_cold.py "$task_runtime" mysql native
    fi
    python3 tests/mysql_check.py --sql-lock-limit "$task_runtime"
    python3 tests/mysql_check.py --ledger-root-batch "$task_runtime"
    python3 tests/mysql_check.py --ledger-statements "$task_runtime"
    python3 tests/mysql_check.py --ledger-context-batch "$task_runtime"
    python3 tests/mysql_check.py --sql-lock-timeout "$task_runtime"
    python3 tests/mysql_check.py --sql-metadata-wait "$task_runtime"
    python3 tests/mysql_check.py --mysql-store-lock-timeout "$task_runtime"
    python3 tests/mysql_check.py --mysql-store-constructor "$task_runtime"
    python3 tests/mysql_check.py --webhook-lock-policy "$task_runtime"
    python3 tests/mysql_check.py --sql-operation-budget "$task_runtime"
    python3 tests/mysql_check.py --sql-fixed-context "$task_runtime"
    python3 tests/mysql_check.py --sql-owned-entry "$task_runtime"
    python3 tests/mysql_check.py --sql-guard-cursor "$task_runtime"
    python3 tests/mysql_check.py --sql-unit-precheck "$task_runtime"
    python3 tests/mysql_check.py --sql-witness-transport "$task_runtime"
    python3 tests/mysql_check.py --sql-witness-batch "$task_runtime"
    python3 tests/mysql_check.py --sql-durable-statements "$task_runtime"
    python3 tests/mysql_check.py --mysql-resolved-table "$task_runtime"
    python3 tests/mysql_check.py --native-address-captured "$task_runtime"
    python3 tests/mysql_check.py --current-worker-context "$task_runtime"
    python3 tests/mysql_check.py --audit-window-archive "$task_runtime"
    python3 tests/mysql_check.py --current-worker-read "$task_runtime"
    "$task_runtime" tests/preset-shared-budget.php mysql
    "$task_runtime" tests/authorization-audit-policy-sql.php mysql
    "$task_runtime" tests/sql-enlistment.php mysql
    "$task_runtime" -d memory_limit=16M tests/sql-context.php mysql
    "$task_runtime" -d memory_limit=16M tests/sql-schema-reuse.php mysql
    "$task_runtime" -d memory_limit=16M tests/sql-schema-pair.php mysql
    "$task_runtime" -d memory_limit=16M tests/remember-risk-boundary.php mysql
    "$task_runtime" -d memory_limit=16M tests/sql-schema-unexpected-unique.php mysql
    "$task_runtime" -d memory_limit=16M tests/sql-schema-consumers.php mysql
    "$task_runtime" -d memory_limit=8M tests/sql-schema-dependencies.php mysql
    "$task_runtime" tests/outbox.php mysql
    "$task_runtime" tests/outbox-safety.php mysql
    "$task_runtime" -d memory_limit=8M tests/outbox-reconciliation.php mysql
    "$task_runtime" tests/outbox-reconciliation-concurrency.php mysql
    "$task_runtime" tests/outbox-concurrency.php mysql
    "$task_runtime" -d memory_limit=8M tests/outbox-input-bounds.php mysql
    "$task_runtime" -d memory_limit=32M tests/outbox-hard-limit.php mysql
    if "$task_runtime" -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
        for task_account_test in mailbox-recovery mailbox-recovery-approvals mailbox-recovery-safety mailbox-recovery-maintenance mailbox-recovery-dispatch mailbox-recovery-factory mailbox-recovery-concurrency account-dispatch account-mail-factory account-recovery account-recovery-maintenance account-recovery-factory account-recovery-clock account-recovery-concurrency account-budget-sql account-factory account-ledger-mysql registration-authority account-request-budget registration registration-capacity registration-maintenance maintenance-completion-authority registration-ledger-maintenance address-lock-order address-change-maintenance address-change; do
            "$task_runtime" -d memory_limit=8M "tests/${task_account_test}.php" mysql
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql
        "$task_runtime" -d memory_limit=32M tests/proof-state.php mysql normal
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory proofs
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory audit_write sink-budget
        for task_captured_feature in links grants; do
            for task_captured_mode in normal deny fields fault selectors-fault reentry effect-deny return-deny; do
                "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory audit_delegation "captured-permission-$task_captured_feature-$task_captured_mode"
            done
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory audit_delegation captured-permission-grants-changed
        for task_audit_mode in reset-proof-return-issue-normal reset-proof-return-consume-guard reset-proof-return-execute-expiry reset-proof-return-revoke-guard link-return-issue-normal link-return-issue-guard link-return-verify-guard link-return-execute-expiry link-return-all-guard link-return-revoke-guard hmac-return-verify-normal hmac-return-verify-guard hmac-return-verify-fault hmac-return-verify-clock hmac-return-execute-normal hmac-return-execute-expiry operation-return-begin-normal operation-return-begin-guard operation-return-confirm-normal operation-return-confirm-fault operation-return-consume-guard operation-return-execute-normal operation-return-execute-expiry policy-business-normal policy-business-denied policy-business-fields policy-business-foreign policy-business-before-fault policy-business-return-fault policy-business-return-denied bearer-auth-normal bearer-header-narrow bearer-header-expiry business-normal business-guard business-scope business-expiry custom-data-denied custom-selector-write custom-selector-fault custom-selector-invalid custom-before-fault custom-return-fault custom-audit custom-plain custom-denied custom-denied-plain custom-return custom-return-plain custom-fault custom-write custom-reentry read-factor-locations read-pair audit-admission-timeout post-audit-delay post-audit-denial post-audit-timeout normal return-denial return-expiry return-scope return-fault return-clock defaults; do
            "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory audit_delegation "$task_audit_mode"
        done
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory factor_notices
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory outbox_rotation
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory dispatch_budgets
        "$task_runtime" -d memory_limit=32M tests/outbox-rotation.php mysql
        "$task_runtime" -d memory_limit=32M tests/state-boundary/operation-deadline.php mysql
        "$task_runtime" -d memory_limit=32M tests/outbox-initial-claim.php mysql
        for task_initial_mode in normal expiry budget prewrite defaults current current-expiry current-late-expiry ack ack-expiry ack-late-role ack-late-expiry reject reject-expiry reject-late-role reject-late-expiry; do
            "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory outbox_initial "$task_initial_mode"
        done
        "$task_runtime" -d memory_limit=32M tests/factor-notice-completion.php mysql
        "$task_runtime" -d memory_limit=32M tests/proof-state.php mysql restore
        "$task_runtime" -d memory_limit=32M tests/proof-state.php mysql late
        "$task_runtime" -d memory_limit=32M tests/proof-state.php mysql expiry-admission
        "$task_runtime" -d memory_limit=32M tests/proof-state.php mysql expiry-late
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory mapping
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory clock
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory recovery
        "$task_runtime" -d memory_limit=32M tests/state-boundary/native-maintenance.php mysql factory mailbox_recovery
        "$task_runtime" -d memory_limit=8M tests/account-state-codecs.php mysql
        python3 tests/state_boundary.py "$task_runtime" mysql
        task_state_mysql_browser=()
        if [[ ${SOSECURITY_REQUIRE_STATE_BROWSER:-0} == 1 ]]; then task_state_mysql_browser+=(--browser); fi
        python3 tests/state_http.py "$task_runtime" --backend mysql "${task_state_mysql_browser[@]}"
        if command -v openssl >/dev/null; then
            python3 tests/state_http.py "$task_runtime" --backend mysql --tls "${task_state_mysql_browser[@]}"
            python3 tests/state_http.py "$task_runtime" --backend mysql --tls --business "${task_state_mysql_browser[@]}"
        else
            python3 tests/state_http.py "$task_runtime" --backend mysql --business "${task_state_mysql_browser[@]}"
        fi
        python3 tests/account_change_concurrency.py "$task_runtime" mysql
    else
        echo 'NOT RUN account lifecycle MySQL: sodium unavailable'
        if [[ ${SOSECURITY_REQUIRE_CRYPTO:-0} == 1 ]]; then exit 1; fi
    fi
    "$task_runtime" -d memory_limit=8M tests/outbox-index-budget.php mysql
    "$task_runtime" tests/idempotency.php mysql
    "$task_runtime" tests/idempotency-safety.php mysql
    "$task_runtime" -d memory_limit=8M tests/idempotency-input-bounds.php mysql
    "$task_runtime" tests/idempotency-concurrency.php mysql
    "$task_runtime" tests/mysql.php
    "$task_runtime" tests/api-key-time.php mysql
    python3 tests/audit_metrics_process.py "$task_runtime" mysql
    "$task_runtime" -d memory_limit=8M tests/audit-metrics-fault.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-recent-events.php mysql
    python3 tests/audit_recent_process.py "$task_runtime" mysql
    "$task_runtime" -d memory_limit=8M tests/audit-alert-outbox.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-alert-retained.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-alert-worker.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-sql.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-sql-history.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-sql-fault.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-sql-pipeline.php mysql
    python3 tests/audit_sql_process.py "$task_runtime" mysql
    "$task_runtime" tests/lease-sql.php mysql
    "$task_runtime" tests/operation-sql.php mysql
    "$task_runtime" -d memory_limit=16M tests/webhook-schema.php mysql
    "$task_runtime" tests/webhook-inbox.php mysql
    "$task_runtime" -d memory_limit=8M tests/webhook-request-authority.php mysql
    "$task_runtime" -d memory_limit=8M tests/webhook-clock-failure.php mysql
    "$task_runtime" tests/webhook-inbox-concurrency.php mysql
    "$task_runtime" tests/webhook-completion-authority.php mysql
    for task_api_mode in normal epoch late-deny late-expiry budget race; do
        "$task_runtime" -d memory_limit=32M tests/api-key-state.php mysql "$task_api_mode"
    done
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php mysql
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php mysql mapping-change
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php mysql completion-revoke
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php mysql processing-failure
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php mysql processing-late-revoke
    "$task_runtime" -d memory_limit=16M tests/webhook-state-factory.php mysql processing-race
    "$task_runtime" -d memory_limit=16M tests/webhook-state-source.php mysql
    "$task_runtime" -d memory_limit=16M tests/webhook-state-access.php mysql
    "$task_runtime" tests/webhook-processing.php mysql
    "$task_runtime" tests/webhook-processing-concurrency.php mysql
    for task_operation in processing inbox store prune install; do
        "$task_runtime" tests/webhook-processing-ownership.php mysql "$task_operation"
        "$task_runtime" tests/webhook-processing-ownership.php mysql "$task_operation" implicit
    done
elif command -v mysqld >/dev/null && command -v mysql >/dev/null && command -v python3 >/dev/null && "$task_runtime" -r 'exit(extension_loaded("pdo_mysql") ? 0 : 1);'; then
    python3 tests/mysql_check.py "$task_runtime"
else
    echo 'NOT RUN MySQL integration: mysqld, mysql, Python 3 and ext-pdo_mysql required'
    if [[ ${SOSECURITY_REQUIRE_MYSQL:-0} == 1 ]]; then exit 1; fi
fi
"$task_runtime" tests/concurrency.php
if command -v python3 >/dev/null; then
    python3 tests/api_vectors.py --php "$task_runtime"
    python3 tests/credential_vectors.py "$task_runtime"
    python3 tests/webhook_vectors.py "$task_runtime"
    python3 tests/budget_vectors.py "$task_runtime"
    python3 tests/budget_demo.py "$task_runtime"
    python3 tests/lease_demo.py "$task_runtime"
    python3 tests/crypto_vectors.py "$task_runtime"
    python3 tests/mfa_demo.py "$task_runtime"
    python3 tests/auth_http.py "$task_runtime"
    python3 tests/auth_demo.py "$task_runtime"
    python3 tests/auth_remote.py "$task_runtime"
    python3 tests/authorization_http.py "$task_runtime"
    python3 tests/operation_http.py "$task_runtime"
    python3 tests/credential_http.py "$task_runtime"
    python3 tests/webhook_http.py "$task_runtime"
    python3 tests/webhook_processing_http.py "$task_runtime" --http
    python3 tests/idempotency_http.py "$task_runtime"
    python3 tests/link_http.py "$task_runtime"
    python3 tests/remember_http.py "$task_runtime"
    python3 tests/device_risk_http.py "$task_runtime"
    python3 tests/remember_vectors.py "$task_runtime"
    python3 tests/link_vectors.py "$task_runtime"
    python3 tests/download_vectors.py "$task_runtime"
    python3 tests/download_http.py "$task_runtime"
    python3 tests/password_calibration.py "$task_runtime"
    python3 tests/signed_csrf_vectors.py --php "$task_runtime"
    python3 tests/signed_csrf_http.py "$task_runtime"
    if command -v openssl >/dev/null; then
        python3 tests/signed_csrf_https.py "$task_runtime"
        python3 tests/remember_https.py "$task_runtime"
        python3 tests/download_http.py "$task_runtime" --tls
        python3 tests/credential_http.py "$task_runtime" --tls
        python3 tests/webhook_http.py "$task_runtime" --tls
        python3 tests/webhook_processing_http.py "$task_runtime"
        python3 tests/idempotency_http.py "$task_runtime" --tls
    else
        echo 'NOT RUN signed-CSRF HTTPS: openssl required'
        if [[ ${SOSECURITY_REQUIRE_HTTP:-0} == 1 ]]; then exit 1; fi
    fi
    python3 tests/signed_csrf_demo.py "$task_runtime"
    if [[ -f integrations/htmlpurifier/vendor/autoload.php ]]; then python3 tests/html_demo.py "$task_runtime"; fi
    python3 tests/api_http.py "$task_runtime"
    python3 tests/api_demo.py "$task_runtime"
    python3 tests/network_demo.py "$task_runtime"
    python3 tests/cors_http.py "$task_runtime"
    python3 tests/upload_demo.py "$task_runtime"
    python3 tests/upload_http.py "$task_runtime"
    python3 tests/test_http.py "$task_runtime"
    python3 tests/demo.py "$task_runtime"
    python3 tests/captcha-demo.py "$task_runtime"
else
    if [[ ${SOSECURITY_REQUIRE_HTTP:-0} == 1 ]]; then
        echo 'FAIL HTTP integration prerequisite Python 3 missing' >&2
        exit 1
    fi
    echo 'NOT RUN HTTP integration: Python 3 required'
fi
