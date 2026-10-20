#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_runtime=${1:-php}
"$task_runtime" bin/lint.php
"$task_runtime" bin/api-contract.php
python3 tests/lock_inventory.py "$task_runtime"
"$task_runtime" tests/portable-core.php
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
"$task_runtime" tests/captcha-providers.php
"$task_runtime" -d memory_limit=8M tests/secret-config-export.php
"$task_runtime" -d memory_limit=8M tests/bearer-object-export.php
"$task_runtime" -d memory_limit=8M tests/transport-value-export.php
"$task_runtime" tests/mfa.php
"$task_runtime" tests/auth.php
"$task_runtime" -d memory_limit=8M tests/auth-export.php
"$task_runtime" tests/remember.php
"$task_runtime" tests/device-risk.php
"$task_runtime" tests/password.php
"$task_runtime" tests/password-dependencies.php
"$task_runtime" tests/authorization.php
"$task_runtime" tests/budgets.php
"$task_runtime" tests/native-report-budget.php
"$task_runtime" tests/leases.php
"$task_runtime" tests/operations.php
"$task_runtime" tests/links.php
"$task_runtime" tests/downloads.php
"$task_runtime" -d memory_limit=8M tests/download-stream.php
"$task_runtime" tests/session.php
"$task_runtime" tests/hardening.php
"$task_runtime" -d memory_limit=8M tests/cookie-budget.php
"$task_runtime" tests/storage-failure.php
"$task_runtime" tests/configuration.php
"$task_runtime" tests/configuration-presets.php
"$task_runtime" tests/validation.php
"$task_runtime" tests/http-policy.php
"$task_runtime" tests/outbound.php
"$task_runtime" tests/api.php
"$task_runtime" tests/credentials.php
"$task_runtime" tests/webhooks.php
"$task_runtime" -d memory_limit=8M tests/webhook-key-export.php
"$task_runtime" tests/signed-csrf.php
if [[ -f integrations/htmlpurifier/vendor/autoload.php ]]; then
    "$task_runtime" tests/html.php
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
    for task_snapshot_test in sql capture capture-commit files file-view composite-view composite-references example slot-pages slot-page-bounds slot-page-bytes slot-page-race slot-page-filter; do
        "$task_runtime" -d memory_limit=8M "tests/state-snapshot/${task_snapshot_test}.php" sqlite
    done
    "$task_runtime" -d memory_limit=8M tests/account-foundation.php
    if "$task_runtime" -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
        for task_account_test in mailbox-recovery mailbox-recovery-approvals mailbox-recovery-safety mailbox-recovery-maintenance mailbox-recovery-dispatch mailbox-recovery-factory mailbox-recovery-wrong-target mailbox-recovery-wrong-purpose mailbox-recovery-concurrency account-send-budgets account-dispatch account-factor-notices account-mail-factory password-baseline account-recovery account-recovery-maintenance account-recovery-factory account-recovery-clock account-recovery-concurrency account-budgets account-budget-sql account-factory account-ledger registration-authority account-request-budget registration registration-capacity registration-maintenance registration-ledger-maintenance address-lock-order address-change-maintenance address-change; do
            "$task_runtime" -d memory_limit=8M "tests/${task_account_test}.php"
        done
        python3 tests/account_factor.py "$task_runtime"
        python3 tests/managed_auth_http.py "$task_runtime"
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
    "$task_runtime" -d memory_limit=8M tests/sql-schema-dependencies.php
    "$task_runtime" tests/outbox.php
    "$task_runtime" -d memory_limit=8M tests/audit-alert-outbox.php
    "$task_runtime" -d memory_limit=8M tests/audit-alert-retained.php
    "$task_runtime" -d memory_limit=8M tests/audit-alert-worker.php
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
    "$task_runtime" tests/authorization-sql.php
    "$task_runtime" tests/lease-sql.php
    "$task_runtime" tests/operation-sql.php
    "$task_runtime" tests/webhook-inbox.php
    "$task_runtime" tests/webhook-inbox-concurrency.php
    "$task_runtime" tests/webhook-processing.php
    "$task_runtime" -d memory_limit=8M tests/webhook-body-budget.php
    "$task_runtime" tests/webhook-processing-factory.php
    "$task_runtime" tests/webhook-processing-concurrency.php
    "$task_runtime" tests/webhook-processing-ownership.php
    "$task_runtime" tests/webhook-processing-ownership.php sqlite inbox
    "$task_runtime" tests/idempotency.php
    "$task_runtime" tests/idempotency-safety.php
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
    if command -v python3 >/dev/null; then
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
    "$task_runtime" tests/sql-enlistment.php mysql
    "$task_runtime" -d memory_limit=8M tests/sql-schema-dependencies.php mysql
    "$task_runtime" tests/outbox.php mysql
    "$task_runtime" tests/outbox-safety.php mysql
    "$task_runtime" -d memory_limit=8M tests/outbox-reconciliation.php mysql
    "$task_runtime" tests/outbox-reconciliation-concurrency.php mysql
    "$task_runtime" tests/outbox-concurrency.php mysql
    "$task_runtime" -d memory_limit=8M tests/outbox-input-bounds.php mysql
    "$task_runtime" -d memory_limit=32M tests/outbox-hard-limit.php mysql
    if "$task_runtime" -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
        for task_account_test in mailbox-recovery mailbox-recovery-approvals mailbox-recovery-safety mailbox-recovery-maintenance mailbox-recovery-dispatch mailbox-recovery-factory mailbox-recovery-concurrency account-dispatch account-mail-factory account-recovery account-recovery-maintenance account-recovery-factory account-recovery-clock account-recovery-concurrency account-budget-sql account-factory account-ledger-mysql registration-authority account-request-budget registration registration-capacity registration-maintenance registration-ledger-maintenance address-lock-order address-change-maintenance address-change; do
            "$task_runtime" -d memory_limit=8M "tests/${task_account_test}.php" mysql
        done
        python3 tests/account_change_concurrency.py "$task_runtime" mysql
    else
        echo 'NOT RUN account lifecycle MySQL: sodium unavailable'
        if [[ ${SOSECURITY_REQUIRE_CRYPTO:-0} == 1 ]]; then exit 1; fi
    fi
    "$task_runtime" -d memory_limit=8M tests/outbox-index-budget.php mysql
    "$task_runtime" tests/idempotency.php mysql
    "$task_runtime" tests/idempotency-safety.php mysql
    "$task_runtime" tests/idempotency-concurrency.php mysql
    "$task_runtime" tests/mysql.php
    python3 tests/audit_metrics_process.py "$task_runtime" mysql
    "$task_runtime" -d memory_limit=8M tests/audit-metrics-fault.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-recent-events.php mysql
    python3 tests/audit_recent_process.py "$task_runtime" mysql
    "$task_runtime" -d memory_limit=8M tests/audit-alert-outbox.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-alert-retained.php mysql
    "$task_runtime" -d memory_limit=8M tests/audit-alert-worker.php mysql
    "$task_runtime" tests/lease-sql.php mysql
    "$task_runtime" tests/operation-sql.php mysql
    "$task_runtime" tests/webhook-inbox.php mysql
    "$task_runtime" tests/webhook-inbox-concurrency.php mysql
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
