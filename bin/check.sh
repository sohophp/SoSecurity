#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_runtime=${1:-php}
"$task_runtime" bin/lint.php
"$task_runtime" tests/run.php
"$task_runtime" tests/session.php
"$task_runtime" tests/hardening.php
"$task_runtime" tests/storage-failure.php
"$task_runtime" tests/configuration.php
"$task_runtime" tests/validation.php
"$task_runtime" tests/http-policy.php
"$task_runtime" tests/outbound.php
"$task_runtime" tests/api.php
"$task_runtime" tests/upload.php
if "$task_runtime" -r 'exit(extension_loaded("pdo_sqlite") ? 0 : 1);'; then
    "$task_runtime" tests/reset-flow.php
else
    echo 'NOT RUN reset host integration: test-only ext-pdo_sqlite required'
    if [[ ${SOSECURITY_REQUIRE_RESET:-0} == 1 ]]; then exit 1; fi
fi
if command -v redis-server >/dev/null && command -v redis-cli >/dev/null && "$task_runtime" -r 'exit(extension_loaded("redis") ? 0 : 1);'; then
    task_redis_dir=$(mktemp -d /tmp/sosecurity-redis.XXXXXXXX)
    task_redis_socket="$task_redis_dir/redis.sock"
    cleanup() {
        redis-cli -s "$task_redis_socket" shutdown nosave >/dev/null 2>&1 || true
        rm -rf -- "$task_redis_dir"
    }
    trap cleanup EXIT
    redis-server --port 0 --unixsocket "$task_redis_socket" --unixsocketperm 700 --dir "$task_redis_dir" --save '' --appendonly no --daemonize yes --pidfile "$task_redis_dir/redis.pid" --logfile "$task_redis_dir/redis.log"
    export SOSECURITY_TEST_REDIS_SOCKET="$task_redis_socket"
    "$task_runtime" tests/redis.php
    "$task_runtime" tests/api.php
    if command -v python3 >/dev/null; then python3 tests/redis_restart.py "$task_runtime"; fi
else
    if [[ ${SOSECURITY_REQUIRE_REDIS:-0} == 1 ]]; then
        echo 'FAIL Redis integration prerequisites missing' >&2
        exit 1
    fi
    echo 'NOT RUN Redis integration: redis-server, redis-cli and ext-redis required'
fi
if [[ -n ${SOSECURITY_TEST_MYSQL_SOCKET:-} ]]; then
    "$task_runtime" tests/mysql.php
elif command -v mysqld >/dev/null && command -v mysql >/dev/null && command -v python3 >/dev/null && "$task_runtime" -r 'exit(extension_loaded("pdo_mysql") ? 0 : 1);'; then
    python3 tests/mysql_check.py "$task_runtime"
else
    echo 'NOT RUN MySQL integration: mysqld, mysql, Python 3 and ext-pdo_mysql required'
    if [[ ${SOSECURITY_REQUIRE_MYSQL:-0} == 1 ]]; then exit 1; fi
fi
"$task_runtime" tests/concurrency.php
if command -v python3 >/dev/null; then
    python3 tests/api_vectors.py --php "$task_runtime"
    python3 tests/api_http.py "$task_runtime"
    python3 tests/api_demo.py "$task_runtime"
    python3 tests/network_demo.py "$task_runtime"
    python3 tests/cors_http.py "$task_runtime"
    python3 tests/upload_demo.py "$task_runtime"
    python3 tests/upload_http.py "$task_runtime"
    python3 tests/test_http.py "$task_runtime"
    python3 tests/demo.py "$task_runtime"
else
    if [[ ${SOSECURITY_REQUIRE_HTTP:-0} == 1 ]]; then
        echo 'FAIL HTTP integration prerequisite Python 3 missing' >&2
        exit 1
    fi
    echo 'NOT RUN HTTP integration: Python 3 required'
fi
