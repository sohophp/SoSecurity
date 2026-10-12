#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_runtime=${1:-php}
"$task_runtime" bin/lint.php
"$task_runtime" tests/run.php
"$task_runtime" tests/session.php
if command -v redis-server >/dev/null && command -v redis-cli >/dev/null && "$task_runtime" -r 'exit(extension_loaded("redis") ? 0 : 1);'; then
    task_redis_dir=$(mktemp -d /tmp/sosecurity-redis.XXXXXXXX)
    task_redis_socket="$task_redis_dir/redis.sock"
    cleanup() {
        redis-cli -s "$task_redis_socket" shutdown nosave >/dev/null 2>&1 || true
        rm -rf -- "$task_redis_dir"
    }
    trap cleanup EXIT
    redis-server --port 0 --unixsocket "$task_redis_socket" --unixsocketperm 700 --save '' --appendonly no --daemonize yes --pidfile "$task_redis_dir/redis.pid" --logfile "$task_redis_dir/redis.log"
    export SOSECURITY_TEST_REDIS_SOCKET="$task_redis_socket"
    "$task_runtime" tests/redis.php
else
    if [[ ${SOSECURITY_REQUIRE_REDIS:-0} == 1 ]]; then
        echo 'FAIL Redis integration prerequisites missing' >&2
        exit 1
    fi
    echo 'NOT RUN Redis integration: redis-server, redis-cli and ext-redis required'
fi
"$task_runtime" tests/concurrency.php
if command -v python3 >/dev/null; then
    python3 tests/test_http.py "$task_runtime"
    python3 tests/demo.py "$task_runtime"
else
    if [[ ${SOSECURITY_REQUIRE_HTTP:-0} == 1 ]]; then
        echo 'FAIL HTTP integration prerequisite Python 3 missing' >&2
        exit 1
    fi
    echo 'NOT RUN HTTP integration: Python 3 required'
fi
