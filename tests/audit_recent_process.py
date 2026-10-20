#!/usr/bin/env python3
"""Verify the shared recent-event cap across eight real PHP processes."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

runtime = sys.argv[1] if len(sys.argv) > 1 else "php"
backend = sys.argv[2] if len(sys.argv) > 2 else "file"
if backend not in ("file", "redis", "mysql"):
    raise RuntimeError("Unknown recent-event backend")
worker = str(Path(__file__).with_name("audit-recent-worker.php"))
target = None
if backend != "file":
    variable = "SOSECURITY_TEST_REDIS_SOCKET" if backend == "redis" else "SOSECURITY_TEST_MYSQL_SOCKET"
    target = Path(os.environ.get(variable, ""))
    prefix = "sosecurity-redis." if backend == "redis" else "sosecurity-mysql-"
    marker = "audit-metrics-owner" if backend == "redis" else "account-test-owner"
    socket_name = "redis.sock" if backend == "redis" else "mysql.sock"
    if not str(target.parent).startswith("/tmp/" + prefix) or target.name != socket_name \
            or not target.is_socket() or not (target.parent / marker).is_file():
        raise RuntimeError("Recent-event test requires a controller-owned private socket")
namespace = "audit-recent-process-" + os.urandom(8).hex()
clock_time = str((int(time.time()) // 86400 + 1) * 86400 + 43200)
with tempfile.TemporaryDirectory(prefix="sosecurity-audit-recent-") as directory:
    if target is None:
        target = Path(directory)
    command = [runtime, "-d", "memory_limit=8M", worker, str(target)]
    def invoke(action, actor=None):
        args = [*command, action, backend, namespace, clock_time]
        if actor is not None:
            args.append(actor)
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Recent-event worker failed: " + result.stderr[:1000])
        return result.stdout.strip()
    if backend == "redis":
        invoke("initialize")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda index: invoke("write", "actor-" + str(index)), range(8)))
    if results.count("ACCEPTED") != 3 or results.count("REFUSED") != 5:
        raise AssertionError("Concurrent recent-event capacity was not exact: " + repr(results))
    events = json.loads(invoke("inspect"))
    if len(events) != 3 or len({event["subject"] for event in events}) != 3 \
            or any(event["event"] != "login.failed" for event in events):
        raise AssertionError("Recent-event index lost or duplicated accepted records")
    if invoke("write", "overflow") != "REFUSED":
        raise AssertionError("Recent-event capacity allowed an extra write")
print("PASS recent audit process contention on " + backend + ": 8 workers, 3 accepted, 5 refused")
