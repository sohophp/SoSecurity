#!/usr/bin/env python3
"""Check fixed audit counters across eight real processes and one private FileStore."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

runtime = sys.argv[1] if len(sys.argv) > 1 else "php"
backend = sys.argv[2] if len(sys.argv) > 2 else "file"
worker = str(Path(__file__).with_name("audit-metrics-worker.php"))
if backend not in ("file", "redis", "mysql"):
    raise RuntimeError("Unknown private audit metrics backend")
target = None
if backend != "file":
    variable = "SOSECURITY_TEST_REDIS_SOCKET" if backend == "redis" else "SOSECURITY_TEST_MYSQL_SOCKET"
    target = Path(os.environ.get(variable, ""))
    prefix = "sosecurity-redis." if backend == "redis" else "sosecurity-mysql-"
    marker = "audit-metrics-owner" if backend == "redis" else "account-test-owner"
    socket_name = "redis.sock" if backend == "redis" else "mysql.sock"
    if not str(target.parent).startswith("/tmp/" + prefix) or target.name != socket_name \
            or not target.is_socket() or not (target.parent / marker).is_file():
        raise RuntimeError("Audit metrics require a controller-owned private socket")
namespace = "metrics-" + os.urandom(8).hex()
# One fixed future instant keeps every worker in the same window, even at UTC midnight.
clock_time = str((int(time.time()) // 86400 + 1) * 86400 + 43200)
with tempfile.TemporaryDirectory(prefix="sosecurity-audit-metrics-") as directory:
    if target is None:
        target = Path(directory)
    if backend == "redis":
        subprocess.run([runtime, worker, str(target), "initialize", backend, namespace, clock_time], check=True)
    children = [subprocess.Popen([runtime, worker, str(target), "write", backend, namespace, clock_time],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for _ in range(8)]
    for child in children:
        stdout, stderr = child.communicate(timeout=30)
        if child.returncode:
            raise RuntimeError(stderr.decode("utf-8", "replace")[:1000])
    result = subprocess.run([runtime, worker, str(target), "inspect", backend, namespace, clock_time],
                            capture_output=True, text=True, timeout=15, check=True)
    snapshot = json.loads(result.stdout)
    if snapshot["total"] != 80 or snapshot["counts"]["authentication"] != 80 \
            or snapshot["alerts"] != ["authentication"]:
        raise AssertionError("Shared audit metric count or fixed alert signal is wrong")
    denied = subprocess.run([runtime, worker, str(target), "reject", backend, namespace, clock_time],
                            capture_output=True, text=True, timeout=15, check=True)
    if denied.stdout.strip() != "capacity-denied":
        raise AssertionError("Capacity exhaustion was not rejected")
    print("PASS fixed audit metrics on " + backend + ": 8 processes, 80 counted attempts, fixed alert and capacity rejection")
