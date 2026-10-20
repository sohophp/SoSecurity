#!/usr/bin/env python3
"""Run audit metrics against a disposable Redis Unix-socket instance."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

root = Path(__file__).resolve().parent.parent
runtimes = sys.argv[1:] or ["php"]
with tempfile.TemporaryDirectory(prefix="sosecurity-redis.") as directory:
    path = Path(directory)
    socket = path / "redis.sock"
    (path / "audit-metrics-owner").write_text("owned SDK audit metrics test\n")
    subprocess.run(["redis-server", "--port", "0", "--unixsocket", str(socket),
                    "--unixsocketperm", "700", "--dir", directory, "--save", "",
                    "--appendonly", "no", "--daemonize", "yes", "--pidfile", str(path / "redis.pid"),
                    "--logfile", str(path / "redis.log")], check=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith("SOSECURITY_TEST_")}
    env["SOSECURITY_TEST_REDIS_SOCKET"] = str(socket)
    try:
        for _ in range(100):
            if socket.is_socket():
                probe = subprocess.run(["redis-cli", "-s", str(socket), "PING"],
                                       capture_output=True, text=True)
                if probe.returncode == 0 and probe.stdout.strip() == "PONG":
                    break
            time.sleep(.05)
        else:
            raise RuntimeError("Private Redis did not start")
        for runtime in runtimes:
            subprocess.run(["python3", str(root / "tests/audit_metrics_process.py"), runtime, "redis"],
                           env=env, check=True)
            subprocess.run([runtime, "-d", "memory_limit=8M", str(root / "tests/audit-metrics-fault.php"), "redis"],
                           env=env, check=True)
            subprocess.run([runtime, "-d", "memory_limit=8M", str(root / "tests/audit-recent-events.php"), "redis"],
                           env=env, check=True)
            subprocess.run(["python3", str(root / "tests/audit_recent_process.py"), runtime, "redis"],
                           env=env, check=True)
    finally:
        subprocess.run(["redis-cli", "-s", str(socket), "SHUTDOWN", "NOSAVE"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
