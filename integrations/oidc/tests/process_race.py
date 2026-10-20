#!/usr/bin/env python3
"""Two actual PHP processes race federated session issue/verify against provider logout."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    if result.returncode:
        raise RuntimeError("Worker failed: " + result.stderr.decode("utf-8", "replace")[:1200])
    return result.stdout.decode().strip()


def wait_for(path, process):
    deadline = time.monotonic() + 10
    while not path.is_file():
        if process.poll() is not None:
            raise RuntimeError("Race worker stopped before its checkpoint: "
                               + process.stderr.read().decode("utf-8", "replace")[:1200])
        if time.monotonic() >= deadline:
            raise RuntimeError("Race worker did not reach its checkpoint")
        time.sleep(0.01)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: process_race.py /path/to/vendor/autoload.php php72")
    autoload, runtime = str(Path(sys.argv[1]).resolve()), sys.argv[2]
    if os.environ.get("SOSECURITY_TEST_MYSQL_SOCKET") and os.environ.get("SOSECURITY_TEST_OIDC_REDIS_SOCKET"):
        raise RuntimeError("Only one owned OIDC test backend may be selected")
    worker = str(Path(__file__).with_name("process-worker.php"))
    checks = 0
    for action in ("issue_race", "verify_race"):
        with tempfile.TemporaryDirectory(prefix="sosecurity-oidc-process-") as directory:
            base = [runtime, worker, autoload, directory]
            if run(base + ["setup"]) != "ready":
                raise AssertionError("Federated link setup failed")
            checks += 1
            if action == "verify_race":
                if run(base + ["issue"]) != "issued" or run(base + ["verify"]) != "verified":
                    raise AssertionError("Baseline session could not be verified")
                checks += 2
            process = subprocess.Popen(base + [action], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                wait_for(Path(directory) / "ready", process)
                checks += 1
                if run(base + ["logout"]) != "logged_out":
                    raise AssertionError("Concurrent logout did not commit")
                checks += 1
            finally:
                (Path(directory) / "go").write_text("1")
                stdout, stderr = process.communicate(timeout=15)
            if process.returncode or stdout.decode().strip() != "rejected":
                raise RuntimeError("Race worker accepted old authority: " + stderr.decode("utf-8", "replace")[:1200])
            checks += 1
    backend = ("RedisStore" if os.environ.get("SOSECURITY_TEST_OIDC_REDIS_SOCKET") else
               "MySqlStore" if os.environ.get("SOSECURITY_TEST_MYSQL_SOCKET") else "FileStore")
    print("PASS federated", backend, "process races:", checks, "checks", runtime)


if __name__ == "__main__":
    main()
