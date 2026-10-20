#!/usr/bin/env python3
"""Run OIDC session and process-race checks on an owned no-TCP local Redis instance."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main():
    if len(sys.argv) < 3:
        raise SystemExit("Usage: redis_process.py /path/to/vendor/autoload.php php72 [php73 ...]")
    autoload = Path(sys.argv[1]).resolve()
    if not autoload.is_file():
        raise RuntimeError("Local OIDC consumer autoload.php is required")
    tests = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="sosecurity-oidc-redis-") as directory:
        base = Path(directory)
        marker = base / "oidc-test-owner"
        marker.write_text("owned OIDC Redis test instance\n")
        marker.chmod(0o600)
        socket = base / "redis.sock"
        log = open(base / "redis.log", "w+")
        server = subprocess.Popen(["redis-server", "--port", "0", "--unixsocket", str(socket),
                                   "--unixsocketperm", "700", "--dir", directory, "--save", "",
                                   "--appendonly", "no"], stdout=log, stderr=log)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("SOSECURITY_TEST_")}
        environment["SOSECURITY_TEST_OIDC_REDIS_SOCKET"] = str(socket)

        def cli(*args):
            return subprocess.run(["redis-cli", "-s", str(socket), *args],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=3, check=False)

        try:
            for _ in range(150):
                if server.poll() is not None:
                    raise RuntimeError("Owned Redis test server exited during startup")
                try:
                    if cli("PING").stdout.strip() == "PONG":
                        break
                except subprocess.TimeoutExpired:
                    pass
                time.sleep(0.02)
            else:
                raise RuntimeError("Owned Redis test server did not become ready")
            for runtime in sys.argv[2:]:
                available = subprocess.run([runtime, "-r", 'exit(extension_loaded("redis") ? 0 : 1);'],
                                           env=environment, check=False)
                if available.returncode:
                    raise RuntimeError(runtime + " does not load ext-redis")
                subprocess.run(["python3", str(tests / "process_race.py"), str(autoload), runtime],
                               env=environment, check=True, timeout=30)
                subprocess.run([runtime, str(tests / "sessions.php"), str(autoload), "redis"],
                               env=environment, check=True, timeout=30)
        finally:
            if server.poll() is None:
                cli("SHUTDOWN", "NOSAVE")
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.terminate()
                    server.wait(timeout=5)
            log.close()


if __name__ == "__main__":
    main()
