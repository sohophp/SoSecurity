#!/usr/bin/env python3
"""Install and check the optional OIDC adapter with owned local services only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
from lock_inventory_support import verify


ROOT = Path(__file__).resolve().parents[1]
WITH_ARCHIVE = "--archive" in sys.argv[1:]
RUNTIMES = [arg for arg in sys.argv[1:] if arg != "--archive"] or ["php"]
TEST_ENV = {key: value for key, value in os.environ.items()
            if not key.startswith("SOSECURITY_TEST_") and key != "SOSECURITY_OIDC_AUTOLOAD"}


def run(*command, env=None):
    subprocess.run(command, check=True, env=TEST_ENV if env is None else env)


with tempfile.TemporaryDirectory(prefix="sosecurity-oidc-consumer-") as directory:
    project = Path(directory)
    adapter = ROOT / "integrations" / "oidc"
    if WITH_ARCHIVE:
        output = project / "distribution"
        output.mkdir()
        subprocess.run(["composer", "archive", "--format=zip", "--dir=" + str(output),
                        "--file=adapter", "--no-interaction"], cwd=adapter, check=True, timeout=60)
        package = project / "adapter"
        package.mkdir()
        with zipfile.ZipFile(output / "adapter.zip") as archive:
            names = archive.namelist()
            if "src/StrictClient.php" not in names or any(
                    name.startswith("tests/") or name == "phpstan.neon" or
                    name.startswith("/") or ".." in Path(name).parts for name in names):
                raise RuntimeError("OIDC archive has unexpected test or unsafe entries")
            archive.extractall(package)
        adapter = package
    manifest = {
        "name": "sosecurity/oidc-local-consumer",
        "require": {
            "php": ">=7.2 <8.4",
            "sohophp/sosecurity": "*",
            "sohophp/sosecurity-oidc": "*",
        },
        "repositories": [
            {"type": "path", "url": str(adapter),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity-oidc": "dev-main"}}},
            {"type": "path", "url": str(ROOT),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity": "dev-main"}}},
        ],
        "minimum-stability": "dev",
        "prefer-stable": True,
        "config": {"allow-plugins": False, "platform": {"php": "7.2.34"}},
    }
    (project / "composer.json").write_text(json.dumps(manifest), encoding="utf-8")
    env = dict(TEST_ENV)
    env["COMPOSER_NO_INTERACTION"] = "1"
    run("composer", "install", "--no-progress", "--no-scripts", "--working-dir", directory, env=env)
    run("composer", "audit", "--locked", "--no-interaction", "--working-dir", directory, env=env)
    verify(project, RUNTIMES[0], ROOT / "bin/lock-inventory.php",
           ["sohophp/sosecurity", "sohophp/sosecurity-oidc", "jumbojett/openid-connect-php"])
    locked = json.loads((project / "composer.lock").read_text(encoding="utf-8"))
    upstream = [package for package in locked["packages"]
                if package["name"] == "jumbojett/openid-connect-php"]
    if len(upstream) != 1 or upstream[0]["version"] != "v1.0.2":
        raise RuntimeError("OIDC upstream must be the reviewed v1.0.2")
    autoload = str(project / "vendor" / "autoload.php")
    tests = ROOT / "integrations" / "oidc" / "tests"
    for runtime in RUNTIMES:
        version = subprocess.check_output([runtime, "-r", "echo PHP_VERSION_ID;"],
                                          text=True, env=TEST_ENV).strip()
        if not 70200 <= int(version) < 80400:
            raise RuntimeError(runtime + " is outside the OIDC adapter's PHP range")
        for name in ("claims", "client-debug", "proof-export", "links", "fences",
                     "sessions", "session-binding", "batch-unlink", "unlink-current", "signed-callback"):
            run(runtime, str(tests / (name + ".php")), autoload)
        for mode in ("absolute", "idle", "backwards", "absolute-final", "idle-final", "live", "live-final"):
            run(runtime, str(tests / "session-io-time.php"), mode, autoload)
        if subprocess.run([runtime, "-r", 'exit(extension_loaded("sodium") ? 0 : 1);'], env=TEST_ENV).returncode == 0:
            run(runtime, str(tests / "mfa-login.php"), autoload)
            run(sys.executable, str(tests / "mfa_process.py"), autoload, runtime)
        else:
            print("NOT RUN encrypted OIDC MFA integration: ext-sodium required", flush=True)
            if TEST_ENV.get("SOSECURITY_REQUIRE_CRYPTO") == "1":
                raise RuntimeError("Required OIDC MFA test dependency is unavailable")
        run(sys.executable, str(tests / "process_race.py"), autoload, runtime)
        db_env = dict(env, SOSECURITY_OIDC_AUTOLOAD=autoload)
        run(sys.executable, str(ROOT / "tests" / "mysql_check.py"), "--oidc-process", runtime,
            env=db_env)
        run(sys.executable, str(tests / "redis_process.py"), autoload, runtime)
        run(sys.executable, str(tests / "tls_integration.py"), autoload, runtime)
print("PASS optional OIDC local consumer: locked v1.0.2 and local integration"
      + (", installed from Composer ZIP archive" if WITH_ARCHIVE else ""))
