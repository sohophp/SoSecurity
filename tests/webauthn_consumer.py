#!/usr/bin/env python3
"""Fresh local WebAuthn consumer, exact dependency inventory and component checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from lock_inventory_support import verify

root = Path(__file__).resolve().parents[1]
with_mysql = "--mysql" in sys.argv[1:]
with_browser = "--browser" in sys.argv[1:]
with_archive = "--archive" in sys.argv[1:]
runtime_args = [arg for arg in sys.argv[1:] if arg not in ("--mysql", "--browser", "--archive")]
if len(runtime_args) > 1:
    raise RuntimeError("Pass one PHP runtime and optional --mysql/--browser/--archive.")
runtime = runtime_args[0] if runtime_args else "php82"
if with_browser:
    module = os.environ.get("SOSECURITY_PLAYWRIGHT_MODULE", "")
    if not module or not Path(module).is_dir():
        raise RuntimeError("--browser requires SOSECURITY_PLAYWRIGHT_MODULE to name a local Playwright directory.")
version = int(subprocess.check_output([runtime, "-r", "echo PHP_VERSION_ID;"], text=True).strip())
if version < 80200 or version >= 80600:
    raise RuntimeError("WebAuthn consumer requires PHP 8.2–8.5")

with tempfile.TemporaryDirectory(prefix="sosecurity-webauthn-consumer-") as directory:
    project = Path(directory)
    project.chmod(0o700)
    adapter = root / "integrations/webauthn"
    if with_archive:
        output = project / "distribution"
        output.mkdir()
        subprocess.run(["composer", "archive", "--format=zip", "--dir=" + str(output),
                        "--file=adapter", "--no-interaction"], cwd=adapter, check=True, timeout=60)
        package = project / "adapter"
        package.mkdir()
        with zipfile.ZipFile(output / "adapter.zip") as archive:
            names = archive.namelist()
            if "src/SessionDeviceAuthority.php" not in names or any(
                    name.startswith("tests/") or name.startswith("/") or ".." in Path(name).parts
                    for name in names):
                raise RuntimeError("WebAuthn archive has unexpected test or unsafe entries")
            archive.extractall(package)
        adapter = package
    manifest = {
        "name": "sosecurity/webauthn-local-consumer",
        "require": {
            "php": ">=8.2 <8.6",
            "sohophp/sosecurity": "*",
            "sohophp/sosecurity-webauthn": "*",
            "web-auth/webauthn-lib": "5.3.9",
        },
        "repositories": [
            {"type": "path", "url": str(adapter),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity-webauthn": "dev-main"}}},
            {"type": "path", "url": str(root),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity": "dev-main"}}},
        ],
        "minimum-stability": "dev",
        "prefer-stable": True,
        "config": {"allow-plugins": False, "platform": {"php": "8.2.32"}},
    }
    (project / "composer.json").write_text(json.dumps(manifest), encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if not key.startswith("SOSECURITY_TEST_")}
    env["COMPOSER_NO_INTERACTION"] = "1"
    subprocess.run(["composer", "install", "--no-progress", "--no-scripts", "--no-plugins",
                    "--working-dir", str(project)], env=env, check=True, timeout=180)
    subprocess.run(["composer", "audit", "--locked", "--no-interaction", "--working-dir", str(project)],
                   env=env, check=True, timeout=60)
    verify(project, runtime, root / "bin/lock-inventory.php",
           ["sohophp/sosecurity", "sohophp/sosecurity-webauthn",
            "web-auth/webauthn-lib", "web-auth/cose-lib"])
    autoload = str(project / "vendor/autoload.php")
    suite = root / "integrations/webauthn/tests"
    for name in ("smoke", "challenge", "challenge-race", "repository", "persisted",
                 "device-management", "session-device-authority", "device-race", "recovery",
                 "recovery-race", "migration"):
        command = [runtime]
        if name == "repository":
            command += ["-d", "memory_limit=8M"]
        command += [str(suite / (name + ".php")), autoload]
        subprocess.run(command, cwd=root, env=env, check=True, timeout=120)
    if with_mysql:
        mysql_env = dict(env, SOSECURITY_WEBAUTHN_AUTOLOAD=autoload)
        subprocess.run(["python3", str(root / "tests/mysql_check.py"), "--webauthn", runtime],
                       cwd=root, env=mysql_env, check=True, timeout=300)
    if with_browser:
        browser_env = dict(env, SOSECURITY_WEBAUTHN_AUTOLOAD=autoload)
        subprocess.run(["python3", str(suite / "browser.py"), runtime],
                       cwd=root, env=browser_env, check=True, timeout=180)
print("PASS optional WebAuthn local consumer: exact 5.3.9 lock, eleven component suites"
      + (", private MySQL" if with_mysql else "")
      + (", local Chromium virtual authenticator" if with_browser else "")
      + (", installed from Composer ZIP archive" if with_archive else ""))
