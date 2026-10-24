#!/usr/bin/env python3
"""Install the optional adapter in an isolated local Composer consumer."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from lock_inventory_support import verify

root = Path(__file__).resolve().parents[1]
php_runtimes = sys.argv[1:] or ["php72", "php85"]
with tempfile.TemporaryDirectory(prefix="sosecurity-psr15-") as temp:
    project = Path(temp)
    manifest = {
        "name": "sosecurity/psr15-local-consumer",
        "require": {
            "php": ">=7.2 <8.6",
            "sohophp/sosecurity": "*",
            "sohophp/sosecurity-psr15": "*",
            "nyholm/psr7": "1.8.2",
        },
        "repositories": [
            {"type": "path", "url": str(root / "integrations" / "psr15"),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity-psr15": "dev-main"}}},
            {"type": "path", "url": str(root),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity": "dev-main"}}},
        ],
        "minimum-stability": "dev",
        "prefer-stable": True,
        "config": {"allow-plugins": False, "platform": {"php": "7.2.34"}},
    }
    (project / "composer.json").write_text(json.dumps(manifest), encoding="utf-8")
    env = dict(os.environ)
    env["COMPOSER_NO_INTERACTION"] = "1"
    subprocess.run(["composer", "install", "--no-progress", "--no-scripts", "--working-dir", str(project)],
                   env=env, check=True)
    subprocess.run(["composer", "audit", "--locked", "--no-interaction", "--working-dir", str(project)],
                   env=env, check=True)
    verify(project, php_runtimes[0], root / "bin/lock-inventory.php",
           ["sohophp/sosecurity", "sohophp/sosecurity-psr15", "nyholm/psr7",
            "psr/http-message", "psr/http-server-middleware", "psr/http-server-handler"])
    autoload = str(project / "vendor" / "autoload.php")
    for runtime in php_runtimes:
        subprocess.run([runtime, str(root / "tests" / "psr15-budget.php"), autoload], check=True)
        subprocess.run([runtime, str(root / "tests" / "psr15-privacy.php"), autoload], check=True)
