#!/usr/bin/env python3
"""Install the optional PSR-3 adapter through local Composer path repositories."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from lock_inventory_support import verify

root = Path(__file__).resolve().parents[1]
level = "3" if "--psr3" in sys.argv[1:] else ("2" if "--psr2" in sys.argv[1:] else "1")
runtimes = [item for item in sys.argv[1:] if item not in ("--psr2", "--psr3")] or ["php72", "php85"]
with tempfile.TemporaryDirectory(prefix="sosecurity-psr3-") as temp:
    project = Path(temp)
    manifest = {
        "name": "sosecurity/psr3-local-consumer",
        "require": {
            "sohophp/sosecurity": "*",
            "sohophp/sosecurity-psr3": "*",
            "psr/log": "^" + level + ".0" if level != "1" else "^1.1",
        },
        "repositories": [
            {"type": "path", "url": str(root / "integrations" / "psr3"),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity-psr3": "dev-main"}}},
            {"type": "path", "url": str(root),
             "options": {"symlink": True, "versions": {"sohophp/sosecurity": "dev-main"}}},
        ],
        "minimum-stability": "dev",
        "prefer-stable": True,
        "config": {"allow-plugins": False, "platform": {"php": "8.0.30" if level != "1" else "7.2.34"}},
    }
    (project / "composer.json").write_text(json.dumps(manifest), encoding="utf-8")
    env = dict(os.environ)
    env["COMPOSER_NO_INTERACTION"] = "1"
    subprocess.run(["composer", "install", "--no-progress", "--no-scripts", "--working-dir", str(project)],
                   env=env, check=True)
    subprocess.run(["composer", "audit", "--locked", "--no-interaction", "--working-dir", str(project)],
                   env=env, check=True)
    verify(project, runtimes[0], root / "bin/lock-inventory.php",
           ["sohophp/sosecurity", "sohophp/sosecurity-psr3", "psr/log"])
    autoload = str(project / "vendor" / "autoload.php")
    for runtime in runtimes:
        subprocess.run([runtime, str(root / "tests" / "psr3-audit.php"), autoload], check=True)
