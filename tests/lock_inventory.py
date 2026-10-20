#!/usr/bin/env python3
"""Check exact locked inventory output and fail-closed input handling."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else "php"
generator = root / "bin/lock-inventory.php"

def run(project):
    return subprocess.run([runtime, "-d", "memory_limit=8M", str(generator), str(project)],
                          capture_output=True, text=True, timeout=20)

projects = [(root, []), (root / "tools", ["phpstan/phpstan"]),
            (root / "integrations/htmlpurifier", ["ezyang/htmlpurifier"])]
for project, expected in projects:
    result = run(project)
    if result.returncode or result.stderr:
        raise AssertionError("Valid locked project was rejected: " + result.stderr)
    inventory = json.loads(result.stdout)
    if inventory["format"] != "sosecurity.lock-inventory.v1" \
            or [package["name"] for package in inventory["packages"]] != expected \
            or inventory["manifest_sha256"] != hashlib.sha256((project / "composer.json").read_bytes()).hexdigest() \
            or inventory["lock_sha256"] != hashlib.sha256((project / "composer.lock").read_bytes()).hexdigest():
        raise AssertionError("Inventory does not match exact Composer inputs")
    if run(project).stdout != result.stdout:
        raise AssertionError("Inventory output changed without an input change")

missing = run(root / "integrations/oidc")
if missing.returncode != 1 or missing.stdout or "required" not in missing.stderr:
    raise AssertionError("A lockless optional package was not refused")

with tempfile.TemporaryDirectory(prefix="sosecurity-lock-inventory-") as directory:
    project = Path(directory)
    (project / "composer.json").write_bytes((root / "tools/composer.json").read_bytes())
    lock = json.loads((root / "tools/composer.lock").read_text())
    lock["packages"][0]["dist"]["url"] += "?token=private-secret"
    (project / "composer.lock").write_text(json.dumps(lock))
    secret = run(project)
    if secret.returncode != 1 or secret.stdout or "private-secret" in secret.stderr:
        raise AssertionError("Credential-bearing source URL leaked or was accepted")
    (project / "composer.lock").write_bytes(b"x" * (8388608 + 1))
    oversized = run(project)
    if oversized.returncode != 1 or oversized.stdout or "read budget" not in oversized.stderr \
            or "memory size" in oversized.stderr.lower():
        raise AssertionError("Oversized lock file was not rejected before decoding")

print("PASS locked inventory: exact root/tools/HTML Purifier graphs, deterministic output, lockless/secret/oversize refusal")
