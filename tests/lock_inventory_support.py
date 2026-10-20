"""Check a temporary Composer consumer's exact lock without publishing local paths."""
import hashlib
import json
from pathlib import Path
import subprocess


def verify(project, runtime, generator, required_packages):
    project = Path(project)
    result = subprocess.run([runtime, str(generator), str(project)], capture_output=True,
                            text=True, timeout=30)
    if result.returncode or result.stderr:
        raise RuntimeError("Locked consumer inventory failed: " + result.stderr[:1000])
    inventory = json.loads(result.stdout)
    if inventory["lock_sha256"] != hashlib.sha256((project / "composer.lock").read_bytes()).hexdigest():
        raise RuntimeError("Consumer inventory lock hash differs from the installed lock")
    by_name = {package["name"]: package for package in inventory["packages"]}
    if not set(required_packages).issubset(by_name):
        raise RuntimeError("Required consumer package is missing from locked inventory")
    for package in inventory["packages"]:
        dist = package["dist"]
        if dist is not None and dist["type"] == "path" and dist["url"] != "[local-path]":
            raise RuntimeError("Local Composer path leaked into locked inventory")
    if str(project) in result.stdout or "?token=" in result.stdout:
        raise RuntimeError("Private consumer path or source credential leaked")
    print("PASS locked consumer inventory: " + ", ".join(sorted(required_packages)))
