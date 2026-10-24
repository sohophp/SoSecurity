#!/usr/bin/env python3
"""Two ordinary login requests compete for one pending OIDC MFA challenge; no recovery handoff."""
import subprocess
import sys
import tempfile
from pathlib import Path
from process_race import run, wait_for

autoload, runtime = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix="sosecurity-oidc-mfa-process-") as directory:
    base = [runtime, str(Path(__file__).with_name("mfa-process-worker.php")), autoload, directory]
    if run(base + ["setup"]) != "ready":
        raise RuntimeError("MFA setup failed")
    worker = subprocess.Popen(base + ["complete_pause"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_for(Path(directory) / "ready", worker)
        if run(base + ["compete"]) != "denied":
            raise RuntimeError("Competing MFA request was not denied")
    finally:
        (Path(directory) / "go").write_text("1")
        stdout, stderr = worker.communicate(timeout=15)
    if worker.returncode or stdout.decode().strip() != "authenticated":
        raise RuntimeError("First MFA completion failed: " + stderr.decode()[:1200])
    if run(base + ["replay"]) != "denied" or run(base + ["verify"]) != "verified":
        raise RuntimeError("MFA replay or exact proof consumption failed")
print("PASS OIDC MFA process competition: one session, one consumed proof, replay denied", runtime)
