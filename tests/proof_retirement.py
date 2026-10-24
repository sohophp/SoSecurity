#!/usr/bin/env python3
"""Finite real proof epochs, independent approval, native grants and SIGKILL checks."""
import os
import subprocess
import tempfile
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
runtime, backend = sys.argv[1:]
assert backend in ('sqlite', 'mysql')
with tempfile.TemporaryDirectory(prefix='sosecurity-proof-group-') as private:
    print('OWNED_GROUP '+private, flush=True)
    env = dict(os.environ, TMPDIR=private)
    if backend == 'sqlite':
        for name in ['proof-epoch', 'operations', 'operation-sql', 'links', 'reset-flow']:
            subprocess.run([runtime, '-d', 'memory_limit=8M', str(ROOT/'tests'/(name+'.php'))], cwd=ROOT, env=env, check=True, timeout=240)
    for name in ['proof-retirement', 'proof-retirement-refusals', 'proof-retirement-resume', 'grants-native', 'grants-native-epoch', 'grants-native-refusals', 'grants-native-outcomes', 'grants-native-factory', 'api-retirement']:
        subprocess.run([runtime, '-d', 'memory_limit=16M', str(ROOT/'tests/state-boundary'/(name+'.php')), backend], cwd=ROOT, env=env, check=True, timeout=480)
    subprocess.run(['python3', str(ROOT/'tests/proof_retirement_crash.py'), runtime, backend], cwd=ROOT, env=env, check=True, timeout=720)
    print('PASS native proof epoch group: nine protected suites, three real SIGKILL points; SQLite also checks five ordinary/low-level suites; quarantine remains', flush=True)
