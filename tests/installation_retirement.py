#!/usr/bin/env python3
"""Bounded prior-factor installation checks on the real covered native graph."""
import os
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
runtime, backend = sys.argv[1:]
assert backend in ('sqlite', 'mysql')
compact = os.environ.get('SOSECURITY_TEST_INSTALLATION_COMPACT') == '1'
suites = ['installation-retirement', 'installation-resume', 'session-retirement', 'session-retirement-resume', 'session-retirement-refusals'] if compact else ['installation', 'installation-retirement', 'installation-resume', 'installation-refusals', 'installation-dependencies', 'installation-audit-compat', 'installation-legacy-manifests', 'session-retirement', 'session-retirement-resume', 'session-retirement-refusals']
for name in suites:
    subprocess.run([runtime, '-d', 'memory_limit=16M', str(ROOT/'tests/state-boundary'/(name+'.php')), backend], cwd=ROOT, check=True, timeout=360)
subprocess.run(['python3', str(ROOT/'tests/state_crash.py'), runtime, backend, 'before-prior', 'after-prior', 'after-session'], cwd=ROOT, env=dict(os.environ, SOSECURITY_TEST_INSTALL_SESSIONS='1'), check=True, timeout=720)
print('PASS prior-factor installation group: '+str(len(suites))+' suites and three real SIGKILL points; quarantine retained', flush=True)
