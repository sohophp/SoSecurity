#!/usr/bin/env python3
"""Finite main-SDK witness, admission, permissions and staged-recovery checks."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITES = [
    'fence-source-probe', 'fence-source', 'persistence', 'witness', 'isolation', 'entry', 'raw-store', 'grants-entry', 'grants-native', 'grants-native-refusals', 'grants-native-outcomes', 'grants-native-epoch', 'grants-native-factory', 'links-native', 'links-native-refusals', 'links-native-outcomes', 'links-native-factory', 'reset-native', 'reset-native-refusals', 'reset-native-outcomes', 'reset-native-factory', 'hmac-native', 'hmac-native-refusals', 'hmac-native-outcomes', 'hmac-native-factory', 'hmac-native-ring', 'admission-capacity-probe', 'admission-capacity', 'factory', 'lifecycle', 'native-requests', 'budget-refusals', 'immutable-plans', 'complete-backup', 'entry-scope', 'entry-input',
    'entry-outcomes', 'entry-stale', 'entry-workers', 'entry-enforcement',
    'permission', 'permission-binding', 'permission-current', 'permission-outcomes',
    'permission-password', 'permission-race', 'context-owner', 'retirement', 'stale-retirement', 'stale-retirement-refusals',
    'retirement-refusals', 'successor', 'successor-refusals', 'factor-resolution',
    'factor-resolution-integrity', 'account-resolution', 'account-resolution-refusals', 'recovery-audit', 'recovery-audit-refusals', 'recovery-audit-capacity', 'credentials', 'credentials-refusals', 'credentials-capacity', 'installation', 'installation-retirement', 'installation-resume', 'installation-refusals', 'installation-dependencies', 'installation-audit-compat', 'installation-legacy-manifests', 'session-retirement', 'session-retirement-resume', 'session-retirement-refusals', 'proof-retirement', 'proof-retirement-refusals', 'proof-retirement-resume', 'api-retirement', 'api-retirement-resume', 'api-retirement-refusals', 'api-epoch-backup', 'managed-api-entry', 'managed-api-retirement', 'managed-api-resume', 'managed-api-refusals', 'api-native', 'api-native-refusals', 'api-native-factory', 'api-native-delegation', 'api-native-boundary', 'api-intent', 'api-intent-refusals', 'api-intent-delegation', 'api-intent-formats', 'api-business', 'api-business-refusals', 'api-business-outcomes',
]
if __name__ == '__main__':
    runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
    arguments = sys.argv[2:]
    if arguments not in ([], ['mysql']):
        raise SystemExit('Use runtime [mysql]; MySQL requires the owned no-TCP controller.')
    for name in SUITES:
        subprocess.run([runtime, '-d', 'memory_limit=16M', str(ROOT/'tests/state-boundary'/(name+'.php')), *arguments], cwd=ROOT, check=True)
    subprocess.run([runtime, '-d', 'memory_limit=16M', str(ROOT/'tests/state-boundary/permission-race.php'), 'mysql' if arguments else 'sqlite', 'credential'], cwd=ROOT, check=True)
    subprocess.run(['python3',str(ROOT/'tests/state_crash.py'),runtime,'mysql' if arguments else 'sqlite','before-rename','after-rename','before-prior','after-prior','after-session','after-sql'],cwd=ROOT,env=dict(os.environ,SOSECURITY_TEST_INSTALL_SESSIONS='1'),check=True)
    subprocess.run(['python3',str(ROOT/'tests/api_retirement_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/api_retirement_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,env=dict(os.environ,SOSECURITY_TEST_MANAGED_API='1'),check=True)
    subprocess.run(['python3',str(ROOT/'tests/api_intent_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/business_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/proof_retirement_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/native_links_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/native_reset_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/native_hmac_crash.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    subprocess.run(['python3',str(ROOT/'tests/admission_capacity_race.py'),runtime,'mysql' if arguments else 'sqlite'],cwd=ROOT,check=True)
    print('PASS state boundary SDK: '+str(len(SUITES)+1)+' cases; staged recovery remains quarantined, not final reactivation', flush=True)
