#!/usr/bin/env python3
"""Portable managed-factor tests; each PHP case creates only owned local test state."""
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
suites = ['intent-history', 'intent-history-capacity', 'intent-history-approvals', 'intent-history-rekey', 'intent-history-safety', 'intent-history-purpose', 'migration-maintenance', 'migration-maintenance-closed', 'migration-maintenance-mixed', 'migration-maintenance-safety', 'migration-maintenance-capacity', 'operations', 'operations-notices', 'enrollment-notices', 'notice-queue-rotation', 'recovery-notices', 'recovery-terminal-notices', 'operations-safety', 'operations-input', 'enroll', 'enroll-cancel', 'enroll-safety', 'migration', 'migration-notices', 'migration-safety', 'lifecycle-migrated-operations', 'lifecycle-migrated-recovery', 'lifecycle-migrated-retirement', 'lifecycle-mixed-live', 'lifecycle-root-order', 'lifecycle-recovery-budget', 'lifecycle-actor-root-change', 'factory', 'first-provision', 'operation-resolution', 'resolution-notices', 'operation-resolution-safety', 'operation-resolution-approvals', 'operation-resolution-capabilities', 'operation-resolution-capacity', 'operation-resolution-cas', 'operation-resolution-durability', 'operation-resolution-processes', 'privileged-revocation', 'revocation-notices', 'privileged-revocation-safety', 'privileged-revocation-approvals', 'privileged-revocation-authentication', 'privileged-revocation-processes', 'restoration', 'restoration-notices', 'restoration-cleanup-notices', 'restoration-lifecycle', 'restoration-proof', 'restoration-faults', 'restoration-durability', 'restoration-approvals', 'restoration-rekey', 'restoration-capacity', 'restoration-processes', 'restoration-authentication', 'restoration-safety', 'restoration-previous-reader', 'restoration-maintenance-durability']
if __name__ == '__main__':
    runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
    arguments = sys.argv[2:]
    if arguments and (arguments[0] != 'mysql' or len(arguments) > 2 or (len(arguments) == 2 and arguments[1] not in ('file-store', 'mysql-store'))):
        raise SystemExit('Use runtime [mysql [file-store|mysql-store]]; MySQL requires the owned test controller.')
    for mode in ['work-process', 'closed-process', 'work-fiber', 'closed-fiber', 'child-release', 'clone-work', 'same-context', 'fiber-cancel']:
        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/account-factor/fence-context.php'), 'mysql' if arguments else 'sqlite', mode], check=True, cwd=root)
    for name in suites:
        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/account-factor' / (name + '.php')), *arguments], check=True, cwd=root)
    print('PASS managed factor SDK suites: ' + str(len(suites)), flush=True)
