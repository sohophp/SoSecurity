#!/usr/bin/env python3
"""Verify that separate PHP workers share one audit event cap in a private FileStore."""
import concurrent.futures
import os
import subprocess
import sys
import tempfile
from pathlib import Path

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
worker = Path(__file__).with_name('audit-budgeted-worker.php')
with tempfile.TemporaryDirectory(prefix='sosecurity-audit-budget-') as directory:
    os.chmod(directory, 0o700)
    def run(number):
        result = subprocess.run([runtime, '-d', 'memory_limit=8M', str(worker), directory, 'actor-' + str(number)],
                                capture_output=True, text=True, timeout=15)
        if result.returncode or result.stdout.strip() not in ('ACCEPTED', 'REFUSED'):
            raise RuntimeError('Audit worker failed: ' + result.stdout + result.stderr)
        return result.stdout.strip()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(8)))
    if results.count('ACCEPTED') != 3 or results.count('REFUSED') != 5:
        raise AssertionError('Concurrent audit cap was not exact: ' + repr(results))
print('PASS budgeted audit process contention: 8 independent workers, exactly 3 accepted and 5 refused')
