#!/usr/bin/env python3
"""Twelve real writers compete for seven independent SQL audit slots; no external database."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import tempfile

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
backend = sys.argv[2] if len(sys.argv) > 2 else 'sqlite'
worker = str(Path(__file__).with_name('audit-sql-worker.php'))
with tempfile.TemporaryDirectory(prefix='sosecurity-audit-sql-') as directory:
    Path(directory, 'owner').write_text('local isolated audit test\n')
    def invoke(action, subject='worker'):
        result = subprocess.run([runtime, '-d', 'memory_limit=8M', worker, directory, action, backend, subject],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Audit SQL worker failed: ' + result.stderr[:1500])
        return result.stdout.strip()
    assert invoke('initialize') == 'READY'
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda i: invoke('write', 'actor-' + str(i)), range(12)))
    assert results.count('ACCEPTED') == 7 and results.count('FULL') == 5, results
    records = json.loads(invoke('inspect'))
    assert [int(row['sequence_no']) for row in records] == list(range(1, 8))
    assert len({json.loads(row['record'])['subject'] for row in records}) == 7
    assert invoke('write', 'overflow') == 'FULL'
print('PASS SQL audit process capacity on ' + backend + ': 12 workers, 7 accepted, 5 refused, unique durable sequences')
