#!/usr/bin/env python3
"""Exercise the optional ZIP inspector using only owned temporary files."""
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
with tempfile.TemporaryDirectory(prefix='sosecurity-archive-inspection-') as directory:
    subprocess.run([sys.executable, str(root / 'archive_inspection_fixtures.py'), directory], check=True)
    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'archive-inspection.php'), directory], check=True)
