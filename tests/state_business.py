#!/usr/bin/env python3
"""Bounded real SQL business-composition checks and affected native API compatibility."""
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parent.parent
if len(sys.argv)!=2:
    raise SystemExit('Use PHP runtime; MySQL uses mysql_check.py --state-api-business.')
for name in ['api-business','api-business-refusals','api-business-outcomes','api-native','api-intent','api-intent-formats']:
    subprocess.run([sys.argv[1],'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php'))],cwd=ROOT,check=True)
print('PASS finite native SQL business composition and affected API compatibility',flush=True)
