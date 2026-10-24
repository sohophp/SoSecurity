#!/usr/bin/env python3
"""Finite native one-use lifecycle/business SQL and affected ordinary/manual compatibility."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parent.parent
assert len(sys.argv)==2
for name in ['grants-native','grants-native-refusals','grants-native-outcomes','grants-native-factory','grants-entry','factory','api-intent']:
 subprocess.run([sys.argv[1],'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php'))],cwd=ROOT,check=True)
for name in ['operations','operation-sql']:
 subprocess.run([sys.argv[1],'-d','memory_limit=8M',str(ROOT/'tests'/(name+'.php'))],cwd=ROOT,check=True)
print('PASS finite native grants with ordinary/manual/factory/API compatibility; no full-plan or final recovery claim',flush=True)
