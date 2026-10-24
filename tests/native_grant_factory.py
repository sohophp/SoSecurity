#!/usr/bin/env python3
"""Only the policy-pinned factory and existing manual factory affected by the cache correction."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parent.parent
for name in ['grants-native-factory','factory']:
 subprocess.run([sys.argv[1],'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php'))],cwd=ROOT,check=True)
print('PASS targeted native grant policy-pinned and manual factory compatibility',flush=True)
