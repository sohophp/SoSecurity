#!/usr/bin/env python3
"""Finite native link admission/business SQL with affected ordinary/manual compatibility."""
from pathlib import Path
import os,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parent.parent
runtime,backend=sys.argv[1:]
assert backend in ['sqlite','mysql']
with tempfile.TemporaryDirectory(prefix='sosecurity-native-links-group-') as private:
 print('OWNED_GROUP '+private,flush=True)
 env=dict(os.environ,TMPDIR=private)
 for name in ['links-native','links-native-refusals','links-native-outcomes','links-native-factory','grants-native-factory','proof-retirement','proof-retirement-refusals','proof-retirement-resume']:
  subprocess.run([runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php')),backend],cwd=ROOT,env=env,check=True,timeout=480)
 if backend=='sqlite':
  for name in ['links','proof-epoch']:
   subprocess.run([runtime,'-d','memory_limit=8M',str(ROOT/'tests'/(name+'.php'))],cwd=ROOT,env=env,check=True,timeout=240)
 subprocess.run(['python3',str(ROOT/'tests/native_links_crash.py'),runtime,backend],cwd=ROOT,env=env,check=True,timeout=720)
 print('PASS finite native links: eight protected suites, three real SIGKILL points and contender; SQLite also ordinary links/proof epochs; not full F01/R1-R6 acceptance',flush=True)
print('CLEANED_GROUP '+private,flush=True)
assert not Path(private).exists()
