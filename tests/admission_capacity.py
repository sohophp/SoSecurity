#!/usr/bin/env python3
"""Finite new-ledger physical capacity refusal and last-slot cross-service concurrency."""
from pathlib import Path
import os,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parent.parent
runtime,backend=sys.argv[1:]
assert backend in ['sqlite','mysql']
with tempfile.TemporaryDirectory(prefix='sosecurity-admission-capacity-group-') as private:
 print('OWNED_GROUP '+private,flush=True)
 env=dict(os.environ,TMPDIR=private)
 for name in ['admission-capacity-probe','admission-capacity','links-native','reset-native','grants-native','api-native','hmac-native-refusals']:
  subprocess.run([runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php')),backend],cwd=ROOT,env=env,check=True,timeout=480)
 if backend=='sqlite':
  for name in ['links','reset-flow','operations','api']:
   subprocess.run([runtime,'-d','memory_limit=8M',str(ROOT/'tests'/(name+'.php'))],cwd=ROOT,env=env,check=True,timeout=240)
  subprocess.run([runtime,'-d','memory_limit=8M',str(ROOT/'tests/state-snapshot/file-headroom.php')],cwd=ROOT,env=env,check=True,timeout=240)
 subprocess.run(['python3',str(ROOT/'tests/admission_capacity_race.py'),runtime,backend],cwd=ROOT,env=env,check=True,timeout=720)
 print('PASS finite native admission capacity: seven protected suites, two real last-slot cross-service contests; SQLite also four ordinary suites and physical headroom; no full F01/R1-R6 acceptance',flush=True)
print('CLEANED_GROUP '+private,flush=True)
assert not Path(private).exists()
