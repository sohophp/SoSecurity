#!/usr/bin/env python3
"""Finite native reset proof/admission/password SQL, shared recovery and ordinary compatibility."""
from pathlib import Path
import os,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parent.parent
runtime,backend=sys.argv[1:]
assert backend in ['sqlite','mysql']
with tempfile.TemporaryDirectory(prefix='sosecurity-native-reset-group-') as private:
 print('OWNED_GROUP '+private,flush=True)
 env=dict(os.environ,TMPDIR=private)
 for name in ['reset-native','reset-native-refusals','reset-native-outcomes','reset-native-factory','links-native-factory','proof-retirement','proof-retirement-refusals','proof-retirement-resume']:
  subprocess.run([runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php')),backend],cwd=ROOT,env=env,check=True,timeout=480)
 if backend=='sqlite':
  for name in ['reset-flow','proof-epoch']:
   subprocess.run([runtime,'-d','memory_limit=8M',str(ROOT/'tests'/(name+'.php'))],cwd=ROOT,env=env,check=True,timeout=240)
 subprocess.run(['python3',str(ROOT/'tests/native_reset_crash.py'),runtime,backend],cwd=ROOT,env=env,check=True,timeout=720)
 print('PASS finite native reset: eight protected suites, three real SIGKILL points and contender; SQLite also ordinary reset SQL/proof epochs; not full recovery/F01/R1-R6 acceptance',flush=True)
print('CLEANED_GROUP '+private,flush=True)
assert not Path(private).exists()
