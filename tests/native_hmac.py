#!/usr/bin/env python3
"""Finite covered HMAC key configuration, nonce/business SQL and compatibility checks."""
from pathlib import Path
import os,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parent.parent
runtime,backend=sys.argv[1:]
assert backend in ['sqlite','mysql']
with tempfile.TemporaryDirectory(prefix='sosecurity-native-hmac-group-') as private:
 print('OWNED_GROUP '+private,flush=True)
 env=dict(os.environ,TMPDIR=private)
 for name in ['hmac-native','hmac-native-refusals','hmac-native-outcomes','hmac-native-factory','hmac-native-ring','reset-native-factory','proof-retirement']:
  subprocess.run([runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php')),backend],cwd=ROOT,env=env,check=True,timeout=480)
 if backend=='sqlite':
  for name in ['api','hmac-state']:
   subprocess.run([runtime,'-d','memory_limit=8M',str(ROOT/'tests'/(name+'.php'))],cwd=ROOT,env=env,check=True,timeout=240)
 subprocess.run(['python3',str(ROOT/'tests/native_hmac_crash.py'),runtime,backend],cwd=ROOT,env=env,check=True,timeout=720)
 print('PASS finite native HMAC: seven protected suites, fresh configuration rollback reader, three real SIGKILL points and contender; SQLite also ordinary API/pure nonce source checks; not full recovery/F01/R1-R6 acceptance',flush=True)
print('CLEANED_GROUP '+private,flush=True)
assert not Path(private).exists()
