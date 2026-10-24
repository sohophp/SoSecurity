#!/usr/bin/env python3
"""Finite physical fence rollback and native/recovery compatibility checks."""
from pathlib import Path
import os,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parent.parent
runtime,backend=sys.argv[1:]
assert backend in ['sqlite','mysql']
with tempfile.TemporaryDirectory(prefix='sosecurity-fence-source-group-') as private:
 print('OWNED_GROUP '+private,flush=True)
 env=dict(os.environ,TMPDIR=private)
 for name in ['fence-source-probe','fence-source','entry-workers','factory','hmac-native-factory','reset-native-factory','installation','proof-retirement']:
  subprocess.run([runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary'/(name+'.php')),backend],cwd=ROOT,env=env,check=True,timeout=480)
 if backend=='sqlite':
  subprocess.run([runtime,'-d','memory_limit=8M',str(ROOT/'tests/fence-state.php')],cwd=ROOT,env=env,check=True,timeout=120)
 subprocess.run(['python3',str(ROOT/'tests/native_hmac_crash.py'),runtime,backend],cwd=ROOT,env=env,check=True,timeout=720)
 print('PASS finite fence source: eight protected suites, two fresh readers, three real SIGKILL points and contender; not final reactivation/F01/R1-R6 acceptance',flush=True)
print('CLEANED_GROUP '+private,flush=True)
assert not Path(private).exists()
