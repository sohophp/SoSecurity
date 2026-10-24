#!/usr/bin/env python3
"""Owned process-death tests. No forked/shared PDO or serialized service graph."""
import os,sys,signal,subprocess,tempfile,selectors,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
runtime=sys.argv[1] if len(sys.argv)>1 else 'php'
backend=sys.argv[2] if len(sys.argv)>2 else 'sqlite'
modes=sys.argv[3:] or ['before-first','partial','after-all']
assert backend in ['sqlite','mysql'] and set(modes)<=set(['before-first','partial','after-all'])
for mode in modes:
 with tempfile.TemporaryDirectory(prefix='sosecurity-proof-crash-') as private:
  env=dict(os.environ,TMPDIR=private);transport=str(Path(private)/'transport.json');args=[runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary/proof-retirement-crash-worker.php'),backend]
  child=subprocess.Popen(args+['produce',mode,transport],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  try:
   deadline=time.monotonic()+240;ready=False
   with selectors.DefaultSelector() as selector:
    selector.register(child.stdout,selectors.EVENT_READ)
    while time.monotonic()<deadline:
     if not selector.select(min(1,max(.01,deadline-time.monotonic()))):continue
     line=child.stdout.readline()
     if not line:break
     if line.strip()=='CRASH_READY':ready=True;break
     print(line,end='',flush=True)
   if not ready:raise RuntimeError('Writer failed or did not reach the fixed durable crash point.')
   os.kill(child.pid,signal.SIGKILL);assert child.wait(timeout=10)==-signal.SIGKILL
   subprocess.run(args+['resume',mode,transport],cwd=ROOT,env=env,check=True,timeout=240)
   print('PASS owned process killed and fresh recovery: '+backend+' '+mode,flush=True)
  finally:
   if child.poll() is None:child.kill();child.wait(timeout=10)
   child.stdout.close()
print('PASS real proof epoch crash suite: '+str(len(modes))+' modes; private directories cleaned',flush=True)
