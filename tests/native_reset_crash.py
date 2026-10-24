#!/usr/bin/env python3
"""Three actual SIGKILL points and a concurrent writer waiting on the same witness."""
import os,sys,signal,subprocess,tempfile,selectors,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
runtime=sys.argv[1];backend=sys.argv[2] if len(sys.argv)>2 else 'sqlite'
assert backend in ['sqlite','mysql']
def ready(child,marker):
 deadline=time.monotonic()+240
 with selectors.DefaultSelector() as selector:
  selector.register(child.stdout,selectors.EVENT_READ)
  while time.monotonic()<deadline:
   if not selector.select(min(1,max(.01,deadline-time.monotonic()))):continue
   line=child.stdout.readline()
   if not line:break
   if line.strip()==marker:return
   print(line,end='',flush=True)
 raise RuntimeError('Owned child did not reach '+marker)
for mode in ['after-pending','after-sql-before-commit','after-commit-before-current']:
 with tempfile.TemporaryDirectory(prefix='sosecurity-reset-crash-') as private:
  print('OWNED_RESET_CRASH '+private,flush=True);env=dict(os.environ,TMPDIR=private);transport=str(Path(private)/'transport.json');args=[runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary/reset-native-crash-worker.php'),backend];writer=subprocess.Popen(args+['produce',mode,transport],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);contender=None
  try:
   ready(writer,'CRASH_READY')
   if mode=='after-sql-before-commit':
    contender=subprocess.Popen(args+['contend',mode,transport],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);ready(contender,'CONTENDER_READY');time.sleep(.25);assert contender.poll() is None,'Second writer must wait for the original witness owner'
   os.kill(writer.pid,signal.SIGKILL);assert writer.wait(timeout=10)==-signal.SIGKILL
   if contender is not None:
    output,_=contender.communicate(timeout=60);print(output,end='',flush=True);assert contender.returncode==0
   subprocess.run(args+['resume',mode,transport],cwd=ROOT,env=env,check=True,timeout=240)
   print('PASS real native-reset SIGKILL '+backend+' '+mode+('; concurrent writer waited then refused pending' if contender else ''),flush=True)
  finally:
   for child in [writer,contender]:
    if child is None:continue
    if child.poll() is None:child.kill();child.wait(timeout=10)
    child.stdout.close()
 print('CLEANED_RESET_CRASH '+private,flush=True);assert not Path(private).exists()
print('PASS native-reset real crash suite: 3 SIGKILL points, one concurrent writer, fresh-reader refusal and no callback replay',flush=True)
