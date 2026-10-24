#!/usr/bin/env python3
"""Two real serialized contests for one remaining physical file; no killing successful business work."""
import os,sys,signal,subprocess,tempfile,selectors,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
runtime,backend=sys.argv[1:]
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
for pair in ['links-reset','api-grants']:
 with tempfile.TemporaryDirectory(prefix='sosecurity-capacity-race-') as private:
  print('OWNED_CAPACITY_RACE '+private,flush=True);env=dict(os.environ,TMPDIR=private);args=[runtime,'-d','memory_limit=16M',str(ROOT/'tests/state-boundary/admission-capacity-race-worker.php'),backend];transport=str(Path(private)/'transport.json');writer=subprocess.Popen(args+['produce',pair,transport],cwd=ROOT,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);contender=None
  try:
   ready(writer,'CAPACITY_READY');contender=subprocess.Popen(args+['contend',pair,transport],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);ready(contender,'CONTENDER_READY');time.sleep(.25);assert contender.poll() is None,'Contender must wait for the first authority owner';os.kill(writer.pid,signal.SIGCONT);ready(writer,'WRITER_DONE');output,_=contender.communicate(timeout=240);print(output,end='',flush=True);assert contender.returncode==0;writer.stdin.write('CLEANUP\n');writer.stdin.flush();output,_=writer.communicate(timeout=60);print(output,end='',flush=True);assert writer.returncode==0;print('PASS real last-slot race '+backend+' '+pair+'; first current, contender capacity refusal without new pending',flush=True)
  finally:
   for child in [writer,contender]:
    if child is None:continue
    if child.poll() is None:child.kill();child.wait(timeout=10)
    child.stdout.close()
   if not writer.stdin.closed:writer.stdin.close()
 print('CLEANED_CAPACITY_RACE '+private,flush=True);assert not Path(private).exists()
print('PASS last-slot physical capacity concurrency: two SIGSTOP/CONT contests, two waiting contenders, all owned data cleaned',flush=True)
