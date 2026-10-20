import json,os,signal,subprocess,sys,time
from pathlib import Path
runtime,config_name,action,mode=sys.argv[1:];config=Path(config_name);worker=Path(__file__).with_name('account-recovery-worker.php');settings=json.loads(config.read_text());children=[]
try:
 for i in range(1 if mode!='parallel' else 24):children.append(subprocess.Popen([runtime,'-d','memory_limit=8M',str(worker),str(config),action],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True))
 if mode!='parallel':
  end=time.monotonic()+25;ready=Path(settings['ready'])
  while not ready.exists():
   if children[0].poll() is not None:raise RuntimeError('Worker exited before its owned commit marker: '+str(children[0].communicate()))
   if time.monotonic()>=end:raise RuntimeError('Worker did not reach its owned commit marker')
   time.sleep(.01)
  children[0].kill();out,err=children[0].communicate(timeout=10);assert children[0].returncode==-signal.SIGKILL
  print(json.dumps({'killed':True,'phase':mode}));sys.exit(0)
 results=[]
 for child in children:
  out,err=child.communicate(timeout=30)
  if child.returncode!=0:raise RuntimeError('Recovery race unexpectedly failed: '+out+err)
  results.append(json.loads(out))
 print(json.dumps({'workers':len(results),'successful':sum(row['result'] is True for row in results)}))
finally:
 for child in children:
  if child.poll() is None:child.kill();child.communicate()
