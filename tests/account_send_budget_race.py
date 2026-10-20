import concurrent.futures,json,os,pathlib,subprocess,sys,tempfile,time
stage=pathlib.Path(__file__).resolve().parent.parent;runtime=sys.argv[1];output=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else pathlib.Path(tempfile.mkdtemp(prefix='sosecurity-mail-race-results-'));output.mkdir(exist_ok=True)
def prepare(path):
 os.chmod(path,0o700);(path/'owned-send-budget-test').write_text('owned local budget state\n');(path/'state').mkdir(mode=0o700)
def run(path,mode):
 r=subprocess.run([runtime,'-d','memory_limit=8M',str(stage/'tests/account-send-budget-worker.php'),str(path),mode],capture_output=True,text=True,timeout=15)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
 return json.loads(r.stdout)
with tempfile.TemporaryDirectory(prefix='sosecurity-send-race-') as base:
 base=pathlib.Path(base);race=base/'race';race.mkdir();prepare(race)
 with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:rows=list(pool.map(lambda _:run(race,'race'),range(24)))
 assert sum(row['reserved'] for row in rows)==1,rows
 cases=[]
 for phase in ['reserved','started','accepted','unknown']:
  path=base/phase;path.mkdir();prepare(path);child=subprocess.Popen([runtime,'-d','memory_limit=8M',str(stage/'tests/account-send-budget-worker.php'),str(path),phase],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   end=time.monotonic()+15
   while not (path/'ready').exists():
    if child.poll() is not None:raise RuntimeError(child.communicate())
    if time.monotonic()>end:raise RuntimeError('Owned child readiness timeout')
    time.sleep(.01)
   child.kill();stdout,stderr=child.communicate(timeout=5);assert child.returncode==-9 and not stderr,(child.returncode,stdout,stderr)
  finally:
   if child.poll() is None:child.kill();child.communicate(timeout=5)
  retry=run(path,'retry');assert retry['reserved']==(phase=='reserved'),(phase,retry);cases.append({'phase':phase,'sigkill':True,'retry_admitted':retry['reserved']})
 (output/'report.json').write_text(json.dumps({'passed':True,'runtime':runtime,'workers':24,'admissions':1,'crashes':cases,'only_owned_private_file_store':True},indent=2));print('PASS actual send budget concurrency: 24 workers, one admission; four SIGKILL phases, started/accepted/unknown quarantined')
