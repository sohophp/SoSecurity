from pathlib import Path
import hashlib,json,os,sqlite3,subprocess,sys,tempfile,time

p=Path(__file__).resolve().parent
sdk=p.parent
runtime=sys.argv[1]
backend=sys.argv[3] if len(sys.argv)>3 else (sys.argv[2] if len(sys.argv)>2 and sys.argv[2] in ['sqlite','mysql'] else 'sqlite');assert backend in ['sqlite','mysql']
out=Path(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2] not in ['sqlite','mysql'] else Path(tempfile.mkdtemp(prefix='sosecurity-account-race-results-'));out.mkdir(parents=True,exist_ok=True)
files=[*sdk.joinpath('src').rglob('*.php'),sdk/'tests/bootstrap.php',sdk/'tests/webhook-inbox-support.php',sdk/'examples/SqlAccounts.php',p/'account-change-worker.php',Path(__file__),*sdk.joinpath('resources/sql').glob('account*.sql'),*sdk.joinpath('resources/sql').glob('outbox-*.sql')]
def snapshot():return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
before=snapshot();(out/'source.json').write_text(json.dumps(before,indent=2))
cases=[];active=[];started=0
expected_denials={'account.operation','account.authentication','account.change_incomplete','account.changed','authorization.denied','operation.authentication'}

socket=os.environ.get('SOSECURITY_TEST_MYSQL_SOCKET','')
if backend=='mysql':assert socket.startswith('/tmp/sosecurity-mysql-') and Path(socket).parent.joinpath('account-test-owner').is_file()

def execute_case(scenario):
 global started
 with tempfile.TemporaryDirectory(prefix='change-race-',dir='/tmp') as directory:
  d=Path(directory);(d/'test-owner').write_text('owned address-change concurrency test\n')
  for name in ['sessions','authentication','grants','budgets']:(d/name).mkdir(mode=0o700)
  case=out/scenario;case.mkdir()
  def command(mode,actor='alice',index=0,option=''):return [runtime,'-d','memory_limit=8M',str(p/'account-change-worker.php'),directory,mode,actor,str(index),option,backend]
  def one(mode,actor='alice',option='',allow_denied=False):
   r=subprocess.run(command(mode,actor,option=option),capture_output=True,text=True,timeout=50)
   label=mode+'-'+actor+('-'+option if option else '')
   (case/(label+'.stdout')).write_text(r.stdout);(case/(label+'.stderr')).write_text(r.stderr)
   assert not r.stderr,(scenario,label,'unexpected stderr',r.stderr)
   result=json.loads(r.stdout)
   if allow_denied:assert r.returncode==2 and result.get('reason') in expected_denials,(scenario,label,r.returncode,result)
   else:assert r.returncode==0,(scenario,label,r.returncode,result)
   return result
  def state():
   if backend=='sqlite':
    with sqlite3.connect(d/'race.sqlite',timeout=2) as db:return {json.loads(body)['subject']:json.loads(body)['state'] for (body,) in db.execute("SELECT payload FROM sosecurity_account_records WHERE kind='change'")}
   env=os.environ.copy();env['MYSQL_PWD']='integration-only'
   raw=subprocess.run(['mysql','--no-defaults','--socket='+socket,'-usosecurity_test','-Dsosecurity_test','--batch','--skip-column-names','--raw','-e',"SELECT CAST(payload AS CHAR) FROM sosecurity_account_records WHERE kind='change'"],env=env,capture_output=True,text=True,timeout=3)
   assert raw.returncode==0,raw.stderr
   return {json.loads(body)['subject']:json.loads(body)['state'] for body in raw.stdout.splitlines()}
  def wave(jobs,first=None):
   global started
   children=[];modes={mode for mode,actor in jobs}
   for path in d.glob('ready-*'):path.unlink()
   for mode in modes:
    go=d/('go-'+mode)
    if go.exists():go.unlink()
   try:
    for index,(mode,actor) in enumerate(jobs):
     stdout=(case/(mode+'-'+actor+'-'+str(index)+'.stdout')).open('w');stderr=(case/(mode+'-'+actor+'-'+str(index)+'.stderr')).open('w')
     child=subprocess.Popen(command(mode,actor,index),stdout=stdout,stderr=stderr);children.append((child,stdout,stderr,mode,actor,index));active.append(child);started+=1
    deadline=time.monotonic()+25
    while len(list(d.glob('ready-*')))!=len(jobs):
     assert all(child.poll() is None for child,*_ in children),'Owned worker exited before readiness'
     if time.monotonic()>=deadline:raise RuntimeError('Readiness barrier timed out')
     time.sleep(.01)
    if first:
     (d/('go-'+first)).write_text('go\n');expected='consumed' if first=='complete' else 'cancelled';deadline=time.monotonic()+20
     while state()['alice']!=expected:
      if time.monotonic()>=deadline:raise RuntimeError('Controlled first action did not commit')
      time.sleep(.01)
    for mode in modes:(d/('go-'+mode)).write_text('go\n')
    results=[]
    for child,stdout,stderr,mode,actor,index in children:
     code=child.wait(timeout=45);stdout.close();stderr.close()
     raw=(case/(mode+'-'+actor+'-'+str(index)+'.stdout')).read_text();err=(case/(mode+'-'+actor+'-'+str(index)+'.stderr')).read_text();assert not err,(scenario,mode,index,err)
     result=json.loads(raw)
     committed_unknown=code==2 and result.get('reason')=='account.completion_unknown' and result.get('error')=='SoSecurity\\Storage\\StorageException' and not result.get('sql_failure')
     assert code==0 or committed_unknown or (code==2 and result.get('reason') in expected_denials),(scenario,mode,index,code,result)
     results.append({'mode':mode,'actor':actor,'exit':code,'result':result.get('result') is True,'reason':result.get('reason'),'removed':result.get('removed',0),'committed_unknown':committed_unknown})
    return results
   finally:
    for child,stdout,stderr,*_ in children:
     if child.poll() is None:child.terminate();child.wait(timeout=5)
     stdout.close();stderr.close()
  unique=scenario=='target-unique';assert one('setup',option='unique' if unique else 'single')=={'setup':True,'actors':2 if unique else 1}
  if scenario=='cleanup':
   assert one('expire')=={'expired':True};rows=wave([('maintain','alice')]*24);final=one('inspect')
   assert sum(row['removed'] for row in rows)==5 and sum(row['removed']>0 for row in rows)==1 and all(row['exit']==0 for row in rows),rows
   actor=final['actors']['alice'];assert not actor['changed'] and actor['state'] is None and actor['password_preserved'] and final['records']==0 and final['notices']==3,final
   cases.append({'scenario':scenario,'workers':24,'removed':5,'final':final});return
  if scenario=='proofs':
   rows=wave([('old','alice')]*12+[('new','alice')]*12);final=one('inspect')
   assert sum((row['result'] or row['committed_unknown']) and row['mode']=='old' for row in rows)==1 and sum((row['result'] or row['committed_unknown']) and row['mode']=='new' for row in rows)==1
   actor=final['actors']['alice'];assert actor['state']=='ready' and not actor['changed'] and actor['attempts_old']==actor['attempts_new']==1 and final['records']==5 and final['notices']==3,final
   cases.append({'scenario':scenario,'workers':24,'committed_proofs':2,'completion_unknown':sum(row['committed_unknown'] for row in rows),'final':final});return
  actors=['alice','bob'] if unique else ['alice']
  for actor in actors:assert one('ready',actor)=={'ready':True}
  for actor in actors:assert one('approve',actor)=={'approved':True}
  before_state=one('inspect')
  if scenario in ['kill-before','kill-after']:
   (d/'go-complete').write_text('go\n');r=subprocess.run(command('complete',option=scenario),capture_output=True,text=True,timeout=45);assert r.returncode==-9 and not r.stdout and not r.stderr,(scenario,r.returncode,r.stdout,r.stderr)
   after_kill=one('inspect');changed=scenario=='kill-after';assert after_kill['actors']['alice']['changed']==changed and after_kill['actors']['alice']['state']==('consumed' if changed else 'ready') and after_kill['notices']==(5 if changed else 3)
   denied=one('complete',allow_denied=True);assert denied['reason'] in expected_denials
   if not changed:
    assert one('approve')=={'approved':True};assert one('complete')=={'result':True}
   final=one('inspect');assert final['actors']['alice']['changed'] and final['actors']['alice']['state']=='consumed' and final['notices']==5 and final['root_revision']==before_state['root_revision']+3,final
   cases.append({'scenario':scenario,'terminated_exit':-9,'same_grant_denied':True,'fresh_grant_required':not changed,'after_kill':after_kill,'final':final});return
  if unique:jobs=[('complete','alice')]*12+[('complete','bob')]*12
  elif scenario=='complete':jobs=[('complete','alice')]*24
  else:jobs=[('complete','alice')]*12+[('cancel','alice')]*12
  rows=wave(jobs,first='complete' if scenario=='complete-first' else ('cancel' if scenario=='cancel-first' else None));final=one('inspect')
  assert sum(row['result'] or row['committed_unknown'] for row in rows)==1,(scenario,rows,final)
  changed=sum(actor['changed'] for actor in final['actors'].values())
  if scenario in ['complete','complete-first','target-unique']:assert changed==1,final
  if scenario=='cancel-first':assert changed==0,final
  assert final['records']==5*len(actors)+(2 if changed else 0) and final['notices']==3*len(actors)+(2 if changed else 0) and final['root_revision']==before_state['root_revision']+(3 if changed else 1),final
  assert all(actor['password_preserved'] and actor['version_advanced']==actor['changed'] and actor['address_version_advanced']==actor['changed'] for actor in final['actors'].values())
  assert all(actor['old_session_rejected'] for actor in final['actors'].values() if actor['changed']),final
  if not changed:assert final['actors']['alice']['state']=='cancelled',final
  cases.append({'scenario':scenario,'workers':24,'committed_actions':1,'completion_unknown':sum(row['committed_unknown'] for row in rows),'changed_accounts':changed,'final':final})

try:
 for scenario in ['proofs','cleanup','complete','contended','complete-first','cancel-first','target-unique','kill-before','kill-after']:
  execute_case(scenario);print(json.dumps({'scenario':scenario,'passed':True}),flush=True)
finally:
 for child in active:
  if child.poll() is None:child.terminate();child.wait(timeout=5)
 report={'runtime':runtime,'cases':cases,'concurrent_processes':started,'source_files':len(before),'source_unchanged':before==snapshot(),'backend':backend+' / shared FileStore','evidence_directory':str(out),'passed':len(cases)==9}
 (out/'report.json').write_text(json.dumps(report,indent=2))
assert report['passed'] and report['source_unchanged']
print(json.dumps({key:value for key,value in report.items() if key!='cases'}),flush=True)
