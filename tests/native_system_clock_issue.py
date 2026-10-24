"""Fresh default delegation workflow: observe first issuance; never resume an unknown outcome."""
import hashlib
import json
import pathlib
import subprocess
import tempfile
import sys
import signal
import re

root=pathlib.Path(__file__).resolve().parent.parent
if len(sys.argv)!=4:
    raise SystemExit('Usage: native_system_clock_issue.py PHP_RUNTIME VERSION_TAG NEW_EVIDENCE_DIRECTORY')
out=pathlib.Path(sys.argv[3]).resolve()
if not out.is_dir():raise RuntimeError('Create a dedicated evidence directory first')
runtime=sys.argv[1] if len(sys.argv)>1 else 'php85'
tag=sys.argv[2] if len(sys.argv)>2 else '85'
assert tag in ['72','73','74','80','81','82','83','84','85']
for name in ['timing','run','inputs','result']:
    suffix='.log' if name=='run' else '.json'
    assert not (out/('default-'+tag+'-'+name+suffix)).exists()
entry=root/'tests/state-boundary/native-maintenance.php'
delegation=root/'tests/state-boundary/native-audit-delegation.php'
inputs={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in list((root/'src').rglob('*.php'))+[entry,delegation]}
with tempfile.TemporaryDirectory(prefix='sosecurity-current-default-') as directory:
    work=pathlib.Path(directory)
    text=delegation.read_text()
    needle="$key=$api->issue('tenant','audit-owner',$token,'Owned audited key',['records:read']);"
    assert text.count(needle)==1
    timing="""Check::same(\\SoSecurity\\Support\\SystemClock::class,get_class($clock));Check::same(\\PDO::class,get_class($pdo));$ownedTimer=static function():float{return function_exists('hrtime')?hrtime(true)/1000000000:microtime(true);};$ownedCpuBefore=getrusage();$ownedWallBefore=$ownedTimer();$ownedIssueError=null;
try {$key=$api->issue('tenant','audit-owner',$token,'Owned audited key',['records:read']);}
catch (\\Throwable $error) {$ownedIssueError=$error;}
$ownedWallAfter=$ownedTimer();$ownedCpuAfter=getrusage();
$ownedSeconds=static function(array $r,string $type):float{return $r['ru_'.$type.'time.tv_sec']+$r['ru_'.$type.'time.tv_usec']/1000000;};
$ownedStatus='unavailable';try{$ownedStatus=$witness->inspect(static function():bool{return true;},true)['status'];}catch(\\Throwable $ownedInspectionError){}
$ownedResult=['clock_class'=>get_class($clock),'pdo_class'=>get_class($pdo),'status'=>$ownedStatus,'wall_seconds'=>($ownedWallAfter-$ownedWallBefore),'php_user_seconds'=>$ownedSeconds($ownedCpuAfter,'u')-$ownedSeconds($ownedCpuBefore,'u'),'php_system_seconds'=>$ownedSeconds($ownedCpuAfter,'s')-$ownedSeconds($ownedCpuBefore,'s'),'success'=>$ownedIssueError===null,'reason'=>$ownedIssueError instanceof \\SoSecurity\\Exception\\SecurityException?$ownedIssueError->reason():null,'php'=>PHP_VERSION,'credential_budget_ms'=>$api->policy()->ioMilliseconds()];
file_put_contents(RESULT_PATH,json_encode($ownedResult,JSON_PRETTY_PRINT).PHP_EOL);
if($ownedIssueError!==null){throw $ownedIssueError;}
Check::same(true,$key instanceof \SoSecurity\Api\IssuedCredential);Check::same(1,$key->metadata()->generation());Check::same(1,$count());Check::same('current',$ownedStatus);Check::same($source->digest(),$inspect()['digest']);
$ownedAuditRecord=json_decode($pdo->query('SELECT record FROM sosecurity_audit_records')->fetchColumn(),true);Check::same('authorization.allowed',$ownedAuditRecord['event']);Check::same(['allowed'=>true],$ownedAuditRecord['context']);
echo 'PASS default first issuance, actual credential, audit record and current witness; no further action'.PHP_EOL;return;
""".replace('RESULT_PATH',json.dumps(str(out/('default-'+tag+'-timing.json'))))
    text=text.replace(needle,timing).replace('__DIR__',json.dumps(str(delegation.parent)))
    # Keep the real SDK clock and wait for a fresh TOTP counter instead of advancing a test clock.
    text=text.replace('$clock->time+=30;', '$ownedNextCounter=(intdiv($clock->now(),30)+1)*30;while($clock->now()<$ownedNextCounter){usleep(100000);}')
    text=re.sub(r'\$clock->time(?![A-Za-z0-9_]|\s*(?:[+*/-]?=|\+\+|--))', '$clock->now()', text)
    (work/'delegation.php').write_text(text)
    text=entry.read_text().replace("require __DIR__.'/native-audit-delegation.php'",'require '+json.dumps(str(work/'delegation.php'))).replace('__DIR__',json.dumps(str(entry.parent)))
    text=text.replace('$clock=new NativeMaintenanceClock();', '$clock=new \\SoSecurity\\Support\\SystemClock();')
    text=re.sub(r'\$clock->time(?![A-Za-z0-9_]|\s*(?:[+*/-]?=|\+\+|--))', '$clock->now()', text)
    (work/'entry.php').write_text(text)
    wrapper=work/('runtime-'+tag)
    wrapper.write_text('#!/usr/bin/python3\nimport os,sys\na=[%r if x.endswith("/tests/state-boundary/native-maintenance.php") else x for x in sys.argv[1:]]\nos.execvp(%r,[%r]+a)\n'%(str(work/'entry.php'),runtime,runtime))
    wrapper.chmod(0o700)
    with (out/('default-'+tag+'-run.log')).open('w') as log:
        process=subprocess.Popen(['python3','tests/mysql_check.py','--native-audit-defaults',str(wrapper)],cwd=root,stdout=log,stderr=subprocess.STDOUT,env={k:v for k,v in __import__('os').environ.items() if not k.startswith(('SOSECURITY_TEST_','SOSECURITY_REQUIRE_'))})
        try:
            result_code=process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            result_code=process.wait(timeout=60)
            raise RuntimeError('First issuance timed out; controller cleanup finished')
assert all(hashlib.sha256((root/p).read_bytes()).hexdigest()==h for p,h in inputs.items())
(out/('default-'+tag+'-inputs.json')).write_text(json.dumps(inputs,indent=2)+'\n')
(out/('default-'+tag+'-result.json')).write_text(json.dumps({'exit':result_code,'inputs_unchanged':True,'temporary_probe_cleaned':True,'first_issuance_only':True,'runtime':runtime,'budget_changed':False},indent=2)+'\n')
raise SystemExit(result_code)
