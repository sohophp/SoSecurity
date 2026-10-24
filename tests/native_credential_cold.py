"""Isolated read-only credential capture checks; native mode keeps the actual SystemClock."""
from pathlib import Path
import json,os,re,signal,subprocess,sys,tempfile
if len(sys.argv)!=4:raise SystemExit('Usage: native_credential_cold.py PHP_RUNTIME sqlite|mysql native|opaque|fallback')
runtime,backend,mode=sys.argv[1:];assert backend in ['sqlite','mysql'] and mode in ['native','opaque','fallback']
root=Path(__file__).resolve().parent.parent;entry=root/'tests/state-boundary/native-maintenance.php';delegation=root/'tests/state-boundary/native-audit-delegation.php'
with tempfile.TemporaryDirectory(prefix='sosecurity-credential-clock-') as directory:
 work=Path(directory);actual=entry
 if mode!='fallback':
  text=delegation.read_text().replace('__DIR__',json.dumps(str(delegation.parent))).replace('$clock->time+=30;','$ownedNextCounter=(intdiv($clock->now(),30)+1)*30;while($clock->now()<$ownedNextCounter){usleep(100000);}')
  text=re.sub(r'\$clock->time(?![A-Za-z0-9_]|\s*(?:[+*/-]?=|\+\+|--))','$clock->now()',text);(work/'delegation.php').write_text(text)
  text=entry.read_text();needle="require __DIR__.'/native-audit-delegation.php'";assert text.count(needle)==1;text=text.replace(needle,'require '+json.dumps(str(work/'delegation.php'))).replace('__DIR__',json.dumps(str(entry.parent)))
  assert text.count('$clock=new NativeMaintenanceClock();')==1;text=text.replace('$clock=new NativeMaintenanceClock();','$clock=new \\SoSecurity\\Support\\SystemClock();');text=re.sub(r'\$clock->time(?![A-Za-z0-9_]|\s*(?:[+*/-]?=|\+\+|--))','$clock->now()',text);actual=work/'entry.php';actual.write_text(text)
 expected=['-d','memory_limit=32M',str(entry),backend,'factory','audit_delegation','read-cold'];wrapper=work/'runtime'
 wrapper.write_text('#!/usr/bin/env python3\nimport os,sys\nexpected='+repr(expected)+'\nif sys.argv[1:]!=expected:raise RuntimeError("Unexpected isolated capture invocation")\nos.environ["SOSECURITY_TEST_CREDENTIAL_OPAQUE"]='+repr('1' if mode=='opaque' else '0')+'\na=['+repr(str(actual))+' if x=='+repr(str(entry))+' else x for x in sys.argv[1:]]\nos.execvp('+repr(runtime)+','+repr([runtime])+'+a)\n');wrapper.chmod(0o700)
 args=['python3','tests/mysql_check.py','--credential-cold-capture',str(wrapper)] if backend=='mysql' else [str(wrapper)]+expected
 env={k:v for k,v in os.environ.items() if not k.startswith(('SOSECURITY_TEST_','SOSECURITY_REQUIRE_'))}
 process=subprocess.Popen(args,cwd=root,env=env)
 try:code=process.wait(timeout=900)
 except subprocess.TimeoutExpired:process.send_signal(signal.SIGINT);process.wait(timeout=60);raise RuntimeError('Owned capture check timed out; controller cleanup completed')
raise SystemExit(code)
