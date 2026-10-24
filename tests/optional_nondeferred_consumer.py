#!/usr/bin/env python3
"""Offline archive consumers for explicitly reviewed, nondeferred optional-package checks."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,time,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('package',choices=['oidc','webauthn']);p.add_argument('runtimes',nargs='+');p.add_argument('--output',required=True);p.add_argument('--mysql-devices',action='store_true');p.add_argument('--authority-time-only',action='store_true');args=p.parse_args()
if (args.mysql_devices or args.authority_time_only) and args.package!='webauthn':raise RuntimeError('MySQL device selection requires WebAuthn')
out=pathlib.Path(args.output).resolve()
if out.exists() and any(out.iterdir()):raise RuntimeError('Use a new evidence output directory; existing results are preserved')
out.mkdir(parents=True,exist_ok=True)
with (out/'.consumer-owner').open('x') as owner:owner.write('optional-nondeferred-consumer'+chr(10))
env={k:v for k,v in os.environ.items() if not k.startswith(('SOSECURITY_TEST_','SOSECURITY_REQUIRE_','SOSECURITY_OIDC_','SOSECURITY_WEBAUTHN_'))};env.update(COMPOSER_DISABLE_NETWORK='1',COMPOSER_NO_INTERACTION='1')
report={'package':args.package,'checks':[],'hashes':{},'network':'Composer offline; no external services','deferred_suites_executed':False}
def save(): (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,cmd,cwd,extra=None,required=True):
 start=time.monotonic()
 with (out/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=cwd,env=dict(env,**(extra or {})),stdout=f,stderr=subprocess.STDOUT,timeout=180)
 report['checks'].append({'name':name,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start});save()
 if required and r.returncode:raise RuntimeError(name+' failed; inspect retained log')
 return r.returncode
directory=None
try:
 with tempfile.TemporaryDirectory(prefix='sosecurity-optional-nondeferred-') as directory:
  report['owned_directory']=directory;save()
  base=pathlib.Path(directory);consumer=base/'consumer';consumer.mkdir();repositories=[]
  try:
   for label,source,package in [('core',ROOT,'sohophp/sosecurity'),('adapter',ROOT/'integrations'/args.package,'sohophp/sosecurity-'+args.package)]:
    run(label+'-archive',['composer','--no-plugins','--no-scripts','archive','--format=zip','--dir='+str(base),'--file='+label,'--no-interaction'],source)
    unpack=base/label;unpack.mkdir()
    with zipfile.ZipFile(base/(label+'.zip')) as z:
     names=z.namelist()
     if any(n.startswith(('/','tests/')) or '..' in pathlib.Path(n).parts or '-evidence-' in n for n in names):raise RuntimeError('Unsafe or test archive member')
     z.extractall(unpack)
    repositories.append({'type':'path','url':str(unpack),'options':{'symlink':False,'versions':{package:'dev-main'}}})
   manifest={'name':'sosecurity/nondeferred-'+args.package+'-consumer','require':{'sohophp/sosecurity':'dev-main','sohophp/sosecurity-'+args.package:'dev-main'},'repositories':repositories,'minimum-stability':'dev','prefer-stable':True,'config':{'allow-plugins':False,'platform':{'php':'8.2.32' if args.package=='webauthn' else '7.2.34'}}}
   if args.package=='webauthn':manifest['require']['web-auth/webauthn-lib']='5.3.9'
   (consumer/'composer.json').write_text(json.dumps(manifest))
   run('install',['composer','install','--no-progress','--no-scripts','--no-plugins'],consumer)
   locked=json.loads((consumer/'composer.lock').read_text());versions={x['name']:x['version'] for x in locked['packages']};expected=('web-auth/webauthn-lib','5.3.9') if args.package=='webauthn' else ('jumbojett/openid-connect-php','v1.0.2');assert versions.get(expected[0])==expected[1]
   report['locked_versions']=versions;report['lock_sha256']=hashlib.sha256((consumer/'composer.lock').read_bytes()).hexdigest()
   for label,source,package in [('core',ROOT,'sohophp/sosecurity'),('adapter',ROOT/'integrations'/args.package,'sohophp/sosecurity-'+args.package)]:
    installed=consumer/'vendor'/package;assert not installed.is_symlink()
    for f in (source/'src').rglob('*.php'):
     rel=f.relative_to(source);a=hashlib.sha256(f.read_bytes()).hexdigest();b=hashlib.sha256((installed/rel).read_bytes()).hexdigest();assert a==b;report['hashes'][label+'/'+str(rel)]=a
   for name in ['tests','resources','examples']:shutil.copytree(ROOT/name,consumer/name)
   suite=consumer/'integrations'/args.package;suite.mkdir(parents=True);shutil.copytree(ROOT/'integrations'/args.package/'tests',suite/'tests')
   for f in (ROOT/'integrations'/args.package).glob('*.sql'):shutil.copy2(f,suite/f.name)
   # No workspace runtime sources are copied. Every process asserts the installed class origins first.
   classes=['SoSecurity\\Security','SoSecurity\\Auth\\AuthenticationFlow','SoSecurity\\Oidc\\FederatedSessions' if args.package=='oidc' else 'SoSecurity\\WebAuthn\\DeviceManager']
   origin=consumer/'origin.php';origin.write_text('<?php require __DIR__."/vendor/autoload.php"; foreach('+json.dumps(classes)+ ' as $class){$file=(new ReflectionClass($class))->getFileName();if(strpos($file,__DIR__."/vendor/sohophp/")!==0){throw new RuntimeException("Consumer class origin mismatch");}}')
   for index,runtime in enumerate(args.runtimes):
    version=int(subprocess.check_output([runtime,'-r','echo PHP_VERSION_ID;'],text=True));assert (80200<=version<80600) if args.package=='webauthn' else (70200<=version<80400)
    prefix=str(index)+'-'+str(version);autoload=str(consumer/'vendor/autoload.php');tests=suite/'tests';cases=[]
    if args.package=='webauthn':
     for name in ['smoke','list-budget','challenge','challenge-time','challenge-race','persisted','device-management','device-boundary','session-device-authority','authority-time','device-race']:cases.append((name,[str(tests/(name+'.php')),autoload]))
     for mode in ['normal','current-binding','return-binding','issue-reference','issue-provider','issue-clock','allow-reference','allow-provider','allow-clock','issue-proof','allow-proof']:cases.append(('binding-'+mode,[str(tests/'authority-binding.php'),autoload,mode]))
     for mode in ['before','current','return','notice','clock-before','clock-return']:cases.append(('boundary-'+mode,[str(tests/'device-boundary.php'),autoload,mode]))
     for mode in ['issue-expired','consume-backward','invalid-clock','consume-valid']:cases.append(('time-'+mode,[str(tests/'challenge-time.php'),autoload,mode]))
     for mode in ['register-large','authenticate-large']:cases.append(('list-'+mode,[str(tests/'list-budget.php'),autoload,mode]))
    else:
     for name in ['claims','client-debug','proof-export','fences','session-binding','batch-unlink','unlink-current','signed-callback','mfa-login']:cases.append((name,[str(tests/(name+'.php')),autoload]))
     for mode in ['absolute','idle','backwards','absolute-final','idle-final','live','live-final']:cases.append(('time-'+mode,[str(tests/'session-io-time.php'),mode,autoload]))
    if args.authority_time_only:cases=[case for case in cases if case[0]=='authority-time']
    for name,arguments in cases:run(prefix+'-'+name,[runtime,'-d','auto_prepend_file='+str(origin),'-d','memory_limit=32M']+arguments,consumer,required=False)
    run(prefix+'-inventory',[runtime,str(consumer/'bin/lock-inventory.php'),str(consumer)],consumer) if (consumer/'bin/lock-inventory.php').exists() else run(prefix+'-inventory',[runtime,str(ROOT/'bin/lock-inventory.php'),str(consumer)],consumer)
    if args.mysql_devices:run(prefix+'-mysql-devices',['python3','tests/mysql_check.py','--webauthn-devices',runtime],consumer,{'SOSECURITY_WEBAUTHN_AUTOLOAD':autoload},required=False)
   save()
  finally:report['cleanup_requested']=True;save()
finally:
 report['cleaned']=directory is None or not pathlib.Path(directory).exists();save()

if any(x['exit'] for x in report['checks']):raise SystemExit(1)
print('PASS nondeferred archive consumer',args.package,len(report['checks']))
