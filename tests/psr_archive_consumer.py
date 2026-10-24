#!/usr/bin/env python3
"""Offline PSR adapter archive consumers; no external delivery or advisory request."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,time,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('package',choices=['psr15','psr3']);p.add_argument('--major',required=True,choices=['1','2','3']);p.add_argument('--output',required=True);p.add_argument('runtimes',nargs='+');p.add_argument('--wakeup-only',action='store_true');p.add_argument('--static',action='store_true');a=p.parse_args()
assert a.package!='psr15' or a.major in ['1','2']
assert not a.wakeup_only or a.package=='psr15'
out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True);report={'package':a.package,'major':a.major,'checks':[],'hashes':{}}
env={k:v for k,v in os.environ.items() if not k.startswith(('SOSECURITY_TEST_','SOSECURITY_REQUIRE_'))};env['COMPOSER_DISABLE_NETWORK']='1'
def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,cmd,cwd,required=True):
 at=time.monotonic()
 with (out/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=120)
 report['checks'].append({'name':name,'exit':r.returncode,'command':cmd,'seconds':time.monotonic()-at});save()
 if required and r.returncode:raise RuntimeError(name+' failed')
with tempfile.TemporaryDirectory(prefix='sosecurity-psr-archive-') as tmp:
 base=pathlib.Path(tmp);consumer=base/'consumer';consumer.mkdir();repos=[]
 try:
  for name,source,pkg in [('core',ROOT,'sohophp/sosecurity'),('adapter',ROOT/'integrations'/a.package,'sohophp/sosecurity-'+a.package)]:
   run(name+'-archive',['composer','archive','--format=zip','--dir='+str(base),'--file='+name,'--no-interaction'],source);unpack=base/name;unpack.mkdir()
   with zipfile.ZipFile(base/(name+'.zip')) as z:
    assert not any(n.startswith(('/','tests/')) or '..' in pathlib.Path(n).parts or '-evidence-' in n for n in z.namelist());z.extractall(unpack)
   repos.append({'type':'path','url':str(unpack),'options':{'symlink':False,'versions':{pkg:'dev-main'}}})
  requirements={'sohophp/sosecurity':'dev-main','sohophp/sosecurity-'+a.package:'dev-main'}
  if a.package=='psr15':requirements.update({'nyholm/psr7':'1.8.2','psr/http-message':'^1.1' if a.major=='1' else '^2.0'})
  else:requirements['psr/log']='^1.1' if a.major=='1' else '^'+a.major+'.0'
  minimum=80000 if a.package=='psr3' and a.major!='1' else 70200
  (consumer/'composer.json').write_text(json.dumps({'name':'sosecurity/psr-archive-consumer','require':requirements,'repositories':repos,'minimum-stability':'dev','prefer-stable':True,'config':{'allow-plugins':False,'platform':{'php':'8.0.30' if minimum==80000 else '7.2.34'}}}))
  run('install',['composer','install','--no-progress','--no-scripts','--no-plugins','--no-interaction'],consumer)
  report['locked_versions']={x['name']:x['version'] for x in json.loads((consumer/'composer.lock').read_text())['packages']};report['lock_sha256']=hashlib.sha256((consumer/'composer.lock').read_bytes()).hexdigest()
  for source,pkg in [(ROOT,'sohophp/sosecurity'),(ROOT/'integrations'/a.package,'sohophp/sosecurity-'+a.package)]:
   target=consumer/'vendor'/pkg;assert not target.is_symlink()
   for f in (source/'src').rglob('*.php'):
    rel=f.relative_to(source);h=hashlib.sha256(f.read_bytes()).hexdigest();assert hashlib.sha256((target/rel).read_bytes()).hexdigest()==h;report['hashes'][pkg+'/'+str(rel)]=h
  tests=consumer/'tests';tests.mkdir();name='psr15-budget' if a.package=='psr15' else 'psr3-audit';shutil.copyfile(ROOT/'tests'/(name+'.php'),tests/(name+'.php'))
  extra=ROOT/'tests'/(a.package+'-privacy.php')
  if extra.exists():shutil.copyfile(extra,tests/extra.name)
  cls='SoSecurity\\Psr15\\BudgetMiddleware' if a.package=='psr15' else 'SoSecurity\\Psr3\\AuditSink'
  origin=consumer/'origin.php';origin.write_text('<?php require __DIR__."/vendor/autoload.php";foreach('+json.dumps(['SoSecurity\\Security',cls])+ ' as $class){if(strpos((new ReflectionClass($class))->getFileName(),__DIR__."/vendor/sohophp/")!==0)throw new RuntimeException("Invalid consumer source");}')
  report['test_hashes']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in tests.glob('*.php')}
  if a.static:run('static',['php85',str(ROOT/'tools/vendor/bin/phpstan'),'analyse','--no-progress','--memory-limit=512M','--autoload-file='+str(consumer/'vendor/autoload.php'),str(ROOT/'integrations'/a.package/'src')],ROOT)
  for i,runtime in enumerate(a.runtimes):
   version=int(subprocess.check_output([runtime,'-r','echo PHP_VERSION_ID;'],text=True));assert minimum<=version<80600
   cases=([] if a.wakeup_only else [(name,[])]) + ([(extra.stem,[mode]) for mode in (['wakeup'] if a.wakeup_only else ['export','dump','serialize','wakeup'])] if extra.exists() else [])
   for test,params in cases:run(str(i)+'-'+str(version)+'-'+test+('-'+'-'.join(params) if params else ''),[runtime,'-d','memory_limit=32M','-d','auto_prepend_file='+str(origin),str(tests/(test+'.php')),str(consumer/'vendor/autoload.php')]+params,consumer,False)
   run(str(i)+'-inventory',[runtime,str(ROOT/'bin/lock-inventory.php'),str(consumer)],consumer)
 finally:report['cleaned']=True;save()
if any(c['exit'] for c in report['checks']):raise SystemExit(1)
print('PASS PSR archive',a.package,a.major,len(report['checks']))
