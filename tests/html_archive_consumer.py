#!/usr/bin/env python3
"""Offline HTML Purifier consumer from the actual core archive."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('runtimes',nargs='+');a=p.parse_args();out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
report={'checks':[],'hashes':{}};env={k:v for k,v in os.environ.items() if not k.startswith(('SOSECURITY_TEST_','SOSECURITY_REQUIRE_'))};env['COMPOSER_DISABLE_NETWORK']='1'
def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,cmd,cwd,required=True):
 with (out/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=120)
 report['checks'].append({'name':name,'command':cmd,'exit':r.returncode});save()
 if required and r.returncode:raise RuntimeError(name+' failed')
with tempfile.TemporaryDirectory(prefix='sosecurity-html-archive-') as tmp:
 base=pathlib.Path(tmp);package=base/'package';package.mkdir();consumer=base/'consumer';consumer.mkdir()
 try:
  run('archive',['composer','archive','--format=zip','--dir='+str(base),'--file=core','--no-interaction'],ROOT)
  with zipfile.ZipFile(base/'core.zip') as z:
   assert not any(n.startswith(('/','tests/')) or '..' in pathlib.Path(n).parts or '-evidence-' in n for n in z.namelist());z.extractall(package)
  (consumer/'composer.json').write_text(json.dumps({'name':'sosecurity/html-archive-consumer','require':{'sohophp/sosecurity':'dev-main','ezyang/htmlpurifier':'4.19.1'},'repositories':[{'type':'path','url':str(package),'options':{'symlink':False,'versions':{'sohophp/sosecurity':'dev-main'}}}],'minimum-stability':'dev','prefer-stable':True,'config':{'allow-plugins':False,'platform':{'php':'7.2.34'}}}))
  run('install',['composer','install','--no-progress','--no-interaction','--no-scripts','--no-plugins'],consumer)
  report['locked_versions']={x['name']:x['version'] for x in json.loads((consumer/'composer.lock').read_text())['packages']};installed=consumer/'vendor/sohophp/sosecurity';assert not installed.is_symlink()
  for f in (ROOT/'src').rglob('*.php'):
   rel=f.relative_to(ROOT);h=hashlib.sha256(f.read_bytes()).hexdigest();assert hashlib.sha256((installed/rel).read_bytes()).hexdigest()==h;report['hashes'][str(rel)]=h
  tests=consumer/'tests';tests.mkdir()
  for name in ['bootstrap.php','html.php','html-provider-errors.php']:shutil.copyfile(ROOT/'tests'/name,tests/name)
  report['test_hashes']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in tests.iterdir()}
  (consumer/'helper.php').write_text('''<?php require __DIR__.'/vendor/sohophp/sosecurity/examples/rich-text.php';$s=SoSecurity\\Security::fromArray(['site'=>'consumer','html'=>[]]);$out=SoSecurity\\Examples\\cleanRichText($s->htmlCleaner(),'<p onclick="bad()">中文<strong>正常</strong><script>bad()</script><a href="javascript:bad()">坏链接</a></p>');if($out!=='<p>中文<strong>正常</strong><a>坏链接</a></p>')exit(1);echo "PASS installed HTML helper ".PHP_VERSION.PHP_EOL;''')
  (consumer/'origin.php').write_text('''<?php require __DIR__.'/vendor/autoload.php';foreach(['SoSecurity\\Output\\HtmlCleaner','SoSecurity\\Output\\HtmlPurifierSanitizer'] as $c){if(strpos((new ReflectionClass($c))->getFileName(),__DIR__.'/vendor/sohophp/sosecurity/')!==0)throw new RuntimeException('Incorrect core origin');}if(strpos((new ReflectionClass('HTMLPurifier'))->getFileName(),__DIR__.'/vendor/ezyang/htmlpurifier/')!==0)throw new RuntimeException('Incorrect purifier origin');''')
  for i,runtime in enumerate(a.runtimes):
   version=int(subprocess.check_output([runtime,'-r','echo PHP_VERSION_ID;'],text=True));assert 70200<=version<80600
   for name,args in [('purifier',[str(tests/'html.php'),str(consumer/'vendor/autoload.php')]),('exception',[str(tests/'html-provider-errors.php'),'exception']),('output',[str(tests/'html-provider-errors.php'),'output']),('helper',[str(consumer/'helper.php')])]:run(str(i)+'-'+str(version)+'-'+name,[runtime,'-d','memory_limit=32M','-d','auto_prepend_file='+str(consumer/'origin.php')]+args,consumer,False)
   run(str(i)+'-inventory',[runtime,str(ROOT/'bin/lock-inventory.php'),str(consumer)],consumer)
 finally:report['cleaned']=True;save()
if any(c['exit'] for c in report['checks']):raise SystemExit(1)
print('PASS HTML archive',len(report['checks']))
