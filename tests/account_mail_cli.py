from account_smtp_server import *
worker=stage/'examples/account-mail-worker.php'
with tempfile.TemporaryDirectory(prefix='smailcli-') as private:
 directory=Path(private);os.chmod(directory,0o700);key=directory/'key.pem';cert=directory/'ca.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=smtp.example.test','-addext','subjectAltName=DNS:smtp.example.test','-days','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);os.chmod(key,0o600)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key));rows=[]
 for name,extra,expected_exit in [('accepted',{},0),('revoked-before',{'revoke':'before'},2),('revoked-after',{'revoke':'after'},1),('accepted-reply-lost',{'drop_after_data':True,'accept_then_drop':True},2)]:
  state=directory/'state.json';settings={'mode':'tls','coordination':str(directory/'coord.json'),**extra};relay=Relay(context,settings,directory);config={**settings,'port':relay.port,'ca':str(cert),'state':str(state)};cfg=directory/'config.json';cfg.write_text(json.dumps(config));os.chmod(cfg,0o600)
  bootstrap=directory/'worker.php';bootstrap.write_text("""<?php
require 'STAGE/tests/account-dispatch-support.php';
$config=json_decode(file_get_contents(__DIR__.'/config.json'),true);$e=new RegistrationEnvironment();
register_shutdown_function(static function()use($e,$config):void{file_put_contents($config['state'],json_encode(['queue'=>$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn(),'account'=>$e->account()['status']]));chmod($config['state'],0600);$e->close();});
$source=$e->service();$source->initialize();$source->request('owner@example.com','owned-source');file_put_contents($config['coordination'],json_encode(['database'=>$e->directory.'/registration.sqlite']));chmod($config['coordination'],0600);
$transport=new SoSecurity\\Account\\SmtpTransport('local-test','smtp.example.test',$config['port'],'127.0.0.1','tls',null,$config['ca']);return dispatcher($e,$source,$transport);
""".replace('STAGE',str(stage)));os.chmod(bootstrap,0o600)
  env={**os.environ,'SOSECURITY_ACCOUNT_MAIL_BOOTSTRAP':str(bootstrap)};r=subprocess.run([runtime,'-d','memory_limit=8M',str(worker),'--once'],env=env,capture_output=True,text=True,timeout=15);(output/(name+'.log')).write_text(r.stdout+r.stderr)
  if r.returncode!=expected_exit:relay.socket.close();raise RuntimeError((name,r.returncode,r.stdout,r.stderr))
  relay.close();assert r.returncode==expected_exit,(name,r.returncode,r.stdout,r.stderr)
  actual=json.loads(r.stdout) if r.stdout else None;stored=json.loads(state.read_text())
  if name=='accepted':assert relay.accepted and actual=={'state':'submitted','code':'smtp.accepted'} and stored['queue']=='sent'
  if name=='revoked-before':assert not relay.body and actual['state']=='rejected' and stored['queue']=='dead'
  if name=='revoked-after':assert relay.accepted and not r.stdout and r.stderr=='account_mail_worker.unavailable\n' and stored['queue']=='leased'
  if name=='accepted-reply-lost':assert relay.accepted and actual['state']=='unknown' and stored['queue']=='dead'
  rows.append({'case':name,'exit':r.returncode,'result':actual,'stored':stored,'body_bytes':len(relay.body)});print('PASS actual account mail CLI '+name,flush=True)
 marker=directory/'should-not-run';bootstrap.write_text('<?php file_put_contents('+json.dumps(str(marker))+',"bad");');os.chmod(bootstrap,0o600)
 for args in [[],['--once','--after=-1'],['--once','--after=01'],['--once','--after=1','extra']]:
  r=subprocess.run([runtime,str(worker),*args],env=env,capture_output=True,text=True,timeout=5);assert r.returncode==1 and not marker.exists() and r.stderr=='account_mail_worker.unavailable\n'
 r=subprocess.run([runtime,'-r','require '+json.dumps(str(worker))+'; echo "INERT";'],env=env,capture_output=True,text=True,timeout=5);assert r.returncode==0 and r.stdout=='INERT' and not marker.exists()
 for refusal in ['public-file','public-parent','symlink','oversize']:
  bootstrap.write_text('<?php file_put_contents('+json.dumps(str(marker))+',"bad");');os.chmod(bootstrap,0o600);os.chmod(directory,0o700);chosen=bootstrap
  if refusal=='public-file':os.chmod(bootstrap,0o644)
  if refusal=='public-parent':os.chmod(directory,0o755)
  if refusal=='symlink':chosen=directory/'alias.php';chosen.symlink_to(bootstrap)
  if refusal=='oversize':bootstrap.write_text(bootstrap.read_text()+'/*'+'x'*65536+'*/')
  checked={**env,'SOSECURITY_ACCOUNT_MAIL_BOOTSTRAP':str(chosen)};r=subprocess.run([runtime,str(worker),'--once'],env=checked,capture_output=True,text=True,timeout=5)
  assert r.returncode==1 and not marker.exists() and r.stderr=='account_mail_worker.unavailable\n',(refusal,r.returncode,r.stdout,r.stderr)
  if refusal=='symlink':chosen.unlink()
 os.chmod(directory,0o700)

 (output/'report.json').write_text(json.dumps({'passed':True,'runtime':runtime,'cases':rows,'invalid_invocations':4,'unsafe_bootstraps_refused':4,'import_inert':True,'only_owned_temporary_sqlite_and_loopback':True},indent=2))
