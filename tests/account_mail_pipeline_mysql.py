from account_smtp_server import *
class MySqlRelay(Relay):
 def revoke(self):
  details=json.loads(Path(self.s['coordination']).read_text());owned=Path(details['socket']);assert str(owned).startswith('/tmp/sosecurity-mysql-') and owned.name=='mysql.sock' and (owned.parent/'account-test-owner').is_file()
  result=subprocess.run(['mysql','--no-defaults','--socket='+str(owned),'-uroot','sosecurity_test','-e',"UPDATE account_example SET status='disabled',credential_version='owned-revocation'"],capture_output=True,text=True,timeout=3)
  if result.returncode:raise RuntimeError('Owned MySQL revocation failed')
Relay=MySqlRelay
with tempfile.TemporaryDirectory(prefix='smailpipe-') as private:
 directory=Path(private);os.chmod(directory,0o700);key=directory/'key.pem';cert=directory/'ca.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=smtp.example.test','-addext','subjectAltName=DNS:smtp.example.test','-days','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);os.chmod(key,0o600)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key));rows=[]
 for name,settings in [('accepted',{}),('revoked-before',{'revoke':'before'}),('revoked-after',{'revoke':'after'}),('accepted-reply-lost',{'drop_after_data':True,'accept_then_drop':True})]:
  settings={'mode':'tls','coordination':str(directory/'coord.json'),**settings};relay=Relay(context,settings,directory);config={**settings,'port':relay.port,'ca':str(cert)};config_path=directory/'config.json';config_path.write_text(json.dumps(config));os.chmod(config_path,0o600)
  result=subprocess.run([runtime,'-d','memory_limit=8M',str(stage/'tests/account-mail-pipeline-mysql.php'),str(config_path)],capture_output=True,text=True,timeout=20);(output/(name+'.log')).write_text(result.stdout+result.stderr)
  if result.returncode:relay.socket.close();raise RuntimeError(name+': '+result.stdout+result.stderr)
  relay.close();actual=json.loads(result.stdout)
  if name=='accepted':assert relay.accepted and actual['result']=={'state':'submitted','code':'smtp.accepted'} and actual['queue_state']=='sent' and actual['next']['state']=='idle',actual
  if name=='revoked-before':assert not relay.body and actual['account_status']=='disabled' and actual['result']['state']=='rejected' and actual['after']=='dead',actual
  if name=='revoked-after':assert relay.accepted and actual['exception']=='account.delivery_unknown' and actual['queue_state']=='leased' and actual['next']['state']=='discarded',actual
  if name=='accepted-reply-lost':assert relay.accepted and actual['result']['state']=='unknown' and actual['queue_state']=='dead' and actual['next']['state']=='idle',actual
  if relay.body:
   message=email.message_from_bytes(relay.body,policy=email.policy.default);assert message['To']=='owner@example.com';assert b'token=' in message.get_payload(decode=True)
  rows.append({'case':name,'actual':actual,'server_accepted':relay.accepted,'body_bytes':len(relay.body),'commands':relay.commands});print('PASS owned MySQL + actual SMTP '+name,flush=True)
 (output/'report.json').write_text(json.dumps({'runtime':runtime,'cases':rows,'passed':True,'only_owned_loopback_and_temporary_mysql':True},indent=2));print('PASS actual SQL/SMTP pipeline: '+str(len(rows)),flush=True)
