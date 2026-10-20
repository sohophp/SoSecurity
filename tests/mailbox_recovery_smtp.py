import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from account_smtp_server import *
stage=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='smailbox-') as private:
 directory=Path(private);os.chmod(directory,0o700);key=directory/'key.pem';cert=directory/'ca.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=smtp.example.test','-addext','subjectAltName=DNS:smtp.example.test','-days','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);os.chmod(key,0o600)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key));rows=[]
 for name,extra in [('accepted',{}),('revoked-before',{'revoke':'before'}),('revoked-after',{'revoke':'after'}),('accepted-reply-lost',{'drop_after_data':True,'accept_then_drop':True})]:
  settings={'mode':'tls','coordination':str(directory/'coord.json'),**extra};relay=Relay(context,settings,directory);cfg=directory/'config.json';cfg.write_text(json.dumps({**settings,'port':relay.port,'ca':str(cert)}));os.chmod(cfg,0o600)
  r=subprocess.run([runtime,'-d','memory_limit=8M',str(stage/'tests/mailbox-recovery-smtp.php'),str(cfg)],capture_output=True,text=True,timeout=20);(output/(name+'.log')).write_text(r.stdout+r.stderr)
  if r.returncode:relay.socket.close();raise RuntimeError(r.stdout+r.stderr)
  relay.close();actual=json.loads(r.stdout)
  if name=='accepted':assert relay.accepted and actual['confirmed'] and actual['queue']=='sent' and actual['address']=='rescued@example.com',actual
  if name=='revoked-before':assert not relay.body and not actual['confirmed'] and actual['queue']=='dead' and actual['address']=='owner@example.com',actual
  if name=='revoked-after':assert relay.accepted and not actual['confirmed'] and actual['error']=='account.delivery_unknown' and actual['queue']=='leased' and actual['address']=='owner@example.com',actual
  if name=='accepted-reply-lost':assert relay.accepted and not actual['confirmed'] and actual['result']['state']=='unknown' and actual['queue']=='dead',actual
  if relay.body:
   mail=email.message_from_bytes(relay.body,policy=email.policy.default);assert mail['To']=='rescued@example.com';body=mail.get_payload(decode=True).decode();url=next(line for line in body.splitlines() if line.startswith('https://'));import urllib.parse
   parsed=urllib.parse.urlparse(url);fields=urllib.parse.parse_qs(parsed.fragment);assert parsed.path=='/recover_address' and hashlib.sha256(fields['token'][0].encode()).hexdigest()==actual['token_hash']
  rows.append({'case':name,'actual':actual,'body_bytes':len(relay.body)});print('PASS actual mailbox SQLite/SMTP '+name,flush=True)
 (output/'report.json').write_text(json.dumps({'passed':True,'runtime':runtime,'cases':rows,'temporary_sqlite_and_loopback_only':True,'approval_is_test_implementation':True},indent=2))
