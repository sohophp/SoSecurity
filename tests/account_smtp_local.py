from account_smtp_server import *
with tempfile.TemporaryDirectory(prefix='smail-') as private:
 directory=Path(private);os.chmod(directory,0o700);key=directory/'key.pem';cert=directory/'ca.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=smtp.example.test','-addext','subjectAltName=DNS:smtp.example.test','-days','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);os.chmod(key,0o600)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key))
 cases=[('tls',{'mode':'tls'},'accepted'),('starttls-auth',{'mode':'starttls','auth':True},'accepted'),('unix',{'mode':'unix'},'accepted'),('utf8',{'mode':'tls','utf8':True,'smtp_utf8':True},'accepted'),('utf8-missing',{'mode':'tls','utf8':True},'rejected'),('utf8-stripped',{'mode':'starttls','utf8':True,'smtp_utf8':True,'strip_utf8_after_tls':True},'rejected'),('tls-required',{'mode':'starttls','no_starttls':True,'auth':True},'rejected'),('bad-host',{'mode':'tls','host':'other.example.test'},'rejected'),('header-bound',{'mode':'tls','oversize':True},'rejected'),('recipient-refused',{'mode':'tls','recipient_refused':True},'rejected'),('gate-refused',{'mode':'tls','gate_false':True},'rejected'),('final-temporary',{'mode':'tls','final':451},'rejected'),('final-permanent',{'mode':'tls','final':550},'rejected'),('lost-final',{'mode':'tls','drop_after_data':True},'unknown'),('late-final',{'mode':'tls','delay_after_data':.8,'milliseconds':300},'unknown'),('bare-final',{'mode':'tls','bare_final':True},'accepted'),('large-header',{'mode':'tls','large_header':True},'rejected')]
 cases += [('line-exact',{'mode':'tls','ehlo_raw':'250-'+'X'*506+'\r\n250 OK\r\n'},'accepted'),('line-over',{'mode':'tls','ehlo_raw':'250-'+'X'*507+'\r\n250 OK\r\n'},'rejected'),('reply-total',{'mode':'tls','ehlo_raw':('250-'+'X'*120+'\r\n')*70+'250 OK\r\n'},'rejected'),('reply-group',{'mode':'tls','ehlo_raw':'250-first\r\n251 wrong\r\n'},'rejected'),('reply-nul',{'mode':'tls','ehlo_raw':'250-\0hidden\r\n250 OK\r\n'},'rejected'),('greeting-timeout',{'mode':'tls','greeting_delay':.8,'milliseconds':300},'rejected'),('tls-timeout',{'mode':'tls','tls_delay':.8,'milliseconds':300},'rejected'),('auth-refused',{'mode':'starttls','auth':True,'auth_refuse':True},'rejected'),('large-final',{'mode':'tls','large_final':True},'unknown')]
 if len(sys.argv)>3:cases=[row for row in cases if row[0] in sys.argv[3:]]
 rows=[]
 for name,settings,expected in cases:
  settings={'mode':'tls','auth':False,'utf8':False,'host':'smtp.example.test','gate_false':False,'milliseconds':3000,**settings};relay=Relay(context,settings,directory);config={**settings,'port':relay.port,'socket':relay.path,'ca':str(cert)};config_path=directory/'config.json';config_path.write_text(json.dumps(config));os.chmod(config_path,0o600)
  result=subprocess.run([runtime,'-d','memory_limit=8M',str(stage/'tests/account-smtp.php'),str(config_path)],capture_output=True,text=True,timeout=12);(output/(name+'.log')).write_text(result.stdout+result.stderr)
  if result.returncode:
   relay.socket.close();raise RuntimeError(name+' failed: '+result.stdout+result.stderr)
  relay.close()
  actual=json.loads(result.stdout);assert actual['state']==expected,(name,actual,relay.commands,relay.error);assert actual['private_export'];assert actual['elapsed']<settings['milliseconds']/1000+1.5,(name,actual);assert actual['peak']<=8388608
  if expected=='accepted':
   assert relay.accepted and actual['gate_calls']>0,(name,actual,relay.commands)
   message=email.message_from_bytes(relay.body,policy=email.policy.default);assert message['Message-ID']==actual['message_id'];assert message['To']==('用户@example.test' if settings['utf8'] else 'owner@example.test');assert b'bbbbbbbbbbbbbbbb' in message.get_payload(decode=True);assert not message['Bcc'];assert not message['Cc']
  if name=='starttls-auth':assert relay.authenticated
  if name in ['utf8-missing','utf8-stripped','tls-required','bad-host','header-bound','large-header','line-over','reply-total','reply-group','reply-nul','greeting-timeout','tls-timeout','auth-refused']:assert not any(c.startswith('MAIL ') for c in relay.commands),(name,relay.commands)
  if name=='gate-refused':assert not relay.body
  if name=='utf8':assert any('SMTPUTF8' in c for c in relay.commands if c.startswith('MAIL ')),relay.commands
  if name=='final-temporary':assert actual['retryable'] is True
  if name=='final-permanent':assert actual['retryable'] is False
  if name in ['lost-final','late-final']:assert actual['retryable'] is False and relay.body
  rows.append({'case':name,'expected':expected,'actual':actual,'server_accepted':relay.accepted,'body_bytes':len(relay.body),'commands':relay.commands});print('PASS local SMTP '+name+': '+actual['state'],flush=True)
 (output/'report.json').write_text(json.dumps({'runtime':runtime,'cases':rows,'passed':True,'only_owned_loopback_or_private_unix':True},indent=2));print('PASS local SMTP cases: '+str(len(rows)),flush=True)
