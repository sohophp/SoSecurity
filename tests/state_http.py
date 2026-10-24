#!/usr/bin/env python3
"""Bounded native protected host over loopback HTTP/TLS, real cookies and full backup replay."""
import sys,argparse,base64,copy,hashlib,hmac,http.client,http.cookiejar,http.server,json,os,shutil,socket,sqlite3,ssl,struct,subprocess,tempfile,threading,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
checks=0
def check(expected,actual):
 global checks
 checks+=1
 assert expected==actual,(expected,actual)
def otp(secret):
 key=base64.b32decode(secret+'='*((-len(secret))%8));mac=hmac.new(key,struct.pack('!Q',int(time.time())//30),hashlib.sha1).digest();offset=mac[-1]&15
 return str((struct.unpack('!I',mac[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
class Visitor:
 def __init__(self,url,ca=None):
  self.url=url;self.csrf='';self.jar=http.cookiejar.CookieJar();handlers=[urllib.request.HTTPCookieProcessor(self.jar)]
  if ca:handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
  self.client=urllib.request.build_opener(*handlers)
 def call(self,action=None,fields=None,csrf=None,url=None,headers=None,body=None,method=None):
  if action is not None:body=urllib.parse.urlencode(dict(fields or {},action=action,_csrf=self.csrf if csrf is None else csrf)).encode()
  request=urllib.request.Request(url or self.url,data=body,method=method,headers=dict({'Accept':'application/json'},**(headers or {})))
  try:response=self.client.open(request,timeout=30)
  except urllib.error.HTTPError as error:response=error
  with response:
   check('no-store',response.headers.get('Cache-Control'));check('nosniff',response.headers.get('X-Content-Type-Options'));check('no-referrer',response.headers.get('Referrer-Policy'));check(True,"frame-ancestors 'none'" in response.headers.get('Content-Security-Policy',''))
   raw=response.read(65537);check(True,len(raw)<=65536);result=json.loads(raw);self.csrf=result.get('csrf',self.csrf);check(False,'soss_' in raw.decode());return response.status,result,response.headers
 def sid(self):return next((c.value for c in self.jar if c.name=='SoSecurityManagedExample'),None)
def run(runtime,tls=False,browser=False,backend='sqlite',business=False):
 global checks
 with tempfile.TemporaryDirectory(prefix='sosecurity-state-http-') as name:
  work=Path(name);print('OWNED_HTTP_INSTANCE '+str(work),flush=True);env=dict(os.environ,TMPDIR=str(work));fixture=json.loads(subprocess.check_output([runtime,str(ROOT/'tests/state-boundary/http-setup.php'),backend]+(['business'] if business else []),env=env,text=True));directory=Path(fixture['directory']);assert directory.parent==work and directory.name.startswith('sosecurity-test-') and not directory.is_symlink()
  sessions=work/'sessions';sessions.mkdir(mode=0o700);budget=work/'budget';budget.mkdir(mode=0o700);bootstrap=work/'host-bootstrap.php';shutil.copyfile(ROOT/'tests/state-boundary/http-bootstrap.php',bootstrap);bootstrap.chmod(0o600)
  def control(action='inspect',extra=None):return json.loads(subprocess.check_output([runtime,str(ROOT/'tests/state-boundary/http-control.php'),str(directory),action]+([str(extra)] if extra else []),env=env,text=True))
  def snapshot():
   if backend=='mysql':rows=control('snapshot')
   else:
    with sqlite3.connect(directory/'managed.sqlite') as db:rows=list(db.iterdump())
   files={p.name:p.read_bytes() for p in (directory/'factors').iterdir() if p.name.endswith('.json')}
   witness={p.name:p.read_bytes() for p in (directory/'independent-witness').glob('*.witness')}
   return rows,files,witness
  with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
  origin=f'http://127.0.0.1:{port}';ca=None;proxy=None;server=None;attack=None;nonce=os.urandom(32).hex()
  if tls:
   ca=work/'cert.pem';key=work/'key.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(ca),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],capture_output=True,check=True);key.chmod(0o600)
   class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def forward(self):
     if any(len(self.headers.get_all(k,[]))>1 for k in ['Host','Authorization','Cookie','Origin','Content-Length']):self.send_error(400);return
     size=int(self.headers.get('Content-Length','0'))
     if size<0 or size>16384:self.send_error(413);return
     headers={k:v for k,v in self.headers.items() if k.lower() not in ['connection','transfer-encoding','content-length','x-test-state-tls']};headers['X-Test-State-Tls']=nonce;connection=http.client.HTTPConnection('127.0.0.1',port,timeout=30)
     try:
      connection.request(self.command,self.path,self.rfile.read(size),headers);response=connection.getresponse();raw=response.read(65537)
      if len(raw)>65536:raise RuntimeError('Response budget exceeded')
      self.send_response(response.status)
      for k,v in response.getheaders():
       if k.lower() not in ['connection','transfer-encoding','content-length','server','date']:self.send_header(k,v)
      self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
     finally:connection.close()
    do_GET=forward;do_POST=forward;do_PUT=forward;do_OPTIONS=forward
   proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(ca),str(key));proxy.socket=context.wrap_socket(proxy.socket,server_side=True);threading.Thread(target=proxy.serve_forever,daemon=True).start();origin=f'https://localhost:{proxy.server_port}'
  class Attack(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    raw=b'<!doctype html><title>Owned origin probe</title>';self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
  attack=http.server.ThreadingHTTPServer(('127.0.0.1',0),Attack)
  if tls:attack.socket=context.wrap_socket(attack.socket,server_side=True)
  threading.Thread(target=attack.serve_forever,daemon=True).start();attack_origin=('https://localhost' if tls else 'http://127.0.0.1')+':'+str(attack.server_port)
  env.update(SOSECURITY_STATE_HTTP_ROOT=str(ROOT),SOSECURITY_STATE_HTTP_FIXTURE=str(directory),SOSECURITY_MANAGED_AUTH_EXAMPLE_BOOTSTRAP=str(bootstrap),SOSECURITY_MANAGED_AUTH_EXAMPLE_STATE=str(budget),SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP='0' if tls else '1',SOSECURITY_MANAGED_AUTH_EXAMPLE_ORIGIN=origin,SOSECURITY_TEST_STATE_TLS=nonce)
  audit=work/'response-audit.jsonl';audit.touch(mode=0o600);env['SOSECURITY_STATE_HTTP_AUDIT']=str(audit)
  router=work/'router.php';router.write_text('<?php register_shutdown_function(static function(){file_put_contents(getenv("SOSECURITY_STATE_HTTP_AUDIT"),json_encode(["method"=>$_SERVER["REQUEST_METHOD"]??"","origin"=>$_SERVER["HTTP_ORIGIN"]??"","cookie"=>isset($_COOKIE["SoSecurityManagedExample"]),"status"=>http_response_code(),"failure"=>(static function():array{global $error;$out=[];$e=$error??null;for($i=0;$i<4&&$e instanceof Throwable;$i++,$e=$e->getPrevious()){$out[]=["type"=>get_class($e),"reason"=>method_exists($e,"reason")?$e->reason():null];}return $out;})()]).PHP_EOL,FILE_APPEND);});if(($_SERVER["REMOTE_ADDR"]??"")==="127.0.0.1"&&hash_equals(getenv("SOSECURITY_TEST_STATE_TLS"),$_SERVER["HTTP_X_TEST_STATE_TLS"]??"")){$_SERVER["HTTPS"]="on";}if(($_SERVER["REQUEST_URI"]??"")=="/__test/cli-setup"){require '+json.dumps(str(ROOT/'tests/state-boundary/http-setup.php'))+';return;}if(($_SERVER["REQUEST_URI"]??"")=="/__test/cli-control"){require '+json.dumps(str(ROOT/'tests/state-boundary/http-control.php'))+';return;}require '+json.dumps(str(ROOT/'examples/managed-authentication.php'))+';');router.chmod(0o600)
  try:
   with (work/'server.log').open('w+') as log:
    server=subprocess.Popen([runtime,'-d','memory_limit=16M','-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(ROOT/'examples'),str(router)],env=env,stdout=log,stderr=log)
    try:
     for _ in range(100):
      if server.poll() is not None:log.seek(0);raise RuntimeError(log.read())
      try:
       with socket.create_connection(('127.0.0.1',port),timeout=.1):break
      except OSError:time.sleep(.05)
     else:raise RuntimeError('Server startup timed out')
     url=origin+'/managed-authentication.php';v=Visitor(url,ca);status,initial,headers=v.call();check(200,status);check('anonymous',initial['stage']);before_sid=v.sid();check(True,before_sid is not None);cookie=';'.join(headers.get_all('Set-Cookie',[]));check(True,'HttpOnly' in cookie and 'SameSite=Lax' in cookie);check(tls,'Secure' in cookie)
     def no_effect(attempt,status):
      before=snapshot();actual=attempt()[0];after=snapshot()
      if actual!=status:
       state=control();print('UNEXPECTED_STATUS '+json.dumps({'expected':status,'actual':actual,'source_and_authority_unchanged':before==after,'authority':{k:state[k] for k in ['format','status','revision','matches','trusted','observed']}}),flush=True)
      check(status,actual);check(True,before==after)
     for private_path in ['/__test/cli-setup','/__test/cli-control']:
      before=snapshot();known=set(work.iterdir())
      try:guarded=v.client.open(origin+private_path,timeout=30)
      except urllib.error.HTTPError as error:guarded=error
      with guarded:check(404,guarded.status);check(b'',guarded.read())
      check(True,before==snapshot());check(True,known==set(work.iterdir()))

     no_effect(lambda:v.call('login',{'username':'owned@example.test','password':fixture['password']},csrf='invalid'),403)
     no_effect(lambda:v.call('login',{'username':'owned@example.test','password':fixture['password']},headers={'Origin':'https://attacker.invalid'}),403)
     no_effect(lambda:v.call(method='PUT'),405)
     no_effect(lambda:v.call(body=b'action=login&action=logout&_csrf='+v.csrf.encode(),headers={'Content-Type':'application/x-www-form-urlencoded'}),400)
     no_effect(lambda:v.call(url=url+'?api=identity&api=identity'),400)
     check(401,v.call('login',{'username':'owned@example.test','password':'wrong'})[0]);check(True,control()['matches']);check('current',control()['status'])
     status,waiting,_=v.call('login',{'username':'owned@example.test','password':fixture['password']},headers={'Origin':origin});check(200,status);check('mfa_required',waiting['stage']);check(before_sid,v.sid())
     check(401,v.call('mfa',{'type':'totp','proof':'bad'})[0]);check(True,control()['matches']);check('current',control()['status'])
     status,logged,_=v.call('mfa',{'type':'totp','proof':otp(fixture['secret'])},headers={'Origin':origin});check(200,status);check('authenticated',logged['stage']);check(2,logged['session']['strength']);check(False,before_sid==v.sid());check(True,control()['matches'])
     no_effect(lambda:v.call('api_issue',{'name':'Denied','scopes':'records:read'},csrf='bad'),403)
     no_effect(lambda:v.call('api_issue',{'name':'Denied','scopes':'records:read'},headers={'Origin':'https://attacker.invalid'}),403)
     no_effect(lambda:v.call('api_issue',{'name':'Denied','scopes':'records:read'},headers={'Origin':'null'}),403)
     no_effect(lambda:v.call('api_issue',{'name':'Denied','scopes':'outside:scope'}),403)
     no_effect(lambda:v.call('api_issue',{'name':'Denied','scopes':'records:read'},headers={'Accept':'text/html'}),406)
     no_effect(lambda:v.call('api_issue',{'name':'Denied','scopes':'records:read','owner':'other'}),400)
     status,issued,_=v.call('api_issue',{'name':'HTTP native <script>','scopes':'records:read,records:write'});check(200,status);token=issued['issued_token'];metadata=issued['issued'];check('HTTP native <script>',metadata['name'])
     stranger=Visitor(url,ca);before_sessions={p.name:p.read_bytes() for p in sessions.iterdir()};no_effect(lambda:stranger.call(url=url+'?api=identity'),401);check(before_sessions,{p.name:p.read_bytes() for p in sessions.iterdir()});no_effect(lambda:v.call(url=url+'?api=identity'),401)
     status,identity,headers=stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+token});check(200,status);check('user',identity['identity']['subject']);check(None,headers.get('Set-Cookie'));check(False,'csrf' in identity)
     no_effect(lambda:v.call(url=url+'?api=identity',headers={'Authorization':'Bearer wrong'}),401)
     if business:
      business_url=url+'?api=document';before_sessions={p.name:p.read_bytes() for p in sessions.iterdir()}
      def rename(client=stranger,bearer=token,version='1',doc='owned',title='HTTP 更新',extra=None,headers=None):
       fields=dict(action='rename',id=doc,version=version,title=title);fields.update(extra or {});h={'Content-Type':'application/x-www-form-urlencoded'}
       if bearer is not None:h['Authorization']='Bearer '+bearer
       h.update(headers or {});return client.call(url=business_url,body=urllib.parse.urlencode(fields).encode(),headers=h)
      no_effect(lambda:stranger.call(url=business_url),405)
      no_effect(lambda:rename(client=v,bearer=None),401)
      no_effect(lambda:rename(bearer='wrong'),401)
      no_effect(lambda:rename(headers={'Origin':'https://attacker.invalid'}),403)
      no_effect(lambda:rename(headers={'Origin':'null'}),403)
      no_effect(lambda:rename(extra={'_csrf':v.csrf}),400)
      no_effect(lambda:rename(extra={'owner':'user'}),400)
      no_effect(lambda:rename(version='01'),400)
      no_effect(lambda:rename(version='2'),403)
      no_effect(lambda:rename(doc='foreign'),403)
      no_effect(lambda:rename(headers={'Accept':'text/html'}),406)
      status,document,headers=rename(headers={'Origin':origin});check(200,status);check({'id':'owned','version':2},document['document']);check(None,headers.get('Set-Cookie'));check(False,'csrf' in document)
      current=control();check(3,current['format']);check(True,current['matches']);check('api.credentials.execute',current['intent']['action']);check('authorized',current['intent']['kind']);owned=next(r for r in current['documents'] if r['id']=='owned');check('HTTP 更新',owned['title']);check('2',str(owned['version']));check(before_sessions,{p.name:p.read_bytes() for p in sessions.iterdir()})
      no_effect(lambda:rename(version='1'),403)
      status,narrow,_=v.call('api_issue',{'name':'Business read only','scopes':'records:read'});check(200,status);no_effect(lambda:rename(bearer=narrow['issued_token'],version='2'),401);check(True,v.call('api_revoke',{'id':narrow['issued']['id']})[1]['revoked'])
      print('BUSINESS_HTTP format=3; actual factory/PDO/Intent update, no Cookie authority, exact fields/origin, version/owner/scope denials before pending',flush=True)
     status,listed,_=v.call('api_all');check(200,status);check(1,len(listed['credentials']));check(False,token in json.dumps(listed))
     status,rotated,_=v.call('api_rotate',{'id':metadata['id'],'generation':'1'});check(200,status);next_token=rotated['issued_token'];check(2,rotated['issued']['generation']);no_effect(lambda:stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+token}),401);check(200,stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+next_token})[0])
     status,replaced,_=v.call('api_replace',{'id':metadata['id'],'generation':'2','name':'Narrow','scopes':'records:write','ttl':'300'});check(200,status);no_effect(lambda:stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+replaced['issued_token']}),401);check(True,v.call('api_revoke',{'id':metadata['id']})[1]['revoked'])
     check(200,v.call('api_issue',{'name':'Last','scopes':'records:read'})[0]);check(1,v.call('api_revoke_all')[1]['revoked'])
     short=v.call('api_issue',{'name':'Real expiry','scopes':'records:read','ttl':'8'})[1];delay=directory/'delay-api-scopes';delay.touch(mode=0o600)
     try:no_effect(lambda:stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+short['issued_token']}),401)
     finally:delay.unlink()
     observed=json.loads((directory/'scope-delay-observation.json').read_text());check('SoSecurity\\Support\\SystemClock',observed['clock']);check(True,observed['start']<short['issued']['expires_at']<=observed['end']);print('EXPIRY_OBSERVATION '+json.dumps(dict(observed,expires=short['issued']['expires_at'],outcome='401; source and authority unchanged')),flush=True);check('current',control()['status']);check(200,v.call('api_revoke_all')[0])
     if tls:
      plain=Visitor(f'http://127.0.0.1:{port}/managed-authentication.php');no_effect(lambda:plain.call(headers={'Host':urllib.parse.urlsplit(origin).netloc,'X-Forwarded-Proto':'https'}),503)
     if browser:
      browser_env=dict(env,SOSECURITY_STATE_HTTP_ATTACK_ORIGIN=attack_origin,SOSECURITY_STATE_HTTP_RUNTIME=runtime,SOSECURITY_STATE_HTTP_URL=url,SOSECURITY_STATE_HTTP_PASSWORD=fixture['password'],SOSECURITY_STATE_HTTP_RECOVERY=fixture['recovery'],SOSECURITY_STATE_HTTP_BUSINESS='1' if business else '0',SOSECURITY_PLAYWRIGHT_MODULE=os.environ.get('SOSECURITY_PLAYWRIGHT_MODULE','playwright'))
      subprocess.run(['node',str(ROOT/'tests/state-http-browser.cjs')],cwd=ROOT,env=browser_env,check=True,timeout=90)
     status,old,_=v.call('api_issue',{'name':'Backup owned','scopes':'records:read,records:write' if business else 'records:read'});check(200,status);old_token=old['issued_token'];check(200,stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+old_token})[0]);backup_files={p.name:p.read_bytes() for p in (directory/'factors').glob('*.json')};backup_sessions={p.name:p.read_bytes() for p in sessions.iterdir()};backup_cookies=[copy.copy(c) for c in v.jar];backup_csrf=v.csrf;backup=work/'backup.sqlite'
     if backend=='mysql':backup=work/'backup.json';backup.write_text(json.dumps(control('snapshot')));backup.chmod(0o600)
     else:
      with sqlite3.connect(directory/'managed.sqlite') as source,sqlite3.connect(backup) as target:source.backup(target)
     if business:
      status,changed,_=rename(bearer=old_token,version='2',title='Newest trusted business');check(200,status);check(3,changed['document']['version'])
     check(1,v.call('api_revoke_all')[1]['revoked']);check('anonymous',v.call('logout')[1]['stage']);check(True,control('change-role')['matches']);latest=control();check('current',latest['status'])
     if backend=='mysql':check(True,control('restore',backup)['restored'])
     else:
      with sqlite3.connect(backup) as source,sqlite3.connect(directory/'managed.sqlite') as target:source.backup(target)
     for p in (directory/'factors').glob('*.json'):p.unlink()
     for filename,raw in backup_files.items():p=directory/'factors'/filename;p.write_bytes(raw);p.chmod(0o600)
     for p in sessions.iterdir():p.unlink()
     for filename,raw in backup_sessions.items():p=sessions/filename;p.write_bytes(raw);p.chmod(0o600)
     restored=control();check(False,restored['matches']);check(latest['trusted'],restored['trusted']);no_effect(lambda:stranger.call(url=url+'?api=identity',headers={'Authorization':'Bearer '+old_token}),503)
     if business:no_effect(lambda:rename(bearer=old_token,version='2',title='Must not replay'),503)
     v.jar.clear()
     for cookie in backup_cookies:v.jar.set_cookie(cookie)
     v.csrf=backup_csrf;no_effect(lambda:v.call('api_all'),503)
    except Exception:
     log.flush();log.seek(0);print('SERVER LOG (owned fixture):\n'+log.read()[-6000:],file=sys.stderr);print('SANITIZED RESPONSE AUDIT:\n'+audit.read_text()[-6000:],file=sys.stderr);raise
  finally:
   if server is not None:server.terminate();server.wait(timeout=10)
   if proxy is not None:proxy.shutdown();proxy.server_close()
   if attack is not None:attack.shutdown();attack.server_close()
 check(False,work.exists())
 print(f'PASS native protected state {"TLS" if tls else "HTTP"}: {checks} assertions on {runtime}; backend={backend}, continuous SystemClock and mid-request expiry, real password/TOTP, cookies/CSRF/origin, all API management, Bearer without cookies, unchanged-source refusals, full SQL/files/PHP-session replay denied; '+('Chromium executed; ' if browser else '')+'owned resources cleaned',flush=True)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--tls',action='store_true');parser.add_argument('--browser',action='store_true');parser.add_argument('--business',action='store_true');parser.add_argument('--backend',choices=['sqlite','mysql'],default='sqlite');args=parser.parse_args();run(args.runtime,args.tls,args.browser,args.backend,args.business)
