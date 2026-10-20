#!/usr/bin/env python3
"""Native authenticated issuance and public signed reads/explicit redemption against private SQLite/FileStore."""
import argparse,base64,contextlib,http.cookiejar,json,os,socket,sqlite3,subprocess,tempfile,time
import urllib.error,urllib.parse,urllib.request
from pathlib import Path
root=Path(__file__).resolve().parent.parent;checks=0;PASSWORD='Correct-link-test-password';SCOPE='link-example';BODY='PRIVATE-LINK-DOCUMENT-BODY'
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
class Visitor:
    def __init__(self,url):
        self.url=url;self.csrf='';self.jar=http.cookiejar.CookieJar();self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
    def call(self,action=None,fields=None,url=None,method=None,csrf=None,headers=None):
        body=None
        if action is not None or method=='POST':
            values=dict(fields or {},_csrf=self.csrf if csrf is None else csrf)
            if action is not None:values['action']=action
            body=urllib.parse.urlencode(values).encode()
        try:response=self.client.open(urllib.request.Request(url or self.url,data=body,method=method,headers=dict({'Accept':'application/json'},**(headers or {}))),timeout=15)
        except urllib.error.HTTPError as error:response=error
        with response:
            check('no-store, private',response.headers['Cache-Control']);check('no-referrer',response.headers['Referrer-Policy'])
            raw=response.read().decode();data=json.loads(raw) if raw else {};self.csrf=data.get('csrf',self.csrf)
            for secret in [PASSWORD,'$2y$','soss_']:check(False,secret in raw)
            if response.status!=200:check(False,BODY in raw)
            return response.status,data,response.headers
    def login(self):return self.call('login',{'username':'demo','password':PASSWORD})
    def issue(self,delivery='read',document='a'):
        status,data,_=self.call('issue',{'document_id':document,'delivery':delivery});check(200,status);check(False,BODY in json.dumps(data));return data['issued_url'],data['issued']['id']
    def sid(self):return next((cookie.value for cookie in self.jar if cookie.name=='SoSecurityLinkExample'),None)
@contextlib.contextmanager
def fixture(runtime,ttl=None,secure_origin=False):
    def hashed(password):return subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',password],text=True)
    with tempfile.TemporaryDirectory(prefix='sosecurity-link-http-') as directory:
        work=Path(directory);storage=work/'state';storage.mkdir(mode=0o700);sessions=work/'sessions';sessions.mkdir(mode=0o700)
        database=work/'links.sqlite';db=sqlite3.connect(database);database.chmod(0o600)
        db.execute('CREATE TABLE link_accounts(tenant TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,password_hash TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,roles TEXT NOT NULL,PRIMARY KEY(tenant,subject),UNIQUE(tenant,username))')
        db.executemany('INSERT INTO link_accounts VALUES(?,?,?,?,?,?,?)',[(SCOPE,'alice','demo',hashed(PASSWORD),'1',1,'["editor"]'),(SCOPE,'bob','other',hashed('Other-link-test-password'),'1',1,'["editor"]')])
        db.execute('CREATE TABLE link_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,id))')
        db.executemany('INSERT INTO link_documents VALUES(?,?,?,?,?,?)',[(SCOPE,'a','alice',1,'Link document <script>alert(1)</script>',BODY),(SCOPE,'b','bob',1,'Other owner','OTHER-OWNER-PRIVATE'),('other','a','alice',1,'Other tenant','OTHER-TENANT-PRIVATE')]);db.commit()
        keyfile=work/'keys.json';keydata={'current':'old','keys':{'old':base64.b64encode(os.urandom(32)).decode()}}
        def save_keys():keyfile.write_text(json.dumps(keydata));keyfile.chmod(0o600)
        save_keys()
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        transport_origin=f'http://127.0.0.1:{port}';origin=('https' if secure_origin else 'http')+f'://127.0.0.1:{port}';env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_LINK_EXAMPLE_')};env.update(SOSECURITY_LINK_EXAMPLE_DATABASE=str(database),SOSECURITY_LINK_EXAMPLE_KEYS=str(keyfile),SOSECURITY_LINK_EXAMPLE_ORIGIN=origin,SOSECURITY_LINK_EXAMPLE_STORAGE=str(storage),SOSECURITY_LINK_EXAMPLE_DUMMY_HASH=hashed('Dummy-link-test-password'),SOSECURITY_LINK_EXAMPLE_HTTPS='1' if secure_origin else '0')
        if ttl is not None:env['SOSECURITY_LINK_EXAMPLE_TTL']=str(ttl)
        with (work/'server.log').open('w+') as log:
            server=subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'examples')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:log.seek(0);raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('Signed-link native server startup timed out')
                yield {'db':db,'work':work,'url':transport_origin+'/signed-links.php','origin':origin,'env':env,'keys':keydata,'save_keys':save_keys,'keyfile':keyfile,'database':database,'storage':storage}
                log.flush();log.seek(0);messages=log.read()
                for bad in ['PHP Warning:','PHP Deprecated:','PHP Fatal error:']:check(False,bad in messages)
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
                db.close()
def run(runtime,browser=False):
    if subprocess.call([runtime,'-r','exit(extension_loaded("pdo_sqlite")?0:1);'])!=0:
        print('NOT RUN signed-link HTTP: optional PDO SQLite required');return 1 if os.getenv('SOSECURITY_REQUIRE_RESET')=='1' else 0
    with fixture(runtime) as f:
        db=f['db'];v=Visitor(f['url']);reader=Visitor(f['url'])
        original=db.execute('SELECT * FROM link_documents ORDER BY tenant,id').fetchall()
        if browser:
            env=f['env'].copy();env['SOSECURITY_TEST_LINK_PASSWORD']=PASSWORD
            subprocess.run(['node',str(root/'tests/link-browser.cjs'),f['url']],env=env,check=True);check(original,db.execute('SELECT * FROM link_documents ORDER BY tenant,id').fetchall())
        else:
            status,data,headers=v.call();check(200,status);check('anonymous',data['stage']);check(True,'HttpOnly' in ';'.join(headers.get_all('Set-Cookie',[])))
            check(403,v.call('issue',{'document_id':'a','delivery':'read'})[0]);check(403,v.call('login',{'username':'demo','password':PASSWORD},csrf='wrong')[0]);old=v.sid();old_csrf=v.csrf
            check(200,v.login()[0]);check(False,old==v.sid());check(403,v.call('issue',{'document_id':'a','delivery':'read'},csrf=old_csrf)[0])
            check(403,v.call('issue',{'document_id':'b','delivery':'read'})[0]);check(403,v.call('issue',{'document_id':'missing','delivery':'read'})[0]);check(400,v.call('issue',{'document_id':'a','delivery':'read','tenant':'other'})[0])
            url,identifier=v.issue();check(True,url.startswith(f['url']+'?delivery=read&document_id=a&_ss=sl1.'))
            status,data,headers=reader.call(url=url);check(200,status);check(BODY,data['content']['body']);check(False,any(reader.jar));check(None,headers.get('Set-Cookie'));check(False,data['link']['one_time'])
            check(200,reader.call(url=url,headers={'If-None-Match':'*','If-Modified-Since':'Wed, 01 Jan 2030 00:00:00 GMT'})[0]);check(405,reader.call(url=url,method='HEAD')[0]);check(405,reader.call(url=url,method='POST')[0]);check(200,reader.call(url=url)[0])
            for bad in [url+'&extra=1',url+'&document_id=b',url+'&_ss=duplicate',url.replace('document_id=a','document_id=b'),url.replace('delivery=read','delivery=once'),url.replace('delivery=read&document_id=a','document_id=a&delivery=read'),url.replace('_ss=','%5Fss=')]:
                check(403,reader.call(url=bad)[0])
            check(200,reader.call(url=url)[0]);status,listed,_=v.call('list',{'document_id':'a'});check(200,status);check(1,len(listed['links']));check(False,'sl1.' in json.dumps(listed));check(False,BODY in json.dumps(listed))
            check(503,reader.call(url=url,headers={'Host':'evil.example'})[0])
            f['keys']['current']='new';f['keys']['keys']['new']=base64.b64encode(os.urandom(32)).decode();f['save_keys']();check(200,reader.call(url=url)[0]);new,_=v.issue()
            del f['keys']['keys']['old'];f['save_keys']();check(403,reader.call(url=url)[0]);check(200,reader.call(url=new)[0]);url=new
            offline=f['work']/'offline-keys.json';f['keyfile'].rename(offline);check({'error':'link.unavailable'},reader.call(url=url)[1]);offline.rename(f['keyfile']);check(200,reader.call(url=url)[0])
            f['keyfile'].chmod(0o644);check(503,reader.call(url=url)[0]);f['keyfile'].chmod(0o600)
            f['keyfile'].write_text('x'*16385);check(503,reader.call(url=url)[0]);f['save_keys']()
            saved=json.loads(f['keyfile'].read_text());saved['keys']['new']+='\n';f['keyfile'].write_text(json.dumps(saved));check(503,reader.call(url=url)[0]);f['save_keys']()
            new,identifier=v.issue();check(True,v.call('revoke',{'document_id':'a','link_id':identifier})[1]['revoked']);check(403,reader.call(url=new)[0])
            single,_=v.issue('once');check(405,reader.call(url=single,method='HEAD')[0]);check(200,reader.call(url=single)[0]);check(403,reader.call(url=single)[0])
            redeem,_=v.issue('redeem');check(True,reader.call(url=redeem)[1]['redemption']);check(True,reader.call(url=redeem)[1]['redemption'])
            stranger=Visitor(f['url']);check(403,stranger.call(url=redeem,method='POST',csrf=reader.csrf)[0]);check(403,reader.call(url=redeem,method='POST',csrf='wrong')[0])
            check(200,reader.call(url=redeem,method='POST')[0]);check(403,reader.call(url=redeem,method='POST')[0])
            revoked,_=v.issue('once');check(True,v.call('revoke_all',{'document_id':'a'})[1]['revoked_all']);check(403,reader.call(url=revoked)[0]);check(403,reader.call(url=url)[0])
            url,_=v.issue();db.execute('UPDATE link_documents SET version=version+1 WHERE tenant=? AND id=?',(SCOPE,'a'));db.commit();check(403,reader.call(url=url)[0]);check(original[2],db.execute("SELECT * FROM link_documents WHERE tenant='other'").fetchone())
            url,_=v.issue();db.execute('UPDATE link_documents SET owner=?,version=version+1 WHERE tenant=? AND id=?',('bob',SCOPE,'a'));db.commit();check(403,reader.call(url=url)[0]);db.execute('UPDATE link_documents SET owner=?,version=version+1 WHERE tenant=? AND id=?',('alice',SCOPE,'a'));db.commit()
            url,_=v.issue();replacement=subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',PASSWORD],text=True)
            db.execute('UPDATE link_accounts SET password_hash=? WHERE tenant=? AND subject=?',(replacement,SCOPE,'alice'));db.commit();check(403,reader.call(url=url)[0]);check('anonymous',v.call()[1]['stage']);check(200,v.login()[0])
            url,_=v.issue();db.execute('UPDATE link_accounts SET roles=?,version=? WHERE tenant=? AND subject=?',('["reader"]','2',SCOPE,'alice'));db.commit();check(403,reader.call(url=url)[0]);check('anonymous',v.call()[1]['stage']);check(200,v.login()[0]);check(403,v.call('issue',{'document_id':'a','delivery':'read'})[0])
            db.execute('UPDATE link_accounts SET roles=?,version=? WHERE tenant=? AND subject=?',('["editor"]','3',SCOPE,'alice'));db.commit();v.call();v.login();url,_=v.issue()
            moved=f['work']/'offline.sqlite';f['database'].rename(moved);check(503,reader.call(url=url)[0]);moved.rename(f['database']);check(200,reader.call(url=url)[0])
            moved=f['work']/'offline-state';f['storage'].rename(moved);check(503,reader.call(url=url)[0]);moved.rename(f['storage']);check(200,reader.call(url=url)[0])
            db.execute('UPDATE link_accounts SET enabled=0,version=? WHERE tenant=? AND subject=?',('4',SCOPE,'alice'));db.commit();check(403,reader.call(url=url)[0]);check('anonymous',v.call()[1]['stage'])
    if not browser:
        with fixture(runtime,2) as f:
            v=Visitor(f['url']);v.call();v.login();url,_=v.issue();check(200,v.call(url=url)[0]);time.sleep(2.1);check(403,v.call(url=url)[0])
        with fixture(runtime,secure_origin=True) as f:
            check(503,Visitor(f['url']).call()[0]) # Default HTTPS policy refuses an actual HTTP request, even with the matching Host.
    print(f'PASS signed-link {"browser host" if browser else "HTTP"}: {checks} assertions on {runtime}; real issuer login/CSRF, public bearer reads, explicit one-use POST, raw URL/method/version/key/identity boundaries, expiry and outages')
    return 0
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--browser',action='store_true');args=parser.parse_args();raise SystemExit(run(args.runtime,args.browser))
