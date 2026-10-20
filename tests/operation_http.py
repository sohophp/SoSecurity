#!/usr/bin/env python3
"""Real native password/TOTP -> explicit review -> one-use SQL write, without test proof injection."""
import argparse,base64,contextlib,hashlib,hmac,http.cookiejar,json,os,socket,sqlite3,struct,subprocess,tempfile,time
import urllib.error,urllib.parse,urllib.request
from pathlib import Path

root=Path(__file__).resolve().parent.parent
checks=0
PASSWORD='Correct-operation-test-password'
SCOPE='operation-example'

def check(expected,actual):
    global checks
    checks+=1
    assert expected==actual,(expected,actual)

def otp(uri,offset=0):
    seed=urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)['secret'][0]
    key=base64.b32decode(seed+'='*((-len(seed))%8))
    mac=hmac.new(key,struct.pack('!Q',int(time.time())//30+offset),hashlib.sha1).digest();start=mac[-1]&15
    return str((struct.unpack('!I',mac[start:start+4])[0]&0x7fffffff)%1000000).zfill(6)

class Visitor:
    def __init__(self,url):
        self.jar=http.cookiejar.CookieJar();self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.url=url;self.csrf=''
    def call(self,action=None,fields=None,csrf=None,method=None):
        body=None if action is None else urllib.parse.urlencode(dict(fields or {},action=action,_csrf=self.csrf if csrf is None else csrf)).encode()
        try:response=self.client.open(urllib.request.Request(self.url,data=body,method=method,headers={'Accept':'application/json'}),timeout=15)
        except urllib.error.HTTPError as error:response=error
        with response:
            check('no-store',response.headers['Cache-Control']);check('no-referrer',response.headers['Referrer-Policy'])
            raw=response.read().decode();data=json.loads(raw);self.csrf=data.get('csrf',self.csrf)
            for secret in ['oc1.','og1.','soss_',PASSWORD,'$2y$']:
                check(False,secret in raw)
            return response.status,data,response.headers
    def sid(self):return next((cookie.value for cookie in self.jar if cookie.name=='SoSecurityOperationExample'),None)
    def login(self):return self.call('login',{'username':'demo','password':PASSWORD})
    def prepare(self,title='Reviewed title',document='a'):
        status,data,_=self.call('prepare',{'document_id':document,'title':title});check(200,status)
        return data['review']['id']
    def reauthenticate(self,review):return self.call('reauthenticate',{'username':'demo','password':PASSWORD,'review_id':review})
    def confirm(self,review):return self.call('confirm',{'review_id':review})
    def execute(self,review):return self.call('execute',{'review_id':review})

@contextlib.contextmanager
def fixture(runtime,profile='password'):
    def hashed(value):return subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',value],text=True)
    with tempfile.TemporaryDirectory(prefix='sosecurity-operation-http-') as directory:
        work=Path(directory);storage=work/'state';storage.mkdir(mode=0o700);sessions=work/'sessions';sessions.mkdir(mode=0o700)
        database=work/'operation.sqlite';db=sqlite3.connect(database);database.chmod(0o600)
        db.execute('CREATE TABLE operation_accounts(tenant TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,password_hash TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,roles TEXT NOT NULL,mfa_required INTEGER NOT NULL,PRIMARY KEY(tenant,subject),UNIQUE(tenant,username))')
        db.execute('INSERT INTO operation_accounts VALUES(?,?,?,?,?,?,?,?)',(SCOPE,'alice','demo',hashed(PASSWORD),'1',1,'["editor"]',1 if profile=='totp' else 0))
        db.execute('CREATE TABLE operation_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,PRIMARY KEY(tenant,id))')
        db.executemany('INSERT INTO operation_documents VALUES(?,?,?,?,?)',[(SCOPE,'a','alice',1,'Original'),(SCOPE,'b','bob',1,'Other owner'),('other','a','alice',1,'OTHER-TENANT-PRIVATE')])
        db.execute('CREATE TABLE operation_receipts(tenant TEXT NOT NULL,id TEXT NOT NULL,subject TEXT NOT NULL,intent_hash TEXT NOT NULL,resource_id TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(tenant,id))');db.commit()
        env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_OPERATION_EXAMPLE_')}
        env.update(SOSECURITY_OPERATION_EXAMPLE_DATABASE=str(database),SOSECURITY_OPERATION_EXAMPLE_STORAGE=str(storage),SOSECURITY_OPERATION_EXAMPLE_DUMMY_HASH=hashed('Dummy-operation-test-password'),SOSECURITY_OPERATION_EXAMPLE_HTTPS='0')
        factor=None
        if profile=='password':env['SOSECURITY_OPERATION_EXAMPLE_PASSWORD_PROFILE']='1'
        if profile=='totp':
            key=base64.b64encode(os.urandom(32)).decode();env['SOSECURITY_OPERATION_EXAMPLE_MFA_KEY']=key
            result=subprocess.run([runtime,str(root/'tests/operation-setup.php')],input=json.dumps({'directory':str(storage),'key':key}),text=True,capture_output=True,check=True)
            check('',result.stderr);factor=json.loads(result.stdout)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        with (work/'server.log').open('w+') as log:
            server=subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'examples')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:log.seek(0);raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('Operation example startup timed out')
                yield {'db':db,'database':database,'work':work,'factor':factor,'url':f'http://127.0.0.1:{port}/operation-authorization.php','env':env}
                log.flush();log.seek(0);messages=log.read()
                for warning in ['PHP Warning:','PHP Fatal error:','PHP Deprecated:']:check(False,warning in messages)
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
                db.close()

def run(runtime,browser=False):
    for extension in ['pdo_sqlite','sodium']:
        if subprocess.call([runtime,'-r',f'exit(extension_loaded("{extension}")?0:1);'])!=0:
            print('NOT RUN operation HTTP: optional '+extension+' required')
            return 1 if os.getenv('SOSECURITY_REQUIRE_RESET')=='1' or os.getenv('SOSECURITY_REQUIRE_CRYPTO')=='1' else 0
    for profile in ['password','totp','strong-without-factor']:
        with fixture(runtime,profile) as f:
            db=f['db'];v=Visitor(f['url'])
            def snapshot():return db.execute('SELECT * FROM operation_documents ORDER BY tenant,id').fetchall(),db.execute('SELECT * FROM operation_receipts ORDER BY tenant,id').fetchall()
            def title():return db.execute('SELECT title FROM operation_documents WHERE tenant=? AND id=?',(SCOPE,'a')).fetchone()[0]
            if browser:
                if profile=='strong-without-factor':continue
                env=f['env'].copy();env['SOSECURITY_TEST_OPERATION_PASSWORD']=PASSWORD
                if f['factor']:env['SOSECURITY_TEST_OPERATION_OTP_URI']=f['factor']['uri']
                subprocess.run(['node',str(root/'tests/operation-browser.cjs'),f['url'],profile],env=env,check=True)
                check('Browser reviewed <script>alert(1)</script>',title());check(1,len(snapshot()[1]));continue
            status,initial,headers=v.call();check(200,status);check('anonymous',initial['stage']);check(None,initial['review'])
            cookie=';'.join(headers.get_all('Set-Cookie',[]));check(True,'HttpOnly' in cookie);check(True,'SameSite=Lax' in cookie)
            before=snapshot();check(403,v.call('prepare',{'document_id':'a','title':'Forbidden'})[0]);check(before,snapshot())
            check(405,v.call(method='PUT')[0]);check(403,v.call('login',{'username':'demo','password':PASSWORD},csrf='wrong')[0]);check('anonymous',v.call()[1]['stage'])
            old_sid=v.sid();old_csrf=v.csrf;status,data,_=v.login();check(200,status)
            if profile=='totp':
                check('mfa_required',data['stage']);check(None,data['session']);check(403,v.call('prepare',{'document_id':'a','title':'Before MFA'})[0])
                status,data,_=v.call('mfa',{'type':'totp','proof':otp(f['factor']['uri'])});check(200,status)
            check('authenticated',data['stage']);check(False,old_sid==v.sid());check(403,v.call('prepare',{'document_id':'a','title':'Stale CSRF'},csrf=old_csrf)[0]);session_id=data['session']['id']
            check(403,v.call('prepare',{'document_id':'b','title':'Other owner'})[0]);check(403,v.call('prepare',{'document_id':'missing','title':'Missing'})[0]);check(before,snapshot())
            review=v.prepare();check(403,v.confirm(review)[0]);check(before,snapshot())
            review=v.prepare('Final approved title');old_sid=v.sid();status,data,_=v.reauthenticate(review);check(200,status)
            if profile=='totp':
                check('mfa_required',data['stage']);check(401,v.call('mfa',{'review_id':review,'type':'totp','proof':'wrong'})[0])
                check(200,v.call('mfa',{'review_id':review,'type':'totp','proof':otp(f['factor']['uri'],1)})[0]);data=v.call()[1]
            check(False,old_sid==v.sid());check(session_id,data['session']['id'])
            if profile=='strong-without-factor':
                check(403,v.confirm(review)[0]);check(before,snapshot());check(2,v.call()[1]['policy']['minimum_strength']);continue
            status,data,_=v.confirm(review);check(200,status);check('granted',data['review']['phase']);check(before,snapshot())
            check(400,v.call('execute',{'review_id':review,'title':'ATTACKER REPLACEMENT'})[0]);check(before,snapshot())
            check(True,v.execute(review)[1]['applied']);check('Final approved title',title());check(1,len(snapshot()[1]));committed=snapshot()
            check(403,v.execute(review)[0]);check(committed,snapshot());check('OTHER-TENANT-PRIVATE',db.execute("SELECT title FROM operation_documents WHERE tenant='other'").fetchone()[0])
            if profile=='totp':
                review=v.prepare('Recovery is not default operation proof');v.reauthenticate(review)
                check(200,v.call('mfa',{'review_id':review,'type':'recovery','proof':f['factor']['recovery'][0]})[0]);check('recovery',v.call()[1]['session']['method'])
                check(403,v.confirm(review)[0]);check(committed,snapshot());check(200,v.call('cancel',{'review_id':review})[0]);continue
            # One browser has two views. Old forms cannot confirm/execute/cancel a newer proposal.
            old=v.prepare('Old tab title');current=v.prepare('Current tab title')
            for action in ['reauthenticate','confirm','execute','cancel']:
                values={'review_id':old}
                if action=='reauthenticate':values.update(username='demo',password=PASSWORD)
                status,data,_=v.call(action,values);check(403,status);check('operation.review_changed',data['error']);check(current,data['review']['id']);check(committed,snapshot())
            other=Visitor(f['url']);other.call();other.login();check(403,other.execute(current)[0]);check(current,v.call()[1]['review']['id']);check(committed,snapshot())
            check(200,v.reauthenticate(current)[0]);check(200,v.confirm(current)[0]);check(True,v.execute(current)[1]['applied']);check('Current tab title',title());check(2,len(snapshot()[1]))
            # Resource changes after review burn/reject the authorization and preserve the concurrent writer.
            review=v.prepare('Do not overwrite newer resource');v.reauthenticate(review);v.confirm(review)
            db.execute('UPDATE operation_documents SET version=version+1,title=? WHERE tenant=? AND id=?',('Concurrent writer',SCOPE,'a'));db.commit();before=snapshot()
            check(403,v.execute(review)[0]);check(before,snapshot());check(None,v.call()[1]['review'])
            review=v.prepare('Do not overwrite another owner');v.reauthenticate(review);v.confirm(review)
            db.execute('UPDATE operation_documents SET owner=? WHERE tenant=? AND id=?',('bob',SCOPE,'a'));db.commit();before=snapshot()
            check(403,v.execute(review)[0]);check(before,snapshot());db.execute('UPDATE operation_documents SET owner=? WHERE tenant=? AND id=?',('alice',SCOPE,'a'));db.commit()
            # Authoritative role/version changes invalidate the session before SQL mutation.
            review=v.prepare('Revoked account');v.reauthenticate(review);v.confirm(review)
            db.execute('UPDATE operation_accounts SET version=?,roles=? WHERE tenant=?',('2','["reader"]',SCOPE));db.commit();before=snapshot()
            status,data,_=v.execute(review);check(403,status);check('anonymous',data['stage']);check(before,snapshot())
            db.execute('UPDATE operation_accounts SET version=?,roles=? WHERE tenant=?',('3','["editor"]',SCOPE));db.commit();check(200,v.login()[0])
            offline=f['work']/'offline.sqlite';f['database'].rename(offline)
            status,data,_=v.call();check(503,status);check({'error':'operation.unavailable'},data);check(False,str(f['work']) in json.dumps(data));offline.rename(f['database'])
            check('authenticated',v.call()[1]['stage']);review=v.prepare('Password changed without raw version bump');v.reauthenticate(review);v.confirm(review)
            replacement=subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',PASSWORD],text=True)
            db.execute('UPDATE operation_accounts SET password_hash=? WHERE tenant=?',(replacement,SCOPE));db.commit();before=snapshot()
            check(403,v.execute(review)[0]);check(before,snapshot());check('anonymous',v.call()[1]['stage']);check(200,v.login()[0])
            review=v.prepare('Disabled account');v.reauthenticate(review);v.confirm(review)
            db.execute('UPDATE operation_accounts SET version=?,enabled=0 WHERE tenant=?',('4',SCOPE));db.commit();before=snapshot()
            check(403,v.execute(review)[0]);check(before,snapshot());check('anonymous',v.call()[1]['stage'])
    print(f'PASS operation {"browser host" if browser else "HTTP"}: {checks} assertions on {runtime}; native password/TOTP, explicit review, stale tabs, scope/version/authority, SQL and one-use execution')
    return 0

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--browser',action='store_true');args=parser.parse_args()
    raise SystemExit(run(args.runtime,args.browser))
