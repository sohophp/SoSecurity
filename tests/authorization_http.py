#!/usr/bin/env python3
"""Native authenticated Cookie/CSRF -> real SQLite -> tenant/object/field/batch authorization."""
import argparse,http.cookiejar,json,os,socket,sqlite3,subprocess,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--browser',action='store_true');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;checks=0
if subprocess.call([args.runtime,'-r','exit(extension_loaded("pdo_sqlite")?0:1);'])!=0:
    print('NOT RUN native authorization example: optional PDO SQLite required');raise SystemExit(1 if os.getenv('SOSECURITY_REQUIRE_RESET')=='1' else 0)
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
def hashed(value):return subprocess.check_output([args.runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',value],text=True)
with tempfile.TemporaryDirectory(prefix='sosecurity-authorization-') as directory:
    work=Path(directory);storage=work/'state';storage.mkdir(mode=0o700);sessions=work/'sessions';sessions.mkdir(mode=0o700)
    account={'username':'demo','subject':'demo-account','hash':hashed('Correct-test-password'),'version':'1','roles':['editor']};config=work/'account.json'
    def save():config.write_text(json.dumps(account));config.chmod(0o600)
    save();database=work/'documents.sqlite';db=sqlite3.connect(database);database.chmod(0o600)
    db.execute('CREATE TABLE documents(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,confidential_note TEXT NOT NULL,PRIMARY KEY(tenant,id))')
    db.executemany('INSERT INTO documents VALUES(?,?,?,?,?,?,?)',[('example','a','demo-account',1,'First','Body','PRIVATE-NOTE'),('example','b','someone-else',1,'Other owner','Body','PRIVATE-NOTE'),('example','c','demo-account',1,'Third','Body','PRIVATE-NOTE'),('other','a','demo-account',1,'Other tenant','Other body','OTHER-TENANT-SECRET')]);db.commit()
    def snapshot():return db.execute('SELECT * FROM documents ORDER BY tenant,id').fetchall()
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_AUTH_EXAMPLE_')};env.update(SOSECURITY_AUTH_EXAMPLE_CONFIG=str(config),SOSECURITY_AUTH_EXAMPLE_STORAGE=str(storage),SOSECURITY_AUTH_EXAMPLE_DATABASE=str(database),SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH=hashed('Dummy-test-password'),SOSECURITY_AUTH_EXAMPLE_HTTPS='0')
    with open(work/'server.log','w+') as log:
        server=subprocess.Popen([args.runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'examples')],env=env,stdout=log,stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:log.seek(0);raise RuntimeError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('Authorization example startup timed out')
            url=f'http://127.0.0.1:{port}/authentication.php'
            if args.browser:
                subprocess.run(['node',str(root/'tests/authorization-browser.cjs'),url],env=env,check=True)
                check('Browser changed',db.execute("SELECT title FROM documents WHERE tenant='example' AND id='a'").fetchone()[0]);check('Other owner',db.execute("SELECT title FROM documents WHERE tenant='example' AND id='b'").fetchone()[0])
            else:
                jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));csrf=''
                def call(action=None,fields=None,token=None):
                    global csrf
                    body=None if action is None else urllib.parse.urlencode(dict(fields or {},action=action,_csrf=csrf if token is None else token)).encode()
                    try:response=client.open(urllib.request.Request(url,data=body,headers={'Accept':'application/json'}),timeout=10)
                    except urllib.error.HTTPError as error:response=error
                    with response:
                        check('no-store',response.headers['Cache-Control']);data=json.load(response);csrf=data.get('csrf',csrf);return response.status,data
                def operation(identifier,version=1,changes=None):return {'id':identifier,'version':version,'changes':changes or {'title':'Updated'}}
                def batch(values):return call('document_batch',{'operations':json.dumps(values)})
                call();before=snapshot();check(401,call('document_read',{'document_id':'a'})[0]);check(before,snapshot())
                check(200,call('login',{'username':'demo','password':'Correct-test-password'})[0]);check(403,call('document_read',{'document_id':'a'},token='wrong')[0])
                status,data=call('document_read',{'document_id':'a'});check(200,status);check(['id','version','title'],list(data['document']));check(False,'PRIVATE' in json.dumps(data));check(False,'Body' in json.dumps(data))
                check(403,call('document_read',{'document_id':'a','fields':'confidential_note'})[0]);check(403,call('document_private',{'document_id':'a'})[0])
                for values in [[operation('b')],[operation('a'),operation('b')],[operation('a'),operation('missing')],[operation('a',changes={'owner':'demo-account'})]]:
                    status,data=batch(values);check(403,status);check('authorization.denied',data['error']);check(before,snapshot())
                check(403,batch([operation('b',99)])[0]);check(400,batch([operation('a'),operation('a')])[0]);check(400,batch([operation('a',changes={'title':{'nested':'value'}})])[0]);check(before,snapshot())
                check(200,batch([operation('a')])[0]);check(2,db.execute("SELECT version FROM documents WHERE tenant='example' AND id='a'").fetchone()[0]);check(1,db.execute("SELECT version FROM documents WHERE tenant='other' AND id='a'").fetchone()[0])
                check('Updated',call('document_read',{'document_id':'a','tenant':'other'})[1]['document']['title']);before=snapshot()
                check(409,batch([operation('a',1)])[0]);check(before,snapshot())
                db.execute("CREATE TRIGGER competing_version AFTER UPDATE ON documents WHEN NEW.tenant='example' AND NEW.id='a' BEGIN UPDATE documents SET version=version+1 WHERE tenant='example' AND id='c'; END");db.commit()
                check(409,batch([operation('a',2),operation('c',1)])[0]);check(before,snapshot());db.execute('DROP TRIGGER competing_version');db.commit()
                config.rename(work/'offline.json');check(503,call('document_read',{'document_id':'a'})[0]);(work/'offline.json').rename(config);check(before,snapshot())
                account['roles']=['reader'];account['version']='2';save();check(401,batch([operation('a',2)])[0]);check(before,snapshot())
                call('login',{'username':'demo','password':'Correct-test-password'});check(200,call('document_read',{'document_id':'a'})[0]);check(403,batch([operation('a',2)])[0])
                account['roles']=['manager'];account['version']='3';save();call('login',{'username':'demo','password':'Correct-test-password'})
                check('PRIVATE-NOTE',call('document_private',{'document_id':'a','fields':'confidential_note'})[1]['document']['confidential_note']);check(403,batch([operation('a',2)])[0])
                account['enabled']=False;account['version']='4';save();check(401,call('document_read',{'document_id':'a'})[0]);check(before,snapshot())
                print(f'PASS native authorization HTTP: {checks} assertions on {args.runtime}; real login/CSRF, tenant/owner/fields, full-batch rollback, version/role revocation and source outage')
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait()
            db.close()
