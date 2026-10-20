#!/usr/bin/env python3
"""Real bearer HTTP/TLS -> current SQL authorization -> idempotent business and cached result."""
import argparse
import base64
import contextlib
import http.client
import http.server
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

root=Path(__file__).resolve().parent.parent
checks=0
def check(expected,actual):
    global checks
    checks+=1
    assert expected==actual,(expected,actual)

@contextlib.contextmanager
def fixture(runtime,tls=False,policy=None,installed=True,web_storage=False,controlled_clock=False):
    with tempfile.TemporaryDirectory(prefix='sosecurity-idempotency-http-') as directory:
        work=Path(directory);web=work/'web';web.mkdir(mode=0o700);storage=(web if web_storage else work)/'state';storage.mkdir(mode=0o700);sessions=work/'sessions';sessions.mkdir(mode=0o700)
        php_command=[runtime];tick=[int(time.time())]
        clock_file=work/'clock.txt'
        def advance_clock(seconds):
            if not controlled_clock or not isinstance(seconds,int) or seconds<0:raise RuntimeError('Test clock requires a forward integer step')
            tick[0]+=seconds;temporary=work/'clock.next';temporary.write_text(str(tick[0]));temporary.chmod(0o600);os.replace(temporary,clock_file)
        if controlled_clock:
            advance_clock(0);clock_helper=work/'clock.php';clock_value_path_b64=base64.b64encode(str(clock_file).encode()).decode()
            clock_helper.write_text('<?php namespace SoSecurity\\Support; function time():int {$v=file_get_contents(base64_decode("'+clock_value_path_b64+'"),false,null,0,33); if(!is_string($v)||!preg_match("/\\A[1-9][0-9]{0,17}\\z/D",$v)||(string)(int)$v!==$v){throw new \\RuntimeException("Controlled test clock unavailable");}return (int)$v;}')
            clock_helper.chmod(0o600);clock_helper_path_b64=base64.b64encode(str(clock_helper).encode()).decode();php_command+=['-d','auto_prepend_file='+str(clock_helper)]
        database=work/'orders.sqlite';db=sqlite3.connect(database);database.chmod(0o600)
        if installed:db.executescript((root/'resources/sql/idempotency-sqlite.sql').read_text())
        db.executescript((root/'resources/sql/idempotency-example-sqlite.sql').read_text())
        db.executemany('INSERT INTO idempotency_example_accounts VALUES(?,?,?,?,?)',[
            ('idempotency-example','alice','1',1,'["orders_writer"]'),('idempotency-example','bob','1',1,'["orders_writer"]'),
            ('idempotency-example','reader','1',1,'["reader"]'),('idempotency-example','disabled','1',0,'["orders_writer"]'),
            ('other','alice','1',1,'["orders_writer"]')]);db.commit()
        keys={'current':'old','keys':{'old':base64.b64encode(os.urandom(32)).decode()}};key_file=work/'seals.json'
        def save_keys():key_file.write_text(json.dumps(keys));key_file.chmod(0o600)
        save_keys();secret=os.urandom(32).hex()
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        class Ingress(http.server.BaseHTTPRequestHandler):
            def log_message(self,*unused):pass
            def request(self):
                raw=list(self.headers.raw_items());names=[name.lower() for name,value in raw];length=self.headers.get('Content-Length','0')
                if len(names)!=len(set(names)) or 'transfer-encoding' in names or not length.isascii() or not length.isdigit() or len(length)>5 or int(length)>16384 or any('\r' in value or '\n' in value for name,value in raw):
                    self.send_response(400);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{"error":"idempotency_example.input"}');return
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=20)
                try:
                    connection.putrequest(self.command,self.path,skip_host=True,skip_accept_encoding=True)
                    for name,value in raw:
                        if name.lower() not in ['connection','content-length','x-test-idempotency-ingress']:connection.putheader(name,value)
                    connection.putheader('X-Test-Idempotency-Ingress',secret);connection.putheader('Content-Length',length);connection.endheaders(self.rfile.read(int(length)))
                    response=connection.getresponse();data=response.read(65537)
                    if len(data)>65536:raise RuntimeError('Response exceeded ingress bound')
                    self.send_response(response.status)
                    for name,value in response.getheaders():
                        if name.lower() not in ['connection','content-length','transfer-encoding','server','date']:self.send_header(name,value)
                    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError):pass
                finally:connection.close()
            do_GET=request;do_POST=request;do_PUT=request;do_DELETE=request;do_OPTIONS=request;do_HEAD=request
        proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Ingress);ca=None
        if tls:
            ca=work/'cert.pem';private=work/'key.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(private),'-out',str(ca),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],capture_output=True,check=True);private.chmod(0o600)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(ca),str(private));proxy.socket=context.wrap_socket(proxy.socket,server_side=True)
        threading.Thread(target=proxy.serve_forever,daemon=True).start();origin=('https://localhost:' if tls else 'http://127.0.0.1:')+str(proxy.server_port)
        env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_IDEMPOTENCY_EXAMPLE_')};env.update(SOSECURITY_IDEMPOTENCY_EXAMPLE_ORIGIN=origin,SOSECURITY_IDEMPOTENCY_EXAMPLE_HTTPS='1' if tls else '0',SOSECURITY_IDEMPOTENCY_EXAMPLE_STORAGE=str(storage),SOSECURITY_IDEMPOTENCY_EXAMPLE_DATABASE=str(database),SOSECURITY_IDEMPOTENCY_EXAMPLE_KEYS=str(key_file),SOSECURITY_IDEMPOTENCY_EXAMPLE_EPOCH=os.urandom(32).hex(),SOSECURITY_IDEMPOTENCY_EXAMPLE_DOCUMENT_ROOT=str(web),SOSECURITY_TEST_IDEMPOTENCY_INGRESS=secret)
        for name,value in (policy or {}).items():env['SOSECURITY_IDEMPOTENCY_EXAMPLE_'+name]=str(value)
        router=work/'router.php';router.write_text('<?php '+('require_once base64_decode("'+clock_helper_path_b64+'");' if controlled_clock else '')+'if(($_SERVER["REQUEST_URI"]??"")==="/idempotency-admin.php"){require '+json.dumps(str(root/'examples/idempotency-admin.php'))+';return;} if(($_SERVER["REMOTE_ADDR"]??"")==="127.0.0.1"&&hash_equals(getenv("SOSECURITY_TEST_IDEMPOTENCY_INGRESS"),$_SERVER["HTTP_X_TEST_IDEMPOTENCY_INGRESS"]??"")){$_SERVER["SOSECURITY_IDEMPOTENCY_HEADERS_VALIDATED"]="1";if(getenv("SOSECURITY_IDEMPOTENCY_EXAMPLE_HTTPS")==="1"){$_SERVER["HTTPS"]="on";}} require '+json.dumps(str(root/'examples/idempotency.php'))+';')
        def admin(command,subject,*arguments,success=True):
            result=subprocess.run([*php_command,str(root/'examples/idempotency-admin.php'),command,subject,*arguments],env=env,capture_output=True,text=True,timeout=20)
            if not success:check(1,result.returncode);check('',result.stdout);check('idempotency_admin.unavailable\n',result.stderr);return None
            check(0,result.returncode);check('',result.stderr);return json.loads(result.stdout)
        def credential(subject,scopes=None,ttl=120):
            result=subprocess.run([*php_command,str(root/'tests/idempotency-setup.php')],input=json.dumps({'directory':str(storage),'subject':subject,'scopes':['orders:create'] if scopes is None else scopes,'ttl':ttl}),env=env,capture_output=True,text=True,check=True,timeout=10);check('',result.stderr);return json.loads(result.stdout)
        alice=credential('alice@1');bob=credential('bob@1')
        if installed and not web_storage:check(True,admin('initialize','alice')['initialized']);check(False,admin('initialize','alice')['initialized']);check(True,admin('initialize','bob')['initialized'])
        log=(work/'server.log').open('w+');server=None
        def start():
            nonlocal server
            server=subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(web),str(router)],env=env,stdout=log,stderr=log)
            for _ in range(150):
                if server.poll() is not None:log.flush();log.seek(0);raise RuntimeError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):return
                except OSError:time.sleep(.02)
            raise RuntimeError('Native idempotency server startup timed out')
        def stop(kill=False):
            nonlocal server
            if server is not None and server.poll() is None:
                server.kill() if kill else server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
        def restart():stop();start()
        start()
        try:
            yield dict(work=work,web=web,storage=storage,sessions=sessions,db=db,database=database,keys=keys,key_file=key_file,save_keys=save_keys,env=env,url=origin+'/idempotency.php',backend=f'http://127.0.0.1:{port}/idempotency.php',ca=ca,alice=alice,bob=bob,admin=admin,credential=credential,restart=restart,stop=stop,start=start,advance_clock=advance_clock,clock_now=lambda:tick[0])
            log.flush();log.seek(0);messages=log.read()
            for warning in ['PHP Warning:','PHP Fatal error:','PHP Deprecated:']:check(False,warning in messages)
            check([],list(sessions.iterdir()))
        finally:stop();log.close();proxy.shutdown();proxy.server_close();db.close()

def call(f,reference='order-1',amount=500,key='native-request-00000001',token=None,headers=None,method='POST',body=None,url=None):
    target=url or f['url'];values={'Accept':'application/json'}
    if method!='GET':
        values.update({'Content-Type':'application/json','Idempotency-Key':key})
        if body is None:body=json.dumps({'reference':reference,'amount':amount},separators=(',',':')).encode()
    if token is not None:values['Authorization']='Bearer '+token
    values.update(headers or {})
    client=urllib.request.build_opener(*([urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(f['ca'])))] if f['ca'] and target.startswith('https:') else []))
    try:response=client.open(urllib.request.Request(target,data=body,headers=values,method=method),timeout=20)
    except urllib.error.HTTPError as error:response=error
    with response:
        data=response.read();check(None,response.headers.get('Set-Cookie'));check('no-store, private',response.headers.get('Cache-Control'));check('nosniff',response.headers.get('X-Content-Type-Options'))
        return response.status,(json.loads(data) if 'application/json' in response.headers.get('Content-Type','') else data.decode()),dict(response.headers)

def run(runtime,tls=False,browser=False):
    with fixture(runtime,tls=tls) as f:
        db=f['db'];token=f['alice']['token'];count=lambda:db.execute('SELECT COUNT(*) FROM idempotency_example_orders').fetchone()[0]
        before=list(f['storage'].iterdir());status,page,headers=call(f,method='GET');check(200,status);check(True,'幂等订单示例' in page);check(True,"script-src 'nonce-" in headers['Content-Security-Policy']);check(before,list(f['storage'].iterdir()))
        if browser:
            browser_env=dict(os.environ,SOSECURITY_IDEMPOTENCY_BROWSER_TOKEN=token);subprocess.run(['node',str(root/'tests/idempotency-browser.cjs'),f['url']],env=browser_env,check=True);check(1,count());return
        check(403,call(f)[0]);check(403,call(f,headers={'Cookie':'SoSecurityCredentialExample=unrelated-browser-session'})[0]);check(0,count())
        for proof in [f['credential']('alice@1',['orders:read']),f['credential']('disabled@1'),f['credential']('reader@1'),f['credential']('missing@1'),f['credential']('alice@older')]:check(403,call(f,token=proof['token'])[0]);check(0,count())
        status,first,headers=call(f,token=token);check(201,status);check('false',headers['Idempotency-Replayed']);execution=headers['X-Execution-Id'];check(1,count());check(['amount','order_id','reference'],sorted(first));check(500,first['amount']);check(32,len(first['order_id']))
        status,data,headers=call(f,token=token);check(201,status);check(first,data);check('true',headers['Idempotency-Replayed']);check(execution,headers['X-Execution-Id']);check(1,count())
        status,data,_=call(f,token=token,amount=600);check(409,status);check('idempotency.conflict',data['error']);check(1,count())
        status,data,_=call(f,token=token,key='native-request-00000002');check(201,status);check(first,data);check(1,count());check(2,db.execute('SELECT COUNT(*) FROM idempotency_example_executions').fetchone()[0])
        status,data,headers=call(f,token=token,amount=600,key='native-request-00000003');check(409,status);check('order.reference_conflict',data['error']);check('false',headers['Idempotency-Replayed']);status,data,headers=call(f,token=token,amount=600,key='native-request-00000003');check(409,status);check('true',headers['Idempotency-Replayed']);check(1,count())
        status,data,_=call(f,token=token,key='native-json-variant-0001',body=b'{"amount":500,"reference":"order-\\u0031"}');check(201,status);check(first,data);check(1,count())
        for body in [b'{',b'[]',b'{"reference":"order","amount":true}',b'{"reference":"order","amount":1.5}',b'{"reference":"../bad","amount":1}',b'{"reference":"order","amount":0}',b'{"reference":"order","amount":1,"subject":"bob"}',b' '+b'x'*8192]:check(400,call(f,token=token,body=body)[0]);check(1,count())
        for number,body in enumerate([b'{"reference":"order","amount":0,"amount":500}',b'{"reference":"order","amount":1,"\\u0061mount":500}',b'{"reference":"a","reference":"order","amount":500}',b'{"reference":{"forged":true},"reference":"order","amount":500}']):check(400,call(f,token=token,key='native-duplicate-body-'+str(number).zfill(3),body=body)[0]);check(1,count())
        for extra in [{'Content-Type':'text/plain'},{'Content-Encoding':'gzip'},{'Idempotency-Key':'short'}]:check(400,call(f,token=token,headers=extra)[0]);check(1,count())
        check(405,call(f,token=token,method='PUT')[0]);check(400,call(f,token=token,url=f['url']+'?subject=bob')[0]);check(400,call(f,token=token,url=f['url']+'/extra')[0]);check(503,call(f,token=token,headers={'Host':'untrusted.invalid'})[0]);check(1,count())
        # Duplicate and case-variant authentication/idempotency/framing headers are rejected before PHP drops information.
        target=urllib.parse.urlsplit(f['url'])
        for name in ['Authorization','authorization','Idempotency-Key','idempotency-key','Content-Type','Content-Length','Host']:
            connection=(http.client.HTTPSConnection(target.hostname,target.port,context=ssl.create_default_context(cafile=str(f['ca']))) if tls else http.client.HTTPConnection(target.hostname,target.port));body=b'{"reference":"duplicate","amount":1}'
            connection.putrequest('POST',target.path,skip_host=True,skip_accept_encoding=True)
            for field,value in [('Host',target.netloc),('Authorization','Bearer '+token),('Idempotency-Key','duplicate-request-00001'),('Content-Type','application/json'),('Content-Length',str(len(body)))]:connection.putheader(field,value)
            duplicate={'authorization':'Bearer '+token,'idempotency-key':'duplicate-request-00001','content-type':'application/json','content-length':str(len(body)),'host':target.netloc}[name.lower()];connection.putheader(name,duplicate);connection.endheaders(body);response=connection.getresponse();check(400,response.status);response.read();connection.close();check(1,count())
        check(503,call(f,token=token,url=f['backend'],headers={'Host':target.netloc,'X-Forwarded-Proto':'https','SOSECURITY_IDEMPOTENCY_HEADERS_VALIDATED':'1','X-Test-Idempotency-Ingress':'forged'})[0]);check(1,count())
        # SQL failures and current authority changes happen before the business/result commit.
        db.execute("CREATE TRIGGER fail_order BEFORE INSERT ON idempotency_example_orders BEGIN SELECT RAISE(ABORT,'SYNTHETIC-PRIVATE-SQL'); END");db.commit();status,data,_=call(f,reference='retry',key='native-request-retry-01',token=token);check(503,status);check({'error':'idempotency_example.unavailable'},data);check(1,count());db.execute('DROP TRIGGER fail_order');db.commit();check(201,call(f,reference='retry',key='native-request-retry-01',token=token)[0]);check(2,count())
        db.execute("CREATE TRIGGER revoke_during_order AFTER INSERT ON idempotency_example_orders BEGIN UPDATE idempotency_example_accounts SET enabled=0 WHERE tenant='idempotency-example' AND subject='alice'; END");db.commit();check(403,call(f,reference='denied-commit',key='native-denied-commit-01',token=token)[0]);check(2,count());check(1,db.execute("SELECT enabled FROM idempotency_example_accounts WHERE tenant='idempotency-example' AND subject='alice'").fetchone()[0]);db.execute('DROP TRIGGER revoke_during_order');db.commit()
        original=db.execute("SELECT roles,version FROM idempotency_example_accounts WHERE tenant='idempotency-example' AND subject='alice'").fetchone();db.execute("UPDATE idempotency_example_accounts SET roles='[\"reader\"]' WHERE tenant='idempotency-example' AND subject='alice'");db.commit();check(403,call(f,token=token)[0]);check(2,count());db.execute("UPDATE idempotency_example_accounts SET roles=?,version='2' WHERE tenant='idempotency-example' AND subject='alice'",(original[0],));db.commit();check(403,call(f,token=token)[0]);fresh=f['admin']('issue','alice','120');token=fresh['token'];check(201,call(f,token=token)[0]);check(2,count())
        status,bob,_=call(f,token=f['bob']['token'],headers={'Cookie':'SoSecurityCredentialExample=alice-cookie'});check(201,status);check(False,bob['order_id']==first['order_id']);check(3,count())
        db.execute("UPDATE idempotency_example_orders SET subject='new-owner' WHERE order_id=?",(first['order_id'],));db.commit();check(403,call(f,token=token)[0]);db.execute("UPDATE idempotency_example_orders SET subject='alice' WHERE order_id=?",(first['order_id'],));db.commit();check(201,call(f,token=token)[0])
        # Removing security state does not erase the independent host business uniqueness ledger.
        db.execute('DELETE FROM sosecurity_idempotency_records');db.execute('DELETE FROM sosecurity_idempotency_roots');db.commit();check(503,call(f,token=token)[0]);check(3,count());check(True,f['admin']('initialize','alice')['initialized']);status,restored,_=call(f,token=token);check(201,status);check(first,restored);check(3,count())
        f['key_file'].rename(f['work']/'offline.json');check(503,call(f,token=token)[0]);(f['work']/'offline.json').rename(f['key_file']);check(201,call(f,token=token)[0]);check(3,count())
        f['keys']['keys']['new']=base64.b64encode(os.urandom(32)).decode();f['keys']['current']='new';f['save_keys']();check(1,f['admin']('maintain','alice')['rekeyed']);f['keys']['keys'].pop('old');f['save_keys']();check(201,call(f,token=token)[0]);check(3,count())
        database_offline=f['work']/'offline.sqlite';f['database'].rename(database_offline);check(403,call(f)[0]);check(503,call(f,token=token)[0]);check(False,f['database'].exists());database_offline.rename(f['database']);check(201,call(f,token=token)[0]);check(3,count())
        check(True,f['admin']('revoke',fresh['id'])['revoked']);check(403,call(f,token=token)[0]);f['admin']('issue','reader',success=False)
        check(404,call(f,method='GET',url=f['url'].replace('idempotency.php','idempotency-admin.php'))[0])
        db.execute('DROP TABLE idempotency_example_accounts');db.commit();check(1,f['admin']('maintain','alice')['scanned']);check(3,count())
    with fixture(runtime,tls=tls,policy={'TTL':1,'CAPACITY':1},controlled_clock=True) as f:
        check(201,call(f,token=f['alice']['token'])[0]);created,expires=f['db'].execute('SELECT created_at,expires_at FROM sosecurity_idempotency_records').fetchone();check(f['clock_now'](),created);check(1,expires-created);f['advance_clock'](1);check(expires,f['clock_now']());status,expired,_=call(f,token=f['alice']['token']);check(409,status);check('idempotency.expired',expired['error']);check(0,f['admin']('maintain','alice')['compacted']);status,data,_=call(f,key='native-new-capacity-0001',reference='other',token=f['alice']['token']);check(409,status);check('idempotency.capacity',data['error']);check(1,f['db'].execute('SELECT COUNT(*) FROM idempotency_example_orders').fetchone()[0])
    for options in [dict(installed=False),dict(web_storage=True)]:
        with fixture(runtime,tls=tls,**options) as f:check(503,call(f,token=f['alice']['token'])[0]);check(0,f['db'].execute('SELECT COUNT(*) FROM idempotency_example_orders').fetchone()[0]);check(0,f['db'].execute('SELECT COUNT(*) FROM sosecurity_idempotency_roots').fetchone()[0]) if options.get('web_storage') else check(0,f['db'].execute("SELECT COUNT(*) FROM sqlite_master WHERE name='sosecurity_idempotency_roots'").fetchone()[0])
    with fixture(runtime,tls=tls) as f:
        seeded=subprocess.run([runtime,str(root/'tests/idempotency-setup.php')],input=json.dumps({'directory':str(f['storage']),'mode':'entry_budget'}),capture_output=True,text=True,check=True,timeout=10);check('',seeded.stderr);check(True,json.loads(seeded.stdout)['blocked'])
        f['key_file'].unlink();f['database'].rename(f['work']/'offline.sqlite');status,data,_=call(f,token=f['alice']['token'],headers={'X-Forwarded-For':'192.0.2.45'});check(429,status);check('idempotency_example.rate',data['error']);check(False,f['database'].exists())
    with fixture(runtime,tls=tls) as f:
        # Abandon the HTTP acknowledgement, observe the actual commit independently, then kill only our own server.
        target=urllib.parse.urlsplit(f['url']);connection=(http.client.HTTPSConnection(target.hostname,target.port,context=ssl.create_default_context(cafile=str(f['ca']))) if tls else http.client.HTTPConnection(target.hostname,target.port));body=b'{"reference":"lost-response","amount":500}'
        connection.request('POST',target.path,body,{'Authorization':'Bearer '+f['alice']['token'],'Content-Type':'application/json','Idempotency-Key':'network-lost-response-01'})
        until=time.monotonic()+10;order=None
        try:
            while time.monotonic()<until:
                order=f['db'].execute("SELECT order_id FROM idempotency_example_orders WHERE reference_id='lost-response'").fetchone()
                if order is not None:break
                time.sleep(.01)
        finally:connection.close()
        check(True,order is not None);f['stop'](kill=True);f['start']();status,data,headers=call(f,reference='lost-response',key='network-lost-response-01',token=f['alice']['token']);check(201,status);check('true',headers['Idempotency-Replayed']);check(order[0],data['order_id']);check(1,f['db'].execute('SELECT COUNT(*) FROM idempotency_example_orders').fetchone()[0]);check(1,f['db'].execute('SELECT COUNT(*) FROM idempotency_example_executions').fetchone()[0])

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--tls',action='store_true');parser.add_argument('--browser',action='store_true');args=parser.parse_args()
    if subprocess.call([args.runtime,'-r','exit(extension_loaded("pdo_sqlite")?0:1);'])!=0:
        print('NOT RUN native idempotency: optional PDO SQLite required');raise SystemExit(1 if os.getenv('SOSECURITY_REQUIRE_RESET')=='1' else 0)
    run(args.runtime,args.tls,args.browser);print(f'PASS native idempotency {"TLS" if args.tls else "HTTP"}: {checks} assertions on {args.runtime}; real bearer/current SQL authority, historical receipt replay, independent business uniqueness and fail-closed ingress')
