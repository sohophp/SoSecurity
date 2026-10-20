#!/usr/bin/env python3
"""Real password/SQLite/FileStore download pipeline, binary HTTP and private-CA TLS termination."""
import argparse,base64,contextlib,hashlib,http.client,http.cookiejar,http.server,json,os,socket,sqlite3,ssl,subprocess,tempfile,threading,time
import urllib.error,urllib.parse,urllib.request
from pathlib import Path
root=Path(__file__).resolve().parent.parent;checks=0;SCOPE='download-example';PASSWORD='Correct-download-test-password';OTHER_PASSWORD='Other-download-test-password'
BODY=bytes(range(256))*64;NAME='报告 "2026".bin'
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
class Visitor:
    def __init__(self,url,ca=None):
        self.url=url;self.csrf='';self.jar=http.cookiejar.CookieJar();handlers=[urllib.request.HTTPCookieProcessor(self.jar)]
        if ca:handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
        self.client=urllib.request.build_opener(*handlers)
    def call(self,action=None,fields=None,url=None,method=None,csrf=None,headers=None):
        body=None
        if action is not None or method=='POST':
            values=dict(fields or {},_csrf=self.csrf if csrf is None else csrf)
            if action is not None:values['action']=action
            body=urllib.parse.urlencode(values).encode()
        try:response=self.client.open(urllib.request.Request(url or self.url,data=body,method=method,headers=dict({'Accept':'application/json'},**(headers or {}))),timeout=15)
        except urllib.error.HTTPError as error:response=error
        with response:
            check('no-store, private',response.headers['Cache-Control']);check('no-referrer',response.headers['Referrer-Policy']);raw=response.read()
            data=json.loads(raw) if raw and response.headers.get_content_type()=='application/json' else raw
            if isinstance(data,dict):
                self.csrf=data.get('csrf',self.csrf)
                for secret in [PASSWORD,OTHER_PASSWORD,'$2y$','soss_']:check(False,secret in json.dumps(data))
            return response.status,data,response.headers
    def login(self,username='demo',password=PASSWORD):return self.call('login',{'username':username,'password':password})
    def issue(self,delivery='read',file_id='a'):
        status,data,_=self.call('issue',{'file_id':file_id,'delivery':delivery});check(200,status);return data['issued_url'],data['issued']['id']
def provision(runtime,storage,operation='initialize',holders=None):
    script='''require $argv[1].'/vendor/autoload.php';$s=new SoSecurity\\Storage\\FileStore($argv[2],'download-example');$m=new SoSecurity\\Concurrency\\LeaseManager($s,new SoSecurity\\Concurrency\\LeasePolicy(4,30,30));
if($argv[3]==='initialize'){$m->initialize('download-example','transfers');echo 'true';}
elseif($argv[3]==='hold'){$a=[];for($i=0;$i<4;++$i){$l=$m->acquire('download-example','transfers','held-'.$i);$a[]=$l->token();}echo json_encode($a);}
elseif($argv[3]==='release'){$a=json_decode(stream_get_contents(STDIN),true);foreach($a as $i=>$t){$m->release('download-example','transfers','held-'.$i,$t);}echo 'true';}
elseif($argv[3]==='remove'){$epoch=$m->inspect('download-example','transfers')->epoch();echo json_encode($m->remove('download-example','transfers',$epoch));}
else{echo json_encode($m->inspect('download-example','transfers')->active());}'''
    return json.loads(subprocess.check_output([runtime,'-r',script,str(root),str(storage),operation],input=json.dumps(holders or []).encode()))
def wait_idle(runtime,f):
    # Receiving Content-Length bytes does not prove the live PHP worker has completed finally/release.
    until=time.monotonic()+3
    while True:
        if f['server'].poll() is not None:raise RuntimeError('Download PHP worker exited before cleanup')
        active=provision(runtime,f['state'],'inspect')
        if active==0 or time.monotonic()>=until:return active
        time.sleep(.02)
@contextlib.contextmanager
def fixture(runtime,tls=False,budget=None,initialize=True,web_storage=False,late_finish=False):
    with tempfile.TemporaryDirectory(prefix='sosecurity-download-http-') as directory:
        work=Path(directory);dirs={key:work/key for key in ['state','sessions','source','temporary']}
        for path in dirs.values():path.mkdir(mode=0o700)
        web=root/'examples'
        if web_storage:
            web=work/'web';web.mkdir(mode=0o700);dirs['state'].rmdir();dirs['state']=web/'state';dirs['state'].mkdir(mode=0o700)
            (web/'authorized-download.php').write_text('<?php require '+json.dumps(str(root/'examples/authorized-download.php'))+';')
        source=dirs['source']/'payload.bin';source.write_bytes(BODY);source.chmod(0o600)
        other=dirs['source']/'other.bin';other.write_bytes(b'OTHER-OWNER-PRIVATE');other.chmod(0o600)
        def hashed(value):return subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',value],text=True)
        database=work/'downloads.sqlite';db=sqlite3.connect(database);database.chmod(0o600)
        db.execute('CREATE TABLE download_accounts(tenant TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,password_hash TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,roles TEXT NOT NULL,PRIMARY KEY(tenant,subject),UNIQUE(tenant,username))')
        db.executemany('INSERT INTO download_accounts VALUES(?,?,?,?,?,?,?)',[(SCOPE,'alice','demo',hashed(PASSWORD),'1',1,'["editor"]'),(SCOPE,'bob','other',hashed(OTHER_PASSWORD),'1',1,'["editor"]')])
        db.execute('CREATE TABLE download_files(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,relative_path TEXT NOT NULL,filename TEXT NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(tenant,id))')
        db.executemany('INSERT INTO download_files VALUES(?,?,?,?,?,?,?,?,?)',[(SCOPE,'a','alice',1,'payload.bin',NAME,len(BODY),hashlib.sha256(BODY).hexdigest(),'ready'),(SCOPE,'b','bob',1,'other.bin','other.bin',other.stat().st_size,hashlib.sha256(other.read_bytes()).hexdigest(),'ready'),('other','a','alice',1,'other.bin','tenant-private.bin',other.stat().st_size,hashlib.sha256(other.read_bytes()).hexdigest(),'ready')]);db.commit()
        keyfile=work/'keys.json';keys={'current':'old','keys':{'old':base64.b64encode(os.urandom(32)).decode()}}
        def save_keys():keyfile.write_text(json.dumps(keys));keyfile.chmod(0o600)
        save_keys()
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        proxy=None;ca=None;origin=f'http://127.0.0.1:{port}';secret=os.urandom(32).hex()
        if tls:
            ca=work/'cert.pem';key=work/'key.pem';subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(ca),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True);key.chmod(0o600)
            class Proxy(http.server.BaseHTTPRequestHandler):
                def log_message(self,*unused):pass
                def request(self):
                    length=int(self.headers.get('Content-Length','0'))
                    if length<0 or length>8192:self.send_error(413);return
                    headers={k:v for k,v in self.headers.items() if k.lower() not in ['connection','transfer-encoding','content-length','x-test-download-tls']};headers['X-Test-Download-Tls']=secret
                    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                    try:
                        connection.request(self.command,self.path,self.rfile.read(length),headers);response=connection.getresponse();data=response.read(2097153)
                        if len(data)>2097152:raise RuntimeError('TLS test response budget exceeded')
                        self.send_response(response.status)
                        for name,value in response.getheaders():
                            if name.lower() not in ['connection','transfer-encoding','content-length','server','date']:self.send_header(name,value)
                        self.send_header('Content-Length',response.getheader('Content-Length','0') if self.command=='HEAD' else str(len(data)));self.end_headers()
                        if self.command!='HEAD':self.wfile.write(data)
                    finally:connection.close()
                do_GET=request;do_HEAD=request;do_POST=request;do_PUT=request
            proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(ca),str(key));proxy.socket=context.wrap_socket(proxy.socket,server_side=True);threading.Thread(target=proxy.serve_forever,daemon=True).start();origin=f'https://localhost:{proxy.server_port}'
        env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_DOWNLOAD_EXAMPLE_')};env.update(SOSECURITY_DOWNLOAD_EXAMPLE_DATABASE=str(database),SOSECURITY_DOWNLOAD_EXAMPLE_KEYS=str(keyfile),SOSECURITY_DOWNLOAD_EXAMPLE_ORIGIN=origin,SOSECURITY_DOWNLOAD_EXAMPLE_STORAGE=str(dirs['state']),SOSECURITY_DOWNLOAD_EXAMPLE_ROOT=str(dirs['source']),SOSECURITY_DOWNLOAD_EXAMPLE_TEMPORARY=str(dirs['temporary']),SOSECURITY_DOWNLOAD_EXAMPLE_DUMMY_HASH=hashed('Dummy-download-test-password'),SOSECURITY_DOWNLOAD_EXAMPLE_HTTPS='1' if tls else '0')
        if budget is not None:env['SOSECURITY_DOWNLOAD_EXAMPLE_BUDGET_KIB']=str(budget)
        if initialize:check(True,provision(runtime,dirs['state']))
        router=work/'router.php';late='namespace SoSecurity\\Examples\\DownloadHttp {function connection_aborted(){\\flush();\\usleep(1000000);return \\connection_aborted();}}' if late_finish else ''
        router.write_text('<?php '+late+' namespace {if(($_SERVER["REMOTE_ADDR"]??"")==="127.0.0.1"&&hash_equals(getenv("SOSECURITY_TEST_DOWNLOAD_TLS"),$_SERVER["HTTP_X_TEST_DOWNLOAD_TLS"]??"")){$_SERVER["HTTPS"]="on";}require '+json.dumps(str(root/'examples/authorized-download.php'))+';}')
        env['SOSECURITY_TEST_DOWNLOAD_TLS']=secret
        with (work/'server.log').open('w+') as log:
            server=subprocess.Popen([runtime,'-d','session.save_path='+str(dirs['sessions']),'-S',f'127.0.0.1:{port}','-t',str(web)]+([str(router)] if tls or late_finish else []),env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:log.seek(0);raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('Download native server startup timed out')
                yield dict(dirs,db=db,work=work,url=origin+'/authorized-download.php',ca=ca,origin=origin,env=env,keys=keys,keyfile=keyfile,save_keys=save_keys,database=database,file=source,server=server,backend=f'http://127.0.0.1:{port}/authorized-download.php')
                check(0,wait_idle(runtime,dict(dirs,server=server)))
                check([],list(dirs['temporary'].iterdir()));log.flush();log.seek(0);messages=log.read()
                for bad in ['PHP Warning:','PHP Deprecated:','PHP Fatal error:','download.stream_aborted']:check(False,bad in messages)
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
                if proxy:proxy.shutdown();proxy.server_close()
                db.close()
def run(runtime,tls=False,browser=False):
    if subprocess.call([runtime,'-r','exit(extension_loaded("pdo_sqlite")?0:1);'])!=0:
        print('NOT RUN download HTTP: optional PDO SQLite required');return 1 if os.getenv('SOSECURITY_REQUIRE_RESET')=='1' else 0
    with fixture(runtime,tls) as f:
        db=f['db'];v=Visitor(f['url'],f['ca']);reader=Visitor(f['url'],f['ca']);private=f['url']+'?delivery=private&file_id=a';other=f['url']+'?delivery=private&file_id=b'
        original=db.execute('SELECT * FROM download_files ORDER BY tenant,id').fetchall()
        if browser:
            env=f['env'].copy();env['SOSECURITY_TEST_DOWNLOAD_PASSWORD']=PASSWORD;env['SOSECURITY_TEST_DOWNLOAD_SHA256']=hashlib.sha256(BODY).hexdigest()
            subprocess.run(['node',str(root/'tests/download-browser.cjs'),f['url']],env=env,check=True,timeout=60);check(original,db.execute('SELECT * FROM download_files ORDER BY tenant,id').fetchall())
        else:
            status,data,headers=v.call();check(200,status);check('anonymous',data['stage']);check(True,'HttpOnly' in ';'.join(headers.get_all('Set-Cookie',[])))
            check(403,reader.call(url=private)[0]);status,_,headers=reader.call(url=private,headers={'Range':'bytes=99999999999999999999-'});check(403,status);check(None,headers.get('Content-Range'))
            for identifier in ['a','missing']:
                anonymous=Visitor(f['url'],f['ca']);status,data,headers=anonymous.call(url=f['url']+'?delivery=private&file_id='+identifier,headers={'Range':'bytes=-'});check(403,status);check({'error':'download.denied'},data);check(True,bool(headers.get_all('Set-Cookie')));check(None,headers.get('Content-Range'))
            check(403,v.call('issue',{'file_id':'a','delivery':'read'})[0]);check(403,v.call('login',{'username':'demo','password':PASSWORD},csrf='wrong')[0]);old_csrf=v.csrf
            check(200,v.login()[0]);check(403,v.call('issue',{'file_id':'a','delivery':'read'},csrf=old_csrf)[0]);check(403,v.call(url=other)[0]);check(403,v.call('issue',{'file_id':'b','delivery':'read'})[0]);check(400,v.call('issue',{'file_id':'a','delivery':'read','tenant':'other'})[0])
            status,body,headers=v.call(url=private);check(200,status);check(BODY,body);check('application/octet-stream',headers['Content-Type']);check(str(len(BODY)),headers['Content-Length']);check('nosniff',headers['X-Content-Type-Options']);check('bytes',headers['Accept-Ranges']);check(True,"filename*=UTF-8''"+urllib.parse.quote(NAME,safe='') in headers['Content-Disposition']);check(False,'\n' in headers['Content-Disposition']);check(False,str(f['work']) in str(headers));tag=headers['ETag']
            if tls:check(True,all(c.secure for c in v.jar))
            status,body,headers=v.call(url=private,method='HEAD',headers={'Range':'bytes=0-0'});check(200,status);check(b'',body);check(str(len(BODY)),headers['Content-Length'])
            for value,start,end in [('bytes=0-0',0,0),('bytes=2-5',2,5),('bytes=-3',len(BODY)-3,len(BODY)-1),('bytes=16380-',16380,16383),('bytes=0-99999999999999999999',0,len(BODY)-1)]:
                status,body,headers=v.call(url=private,headers={'Range':value});check(206,status);check(BODY[start:end+1],body);check(f'bytes {start}-{end}/{len(BODY)}',headers['Content-Range'])
            status,_,headers=v.call(url=private,headers={'Range':'bytes=99999999999999999999-'});check(416,status);check('bytes */'+str(len(BODY)),headers['Content-Range'])
            for value in ['bytes=0-1,3-4','bytes=-','items=0-1']:status,_,headers=v.call(url=private,headers={'Range':value});check(400,status);check(None,headers.get('Content-Range'))
            for condition in ['"old"','W/'+tag,'Wed, 01 Jan 2020 00:00:00 GMT']:
                status,body,_=v.call(url=private,headers={'Range':'bytes=0-0','If-Range':condition});check(200,status);check(BODY,body)
            status,body,_=v.call(url=private,headers={'Range':'bytes=0-0','If-Range':tag});check(206,status);check(BODY[:1],body)
            status,body,_=v.call(url=private,headers={'If-None-Match':'*','If-Modified-Since':'Wed, 01 Jan 2030 00:00:00 GMT'});check(200,status);check(BODY,body)
            check(405,v.call(url=private,method='POST')[0]);check(405,v.call(url=private,method='PUT')[0])
            for bad in [private+'&tenant=other',private+'&file_id=b',private.replace('file_id=a','file_id[]=a'),private.replace('delivery=private&file_id=a','file_id=a&delivery=private')]:check(400,v.call(url=bad)[0])
            reader=Visitor(f['url'],f['ca']);url,identifier=v.issue();status,body,headers=reader.call(url=url);check(200,status);check(BODY,body);check(False,any(reader.jar));check(None,headers.get('Set-Cookie'))
            for bad in [url+'&extra=1',url+'&file_id=b',url.replace('file_id=a','file_id=b'),url.replace('_ss=','%5Fss=')]:check(403,reader.call(url=bad)[0])
            check(503,reader.call(url=url,headers={'Host':'evil.example'})[0]);check(403,reader.call(url=url,method='HEAD')[0]);check(200,reader.call(url=url)[0])
            single,_=v.issue('once');check(403,reader.call(url=single,headers={'Range':'bytes=0-0'})[0]);check(403,reader.call(url=single,method='HEAD')[0]);check(BODY,reader.call(url=single)[1]);check(403,reader.call(url=single)[0])
            redeem,_=v.issue('redeem');check(True,reader.call(url=redeem)[1]['redemption']);check(True,reader.call(url=redeem)[1]['redemption']);check(403,reader.call(url=redeem,method='POST',csrf='wrong')[0]);check(BODY,reader.call(url=redeem,method='POST')[1]);check(403,reader.call(url=redeem,method='POST')[0])
            check(True,v.call('revoke',{'file_id':'a','link_id':identifier})[1]['revoked']);check(403,reader.call(url=url)[0])
            url,_=v.issue();saved=f['file'].stat();f['file'].write_bytes(b'X'*len(BODY));os.utime(f['file'],ns=(saved.st_atime_ns,saved.st_mtime_ns));check(403,reader.call(url=url)[0]);check(403,v.call(url=private)[0]);f['file'].write_bytes(BODY)
            f['file'].rename(f['source']/'original.bin');f['file'].symlink_to(f['source']/'other.bin');check(403,v.call(url=private)[0]);f['file'].unlink();(f['source']/'original.bin').rename(f['file'])
            os.link(f['file'],f['source']/'hard.bin');check(403,v.call(url=private)[0]);(f['source']/'hard.bin').unlink()
            f['file'].chmod(0o644);check(403,v.call(url=private)[0]);f['file'].chmod(0o600)
            for column,value in [('filename','renamed.bin'),('version',2),('state','quarantined')]:
                url,_=v.issue();db.execute('UPDATE download_files SET '+column+'=? WHERE tenant=? AND id=?',(value,SCOPE,'a'));db.commit();check(403,reader.call(url=url)[0]);db.execute('UPDATE download_files SET '+column+'=? WHERE tenant=? AND id=?',({'filename':NAME,'version':1,'state':'ready'}[column],SCOPE,'a'));db.commit()
            held=provision(runtime,f['state'],'hold');check(429,v.call(url=private)[0]);check(True,provision(runtime,f['state'],'release',held));check(0,provision(runtime,f['state'],'inspect'));check(BODY,v.call(url=private)[1])
            check(0,wait_idle(runtime,f));check(True,provision(runtime,f['state'],'remove'));check(503,v.call(url=private)[0]);check(True,provision(runtime,f['state']));check(BODY,v.call(url=private)[1]);check(0,wait_idle(runtime,f))
            moved=f['work']/'offline-state';f['state'].rename(moved);check(503,v.call(url=private)[0]);moved.rename(f['state']);check(BODY,v.call(url=private)[1])
            moved=f['work']/'offline.sqlite';f['database'].rename(moved);check(503,v.call(url=private)[0]);moved.rename(f['database']);check(BODY,v.call(url=private)[1])
            f['keyfile'].chmod(0o644);check(503,v.call(url=private)[0]);f['keyfile'].chmod(0o600)
            f['keys']['current']='new';f['keys']['keys']['new']=base64.b64encode(os.urandom(32)).decode();f['save_keys']();url,_=v.issue();check(BODY,reader.call(url=url)[1]);del f['keys']['keys']['new'];f['keys']['current']='old';f['save_keys']();check(403,reader.call(url=url)[0])
            url,_=v.issue();replacement=subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',PASSWORD],text=True);db.execute('UPDATE download_accounts SET password_hash=? WHERE tenant=? AND subject=?',(replacement,SCOPE,'alice'));db.commit();check(403,reader.call(url=url)[0]);check(403,v.call(url=private)[0]);check('anonymous',v.call()[1]['stage']);check(200,v.login()[0])
            url,_=v.issue();db.execute('UPDATE download_accounts SET roles=?,version=? WHERE tenant=? AND subject=?',('["reader"]','2',SCOPE,'alice'));db.commit();check(403,reader.call(url=url)[0]);check(403,v.call(url=private)[0]);check('anonymous',v.call()[1]['stage']);check(200,v.login()[0]);check(BODY,v.call(url=private)[1]);check(403,v.call('issue',{'file_id':'a','delivery':'read'})[0])
            check(200,v.call('logout')[0]);check(403,v.call(url=private)[0]);check(200,v.login('other',OTHER_PASSWORD)[0]);check(403,v.call(url=private)[0]);check(b'OTHER-OWNER-PRIVATE',v.call(url=other)[1])
            db.execute('UPDATE download_accounts SET enabled=0,version=? WHERE tenant=? AND subject=?',('2',SCOPE,'bob'));db.commit();check(403,v.call(url=other)[0]);check('anonymous',v.call()[1]['stage'])
            check(original[2],db.execute("SELECT * FROM download_files WHERE tenant='other'").fetchone());check(0,wait_idle(runtime,f))
            if tls:
                direct=Visitor(f['backend']);check(503,direct.call(headers={'Host':urllib.parse.urlparse(f['origin']).netloc,'X-Forwarded-Proto':'https','X-Test-Download-Tls':'spoofed'})[0])
    if not browser:
        with fixture(runtime,tls,budget=32) as f:
            v=Visitor(f['url'],f['ca']);v.call();v.login();private=f['url']+'?delivery=private&file_id=a'
            for unused in range(2):check(206,v.call(url=private,headers={'Range':'bytes=0-0'})[0])
            check(429,v.call(url=private,headers={'Range':'bytes=0-0'})[0]);check(0,provision(runtime,f['state'],'inspect'))
        with fixture(runtime,tls,initialize=False) as f:
            v=Visitor(f['url'],f['ca']);v.call();v.login();check(503,v.call(url=f['url']+'?delivery=private&file_id=a')[0]);check(True,provision(runtime,f['state']));check(BODY,v.call(url=f['url']+'?delivery=private&file_id=a')[1])
        with fixture(runtime,tls,web_storage=True) as f:
            v=Visitor(f['url'],f['ca']);check((503,{'error':'download.unavailable'}),v.call()[:2])
        if not tls:
            with fixture(runtime,late_finish=True) as f:
                v=Visitor(f['url']);v.call();v.login();check(BODY,v.call(url=f['url']+'?delivery=private&file_id=a')[1]);check(1,provision(runtime,f['state'],'inspect'));check(0,wait_idle(runtime,f))
    print(f'PASS authorized download {"Chromium host" if browser else "TLS" if tls else "HTTP"}: {checks} assertions on {runtime}; real password/SQL authorization, exact binary/Range/HEAD, signed once/redeem/revoke, content and tenant boundaries, global cost/concurrency and failures')
    return 0
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--tls',action='store_true');parser.add_argument('--browser',action='store_true');args=parser.parse_args();raise SystemExit(run(args.runtime,args.tls,args.browser))
