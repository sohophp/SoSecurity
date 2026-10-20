#!/usr/bin/env python3
"""Real producer/worker/receiver in a private network namespace and private SQLite databases."""
import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

root=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser()
parser.add_argument('runtimes',nargs='*',default=['php'])
parser.add_argument('--inside')
parser.add_argument('--authority',action='store_true',help='Use independent current-authority databases')
args=parser.parse_args()
if not args.inside:
    if sys.platform!='linux' or not all(shutil.which(x) for x in ['sudo','unshare','ip','openssl']):
        raise SystemExit('Native Outbox tests require Linux sudo/unshare/ip/OpenSSL')
    with tempfile.TemporaryDirectory(prefix='sosecurity-outbox-native-') as directory:
        work=Path(directory)
        def cert(*options):subprocess.run(['openssl',*options],check=True,capture_output=True)
        cert('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Outbox private integration CA','-keyout',str(work/'ca.key'),'-out',str(work/'ca.crt'))
        cert('req','-newkey','rsa:2048','-nodes','-subj','/CN=receiver.example.com','-keyout',str(work/'server.key'),'-out',str(work/'server.csr'))
        (work/'extensions').write_text('subjectAltName=DNS:receiver.example.com,DNS:dns.google\n')
        cert('x509','-req','-in',str(work/'server.csr'),'-CA',str(work/'ca.crt'),'-CAkey',str(work/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(work/'extensions'),'-out',str(work/'server.crt'))
        subprocess.run(['sudo','-n','unshare','--net','--',sys.executable,str(Path(__file__).resolve()),'--inside',directory,*(['--authority'] if args.authority else []),*[shutil.which(x) or x for x in args.runtimes]],check=True,timeout=max(180,len(args.runtimes)*90))
    raise SystemExit(0)

base=Path(args.inside)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','address','add','8.8.8.8/32','dev','lo'],check=True)
tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2;tls.load_cert_chain(str(base/'server.crt'),str(base/'server.key'))
client_tls=ssl.create_default_context(cafile=str(base/'ca.crt'))
checks=0
check_lock=threading.Lock()
def check(expected,actual):
    global checks
    with check_lock:
        checks+=1
        assert expected==actual,(expected,actual)

class Connection(http.client.HTTPSConnection):
    def __init__(self):super().__init__('receiver.example.com',443,context=client_tls,timeout=10)
    def connect(self):self.sock=self._context.wrap_socket(socket.create_connection(('8.8.8.8',443),timeout=10),server_hostname='receiver.example.com')

def run(runtime):
    global checks
    checks=0
    with tempfile.TemporaryDirectory(prefix='fixture-',dir=base) as directory:
        work=Path(directory);web=root/'examples'
        sender=work/'sender.sqlite';receiver=work/'receiver.sqlite'
        db=sqlite3.connect(sender);recv=sqlite3.connect(receiver)
        for name in ['outbox-sqlite.sql','idempotency-sqlite.sql','outbox-example-sender-sqlite.sql']:db.executescript((root/'resources/sql'/name).read_text())
        for name in ['webhook-sqlite.sql','webhook-processing-sqlite.sql','outbox-example-receiver-sqlite.sql']:recv.executescript((root/'resources/sql'/name).read_text())
        db.execute('INSERT INTO outbox_example_actors VALUES(?,?,?,?)',('alice','1',1,'["orders_writer","outbox_worker","outbox_admin"]'))
        recv.execute('INSERT INTO outbox_example_actors VALUES(?,?,?,?)',('receiver','1',1,'["receiver_worker","receiver_admin"]'))
        recv.execute('INSERT INTO outbox_example_routes VALUES(?,?,?)',('outbox-publisher','outbox-example',1));recv.execute('INSERT INTO outbox_example_owners VALUES(?,?)',('alice',1));db.commit();recv.commit();sender.chmod(0o600);receiver.chmod(0o600)
        def private(name,data):
            path=work/name;path.write_text(json.dumps(data));path.chmod(0o600);return path
        wire={'current':'old','keys':{'old':base64.b64encode(os.urandom(32)).decode()}}
        sender_wire=private('sender-wire.json',wire);receiver_wire=private('receiver-wire.json',wire)
        sender_seals=private('sender-seals.json',{'current':'seal','keys':{'seal':base64.b64encode(os.urandom(32)).decode()}})
        receiver_seals=private('receiver-seals.json',{'current':'seal','keys':{'seal':base64.b64encode(os.urandom(32)).decode()}})
        idem_keys=private('idempotency-keys.json',{'current':'idem','keys':{'idem':base64.b64encode(os.urandom(32)).decode()}})
        for name in ['sender-state','receiver-state']:(work/name).mkdir(mode=0o700)
        common={'document_root':str(web),'version':'1','epoch':'e'*64,'url':'https://receiver.example.com/outbox-receiver.php','policy':{'maximum_payload_bytes':8192,'lease_seconds':6,'backoff_seconds':1,'maximum_backoff_seconds':4,'maximum_attempts':2,'maximum_entries':50}}
        sender_config=private('sender.json',dict(common,role='sender',database=str(sender),storage=str(work/'sender-state'),actor='alice',seals=str(sender_seals),wire_keys=str(sender_wire),idempotency_keys=str(idem_keys),transport_budget_ms=3000))
        checkpoint=work/'checkpoint.sqlite';witness=sqlite3.connect(checkpoint);witness.executescript((root/'resources/sql/outbox-example-checkpoint-sqlite.sql').read_text());witness.close();checkpoint.chmod(0o600);checkpoint_lock=work/'checkpoint.lock';checkpoint_lock.write_bytes(b'');checkpoint_lock.chmod(0o600)
        receiver_config=private('receiver.json',dict(common,role='receiver',database=str(receiver),storage=str(work/'receiver-state'),actor='receiver',seals=str(receiver_seals),wire_keys=str(receiver_wire),checkpoint_database=str(checkpoint),checkpoint_lock=str(checkpoint_lock)))
        sender_authority=db;receiver_authority=recv
        if args.authority:
            for role,actor,roles,config in [('sender','alice',['orders_writer','outbox_worker','outbox_admin'],sender_config),('receiver','receiver',['receiver_worker','receiver_admin'],receiver_config)]:
                path=work/(role+'-authority.sqlite');source=sqlite3.connect(path);source.executescript((root/'resources/sql/outbox-example-authority-sqlite.sql').read_text());source.execute('INSERT INTO outbox_example_actors VALUES(?,?,?,?)',(actor,'1',1,json.dumps(roles)));source.execute('INSERT INTO outbox_example_routes VALUES(?,?,?)',('outbox-publisher','outbox-example',1));source.execute('INSERT INTO outbox_example_owners VALUES(?,?)',('alice',1));source.commit();path.chmod(0o600)
                profile=json.loads(config.read_text());profile['authority_database']=str(path);config.write_text(json.dumps(profile))
                if role=='sender':sender_authority=source
                else:receiver_authority=source
            # The actual producer/worker/HTTP receiver must work without any local permission rows.
            db.execute('DELETE FROM outbox_example_actors');db.commit()
            for table in ['actors','routes','owners']:recv.execute('DELETE FROM outbox_example_'+table)
            recv.commit()
        env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_OUTBOX_')}
        env.update(SOSECURITY_OUTBOX_EXAMPLE_CONFIG=str(sender_config),HTTPS_PROXY='http://127.0.0.1:9',ALL_PROXY='http://127.0.0.1:9',NO_PROXY='')
        receiver_env=dict(env,SOSECURITY_OUTBOX_EXAMPLE_CONFIG=str(receiver_config));secret=os.urandom(32).hex();receiver_env['SOSECURITY_TEST_OUTBOX_INGRESS']=secret
        initialized=subprocess.run([runtime,str(web/'outbox-receiver-admin.php'),'--initialize'],env=receiver_env,capture_output=True,text=True,timeout=10)
        check(0,initialized.returncode);check('',initialized.stderr);check({'initialized':True},json.loads(initialized.stdout))
        router=work/'router.php';router.write_text('<?php if(in_array(parse_url($_SERVER["REQUEST_URI"],PHP_URL_PATH),["/outbox-worker.php","/outbox-admin.php","/outbox-producer.php","/outbox-receiver-admin.php"],true)){return false;} if(($_SERVER["REMOTE_ADDR"]??"")==="127.0.0.1"&&hash_equals(getenv("SOSECURITY_TEST_OUTBOX_INGRESS"),$_SERVER["HTTP_X_TEST_OUTBOX_INGRESS"]??"")){$_SERVER["HTTPS"]="on";$_SERVER["SOSECURITY_OUTBOX_HEADERS_VALIDATED"]="1";} require '+json.dumps(str(web/'outbox-receiver.php'))+';')
        processes=[];backend_ports=[];log=open(work/'server.log','w+')
        for unused in range(2):
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            process=subprocess.Popen([runtime,'-S',f'127.0.0.1:{port}','-t',str(web),str(router)],env=receiver_env,stdout=log,stderr=log);processes.append(process);backend_ports.append(port)
            until=time.monotonic()+10
            while time.monotonic()<until:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:
                    if process.poll() is not None:raise RuntimeError('Private PHP receiver exited')
                    time.sleep(.02)
            else:raise RuntimeError('Private PHP receiver startup timeout')
        state={'mode':'normal','requests':[],'responses':[],'counter':0,'network':[]};lock=threading.Lock();held=threading.Event();release=threading.Event()
        def trace(phase,**data):
            with lock:
                state['network'].append(dict(data,phase=phase,at=round(time.monotonic(),6)))
                if len(state['network'])>128:del state['network'][:-128]
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*unused):pass
            def send(self,status,body=b'',headers=None):
                try:
                    self.send_response(status)
                    for key,value in (headers or {}).items():self.send_header(key,value)
                    self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
            def do_GET(self):
                query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                if self.headers.get('Host')=='dns.google' and urllib.parse.urlsplit(self.path).path=='/resolve':
                    host=query['name'][0];kind=int(query['type'][0]);address='127.0.0.1' if state['mode']=='private-dns' else '8.8.8.8';answer=[{'name':host+'.','type':1,'data':address}] if kind==1 else []
                    trace('doh',type=kind,mode=state['mode'])
                    self.send(200,json.dumps({'Status':0,'Question':[{'name':host+'.','type':kind}],'Answer':answer}).encode(),{'Content-Type':'application/json'});return
                self.forward()
            def do_POST(self):self.forward()
            def forward(self):
                began=time.monotonic()
                headers=list(self.headers.raw_items());names=[name.lower() for name,value in headers];length=self.headers.get('Content-Length','0')
                if len(names)>32 or sum(len(k)+len(v) for k,v in headers)>16384 or len(names)!=len(set(names)) or any(re.search(r'[\x00-\x1f\x7f]',v) for k,v in headers) or 'transfer-encoding' in names or 'content-encoding' in names or not re.fullmatch(r'0|[1-9][0-9]{0,3}',length) or int(length)>8192:
                    self.send(400,b'{"error":"ingress.input"}',{'Content-Type':'application/json'});return
                body=self.rfile.read(int(length))
                with lock:
                    port=backend_ports[state['counter']%2];state['counter']+=1;mode=state['mode'];state['requests'].append((self.path,dict(headers),body))
                trace('http.forward',mode=mode)
                if mode=='redirect':self.send(302,headers={'Location':'https://receiver.example.com/forbidden-follow'});return
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
                try:
                    connection.putrequest(self.command,self.path,skip_host=True,skip_accept_encoding=True)
                    for name,value in headers:
                        if name.lower() not in ['connection','content-length','x-test-outbox-ingress']:connection.putheader(name,value)
                    connection.putheader('X-Test-Outbox-Ingress',secret);connection.putheader('Content-Length',length);connection.endheaders(body)
                    response=connection.getresponse();data=response.read(8193)
                    if len(data)>8192:raise RuntimeError('Private response exceeds its bound')
                    try:parsed=json.loads(data)
                    except ValueError:parsed={}
                    if not isinstance(parsed,dict):parsed={}
                    with lock:state['responses'].append({'status':response.status,'committed':parsed.get('committed') is True,'error':parsed.get('error'),'elapsed':round(time.monotonic()-began,6)})
                    trace('http.response',status=response.status,mode=mode)
                    if mode=='hold':held.set();release.wait(15)
                    if mode=='slow':time.sleep(1.1)
                    if mode=='drop':self.close_connection=True;self.connection.close();return
                    if mode=='malformed':data=b'{"committed":true}'
                    self.send(response.status,data,{k:v for k,v in response.getheaders() if k.lower() not in ['connection','transfer-encoding','content-length','server','date']})
                finally:connection.close()
        accepted=threading.Event()
        class Server(http.server.ThreadingHTTPServer):
            daemon_threads=True;allow_reuse_address=True
            def process_request(self,request,address):
                accepted.set();return super().process_request(request,address)
            def finish_request(self,request,address):
                # Handshake per connection: one incomplete TLS peer cannot block the accept loop.
                request.settimeout(5);trace('tls.begin')
                try:
                    with tls.wrap_socket(request,server_side=True) as secure:
                        trace('tls.ready');super().finish_request(secure,address)
                except (OSError,ssl.SSLError) as failure:
                    trace('tls.refused',error=type(failure).__name__);request.close()
        server=Server(('0.0.0.0',443),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        def cli(name,*arguments,success=True,configuration=sender_config,ca=True):
            command=[runtime]
            if ca:command+=['-d','curl.cainfo='+str(base/'ca.crt')]
            result=subprocess.run([*command,str(web/name),*arguments],env=dict(env,SOSECURITY_OUTBOX_EXAMPLE_CONFIG=str(configuration)),capture_output=True,text=True,timeout=15)
            if success:
                check(0,result.returncode);check('',result.stderr);return json.loads(result.stdout)
            check(1,result.returncode);check('',result.stdout);check(name.removesuffix('.php').replace('-','_')+'.unavailable\n',result.stderr)
        sequence=0
        def produce(reference=None,key=None,amount=500,success=True):
            nonlocal sequence
            sequence+=1;reference=reference or 'order-'+str(sequence);key=key or 'native-request-'+str(sequence).zfill(8)
            data=cli('outbox-producer.php','--key='+key,'--reference='+reference,'--amount='+str(amount),success=success)
            return data
        def worker(expected_failed=0,ca=True):
            began=time.monotonic()
            result=subprocess.run([runtime,*(['-d','curl.cainfo='+str(base/'ca.crt')] if ca else []),str(web/'outbox-worker.php'),'--once'],env=env,capture_output=True,text=True,timeout=15)
            if result.returncode!=(2 if expected_failed else 0):
                diagnostic={'runtime':runtime,'elapsed':time.monotonic()-began,'worker_exit':result.returncode,'sender':db.execute('SELECT status,attempts,last_error FROM sosecurity_outbox_records ORDER BY order_no').fetchall(),'receiver':recv.execute('SELECT status,attempt FROM sosecurity_webhook_processing').fetchall(),'responses':state['responses'][-5:],'network':state['network'][-20:]}
                print('DIAGNOSTIC '+json.dumps(diagnostic),flush=True)
            check(2 if expected_failed else 0,result.returncode);check('',result.stderr);data=json.loads(result.stdout);check(expected_failed,data['failed']);return data
        def record(event_id):return db.execute('SELECT delivery_id,status,attempts,manual_retries,lease_until FROM sosecurity_outbox_records WHERE message_id=?',(event_id,)).fetchone()
        def effect_count():return recv.execute('SELECT COALESCE(SUM(deliveries),0) FROM outbox_example_projection').fetchone()[0]
        def packet(event_id,body=None,delivery=None,stamp=None,signature=None,duplicates=None,path='/outbox-receiver.php'):
            if body is None or delivery is None:
                stored=db.execute('SELECT delivery_id,payload_body FROM sosecurity_outbox_records WHERE message_id=?',(event_id,)).fetchone()
                body=body if body is not None else bytes(stored[1]);delivery=delivery or stored[0]
            stamp=str(int(time.time()) if stamp is None else stamp)
            keys=json.loads(sender_wire.read_text());key=base64.b64decode(keys['keys'][keys['current']]);signature=signature or 'v1,'+base64.b64encode(hmac.digest(key,delivery.encode()+b'.'+stamp.encode()+b'.'+body,'sha256')).decode()
            conn=Connection()
            try:
                conn.putrequest('POST',path);conn.putheader('Content-Type','application/json');conn.putheader('Content-Length',str(len(body)));conn.putheader('Webhook-Id',delivery);conn.putheader('Webhook-Timestamp',stamp);conn.putheader('Webhook-Signature',signature)
                for k,v in duplicates or []:conn.putheader(k,v)
                conn.endheaders(body);response=conn.getresponse();raw=response.read(8193);check(None,response.getheader('Set-Cookie'));return response.status,json.loads(raw)
            finally:conn.close()
        try:
            idle=socket.create_connection(('8.8.8.8',443),timeout=2)
            try:
                check(True,accepted.wait(2))
                with client_tls.wrap_socket(socket.create_connection(('8.8.8.8',443),timeout=2),server_hostname='receiver.example.com') as secure:
                    secure.sendall(b'GET /outbox-receiver.php HTTP/1.0\r\nHost: receiver.example.com\r\n\r\n')
                    response=http.client.HTTPResponse(secure);response.begin();check(405,response.status);check(None,response.getheader('Set-Cookie'));response.read()
            finally:idle.close()
            # No automatic initialization, even with valid deployment keys and an enabled writer.
            produce('before-init',success=False);check(0,db.execute('SELECT COUNT(*) FROM outbox_example_orders').fetchone()[0])
            check({'queue_created':True,'writer_created':True},cli('outbox-admin.php','--initialize=alice'));check({'queue_created':False,'writer_created':False},cli('outbox-admin.php','--initialize=alice'))
            first=produce('first-order',key='stable-request-key-0001');event_id=first['result']['event_id'];delivery=record(event_id)[0]
            check(True,produce('first-order',key='stable-request-key-0001')['replayed']);check(first['result'],produce('first-order',key='stable-request-key-0002')['result']);check(1,db.execute('SELECT COUNT(*) FROM sosecurity_outbox_records').fetchone()[0])
            produce('first-order',key='stable-request-key-0001',amount=501,success=False);produce('first-order',amount=501,success=False)
            original=bytes(db.execute('SELECT payload FROM outbox_example_orders WHERE event_id=?',(event_id,)).fetchone()[0])
            check(1,worker()['sent']);check(('sent',1),record(event_id)[1:3]);check(1,effect_count());check(0,worker()['claimed'])
            status,data=packet(event_id,original);check(200,status);check({'committed':True,'delivery_id':delivery,'body_digest':hashlib.sha256(original).hexdigest()},data);check(1,effect_count())
            check(403,packet(event_id,original,stamp=int(time.time())-1000)[0]);check(403,packet(event_id,original,signature='v1,'+base64.b64encode(b'x'*32).decode())[0])
            altered=json.loads(original);altered['amount']=501;check(409,packet(event_id,json.dumps(altered,separators=(',',':')).encode())[0]);check(1,effect_count())
            check(400,packet(event_id,original,duplicates=[('webhook-timestamp',str(int(time.time())))])[0]);check(400,packet(event_id,original,duplicates=[('Webhook-Signature','ignored')])[0])
            # Clearing only receipt/processing history cannot repeat an independent committed business event.
            recv.execute('DELETE FROM sosecurity_webhook_processing');recv.execute('DELETE FROM sosecurity_webhook_inbox');recv.commit();check(200,packet(event_id,original)[0]);check(1,effect_count())
            # Concurrent actual TLS requests span two independent PHP receiver processes.
            parallel=produce('parallel-order')['result']['event_id']
            parallel_delivery,parallel_body=db.execute('SELECT delivery_id,payload_body FROM sosecurity_outbox_records WHERE message_id=?',(parallel,)).fetchone()
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:results=list(pool.map(lambda unused:packet(parallel,body=bytes(parallel_body),delivery=parallel_delivery),range(24)))
            check(True,all(status in [200,503] for status,data in results));check(True,any(status==200 for status,data in results));check(2,effect_count());check(1,worker()['sent']);check(2,effect_count())
            # Current association and sender roles remain live checks.
            denied=produce('disabled-owner')['result']['event_id'];receiver_authority.execute('UPDATE outbox_example_owners SET enabled=0');receiver_authority.commit();check(0,worker(expected_failed=1)['sent']);check('dead',record(denied)[1]);check(2,effect_count())
            receiver_authority.execute('UPDATE outbox_example_owners SET enabled=1');receiver_authority.commit();check({'retried':True},cli('outbox-admin.php','--retry='+denied));check(1,worker()['sent']);check(3,effect_count())
            sender_authority.execute('UPDATE outbox_example_actors SET enabled=0');sender_authority.commit();produce('revoked-writer',success=False);cli('outbox-worker.php','--once',success=False);cli('outbox-admin.php','--maintain',success=False);sender_authority.execute('UPDATE outbox_example_actors SET enabled=1');sender_authority.commit()
            # A committed receiver effect with a dropped TLS response is retried under the original delivery ID.
            lost=produce('lost-response')['result']['event_id'];stable=record(lost)[0];state['mode']='drop';check(1,worker(expected_failed=1)['failed']);check(4,effect_count());check('pending',record(lost)[1]);state['mode']='normal';time.sleep(1.05);check(1,worker()['sent']);check(stable,record(lost)[0]);check(4,effect_count())
            # Real worker SIGKILL while receiver confirmation is held, after both receiver SQL commits.
            killed=produce('killed-worker')['result']['event_id'];stable=record(killed)[0];state['mode']='hold';held.clear();release.clear()
            process=subprocess.Popen([runtime,'-d','curl.cainfo='+str(base/'ca.crt'),str(web/'outbox-worker.php'),'--once'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                check(True,held.wait(10));check(None,process.poll());check(5,effect_count());check('leased',record(killed)[1]);process.kill();process.communicate(timeout=5);check(-9,process.returncode)
            finally:
                if process.poll() is None:process.kill();process.communicate(timeout=5)
                release.set();state['mode']='normal'
            check(0,worker()['claimed']);until=record(killed)[4];time.sleep(max(0,until-time.time()+.05));check(1,worker()['sent']);check(stable,record(killed)[0]);check(5,effect_count());check(2,record(killed)[2])
            # Rejected TLS, redirects and malformed success never mark a message sent.
            badca=produce('untrusted-ca')['result']['event_id'];check(1,worker(expected_failed=1,ca=False)['failed']);check(5,effect_count());time.sleep(1.05);check(1,worker()['sent']);check(6,effect_count())
            redirected=produce('no-redirect')['result']['event_id'];state['mode']='redirect';check(1,worker(expected_failed=1)['failed']);check(6,effect_count());state['mode']='normal';time.sleep(1.05);check(1,worker()['sent']);check(7,effect_count());check(False,any(path=='/forbidden-follow' for path,headers,body in state['requests']))
            malformed=produce('malformed-confirmation')['result']['event_id'];state['mode']='malformed';check(1,worker(expected_failed=1)['failed']);check('pending',record(malformed)[1]);check(8,effect_count());state['mode']='normal';time.sleep(1.05);check(1,worker()['sent']);check(8,effect_count())
            # Rotation uses current delivery keys while retaining the same immutable payload and ID.
            rotated=produce('key-rotation')['result']['event_id'];stable=record(rotated)[0];new_wire={'current':'new','keys':dict(wire['keys'],new=base64.b64encode(os.urandom(32)).decode())};sender_wire.write_text(json.dumps(new_wire));receiver_wire.write_text(json.dumps(new_wire));check(1,worker()['sent']);check(stable,record(rotated)[0]);check(9,effect_count())
            # The compatible one-second profile still refuses a known late committed confirmation.
            late=produce('late-confirmation')['result']['event_id'];stable=record(late)[0];check(200,packet(late)[0]);check(10,effect_count());profile=json.loads(sender_config.read_text());profile['transport_budget_ms']=1000;sender_config.write_text(json.dumps(profile));state['mode']='slow';check(1,worker(expected_failed=1)['failed']);check('transport.timeout',db.execute('SELECT last_error FROM sosecurity_outbox_records WHERE message_id=?',(late,)).fetchone()[0]);check(10,effect_count());state['mode']='normal';profile['transport_budget_ms']=3000;sender_config.write_text(json.dumps(profile));time.sleep(1.05);check(1,worker()['sent']);check(stable,record(late)[0]);check(10,effect_count())
            backup=work/'receiver-before-last.sqlite';snapshot=sqlite3.connect(backup);recv.backup(snapshot);snapshot.close();backup.chmod(0o600)
            private=produce('private-dns-answer')['result']['event_id'];stable=record(private)[0];state['mode']='private-dns';check(1,worker(expected_failed=1)['failed']);check('transport.policy',db.execute('SELECT last_error FROM sosecurity_outbox_records WHERE message_id=?',(private,)).fetchone()[0]);check('dead',record(private)[1]);check(10,effect_count());state['mode']='normal';check({'retried':True},cli('outbox-admin.php','--retry='+private));check(1,worker()['sent']);check(stable,record(private)[0]);check(11,effect_count())
            for path,headers,body in state['requests']:
                check(False,any(name.lower() in ['authorization','cookie'] for name in headers))
            # Direct backend access and forged validation assertions cannot replace the private ingress capability.
            connection=http.client.HTTPConnection('127.0.0.1',backend_ports[0],timeout=5);connection.request('POST','/outbox-receiver.php',body=original,headers={'Host':'receiver.example.com','Content-Type':'application/json','Sosecurity-Outbox-Headers-Validated':'1','X-Test-Outbox-Ingress':'forged'});response=connection.getresponse();check(503,response.status);response.read();connection.close()
            for entry in ['outbox-worker.php','outbox-admin.php','outbox-producer.php','outbox-receiver-admin.php']:
                conn=Connection();conn.request('GET','/'+entry);response=conn.getresponse();check(404,response.status);response.read();conn.close()
            def receiver_admin(action,success=True):
                result=subprocess.run([runtime,str(web/'outbox-receiver-admin.php'),action],env=receiver_env,capture_output=True,text=True,timeout=10)
                check(0 if success else 1,result.returncode);check('' if success else 'outbox_receiver_admin.unavailable\n',result.stderr)
                if success:return json.loads(result.stdout)
                check('',result.stdout)
            # Restore the actual business database while its separate durable witness is retained.
            recv.close();replacement=receiver.with_suffix('.restore');shutil.copyfile(backup,replacement);replacement.chmod(0o600);os.replace(replacement,receiver);recv=sqlite3.connect(receiver)
            last_body=bytes(db.execute('SELECT payload FROM outbox_example_orders WHERE event_id=?',(private,)).fetchone()[0])
            check(10,effect_count());check(503,packet(private,last_body)[0]);check(10,effect_count());check({'recovered':True},receiver_admin('--recover'));check(11,effect_count())
            check(200,packet(private,last_body)[0]);check(11,effect_count());check({'recovered':False},receiver_admin('--recover'));check({'initialized':False},receiver_admin('--initialize'))
            checkpoint_status=receiver_admin('--status');check(11,checkpoint_status['entries']);check(stable,recv.execute('SELECT delivery_id FROM outbox_example_effects WHERE event_id=?',(private,)).fetchone()[0])
            config=json.loads(receiver_config.read_text());config['epoch']='f'*64;receiver_config.write_text(json.dumps(config))
            check(503,packet(private,last_body)[0]);receiver_admin('--rotate-epoch='+checkpoint_status['epoch']+':'+'0'*64,False)
            check({'rotated':True},receiver_admin('--rotate-epoch='+checkpoint_status['epoch']+':'+checkpoint_status['root_hash']));check(200,packet(private,last_body)[0]);check(11,effect_count())
            check(11,effect_count());check(11,db.execute('SELECT COUNT(*) FROM outbox_example_orders').fetchone()[0])
        finally:
            release.set();server.shutdown();server.server_close()
            for process in processes:
                if process.poll() is None:process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            log.close();db.close();recv.close()
            if args.authority:sender_authority.close();receiver_authority.close()
    print(f'PASS native Outbox TLS: {checks} assertions on {runtime}; authority={args.authority}; actual producer/receiver/worker, private DoH/pins/CA, 24 TLS requests, stable deduplication, dropped confirmation and real worker SIGKILL',flush=True)

for runtime in args.runtimes:run(runtime)
print('PASS native Outbox namespace: isolated databases, routes and per-process CA only; no host network/trust changes or external delivery',flush=True)
