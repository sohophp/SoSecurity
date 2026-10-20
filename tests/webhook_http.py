#!/usr/bin/env python3
"""Real raw HTTP/isolated TLS delivery, private SQLite receipt state and password/TOTP operator access."""
import argparse
import base64
import contextlib
import hashlib
import hmac
import http.client
import http.cookiejar
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
from credential_http import otp

root = Path(__file__).resolve().parent.parent
SCOPE = 'webhook-example'
ACCOUNT = 'publisher-example'
PASSWORD = 'Correct-webhook-test-password'
checks = 0


def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)


class Visitor:
    def __init__(self, url, ca=None):
        self.url, self.csrf = url, ''
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if ca:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
        self.client = urllib.request.build_opener(*handlers)

    def call(self, action=None, fields=None, csrf=None):
        body = None if action is None else urllib.parse.urlencode(dict(fields or {}, action=action, _csrf=self.csrf if csrf is None else csrf)).encode()
        request = urllib.request.Request(self.url, data=body, headers={'Accept': 'application/json'})
        try:
            response = self.client.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            data = json.loads(raw)
            self.csrf = data.get('csrf', self.csrf)
            for secret in [PASSWORD, 'soss_', '$2y$', 'PROVIDER-PRIVATE', 'PAYLOAD-PRIVATE']:
                check(False, secret in raw.decode())
            return response.status, data, response.headers

    def login(self, user='admin'):
        return self.call('login', {'username': user, 'password': PASSWORD})


@contextlib.contextmanager
def fixture(runtime, tls=False, web_storage=False, processing=False):
    with tempfile.TemporaryDirectory(prefix='sosecurity-webhook-http-') as directory:
        work = Path(directory); storage = work / 'state'; sessions = work / 'sessions'
        storage.mkdir(mode=0o700); sessions.mkdir(mode=0o700)
        web = root / 'examples'
        if web_storage:
            web = work / 'web'; web.mkdir(mode=0o700)
            storage.rmdir(); storage = web / 'state'; storage.mkdir(mode=0o700)
            (web / 'webhooks.php').write_text('<?php require '+json.dumps(str(root / 'examples/webhooks.php'))+';')
        def hashed(value):
            return subprocess.check_output([runtime, '-r', 'echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);', value], text=True)
        database = work / 'receive.sqlite'
        db = sqlite3.connect(database); database.chmod(0o600)
        db.executescript((root / 'resources/sql/webhook-sqlite.sql').read_text())
        if processing:
            db.executescript((root / 'resources/sql/webhook-processing-sqlite.sql').read_text())
            db.executescript((root / 'resources/sql/webhook-example-processing-sqlite.sql').read_text())
        db.execute('CREATE TABLE webhook_accounts(tenant TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,password_hash TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,roles TEXT NOT NULL,mfa_required INTEGER NOT NULL,PRIMARY KEY(tenant,subject),UNIQUE(tenant,username))')
        password = hashed(PASSWORD)
        db.executemany('INSERT INTO webhook_accounts VALUES(?,?,?,?,?,?,?,?)', [
            (SCOPE, 'admin', 'admin', password, '1', 1, '["admin"]', 1),
            (SCOPE, 'reader', 'reader', password, '1', 1, '["reader"]', 0),
            (SCOPE, 'weakadmin', 'weakadmin', password, '1', 1, '["admin"]', 0)])
        db.execute('CREATE TABLE webhook_documents(tenant TEXT NOT NULL,account TEXT NOT NULL,id TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,account,id))')
        db.executemany('INSERT INTO webhook_documents VALUES(?,?,?,?,?,?)', [
            (SCOPE, ACCOUNT, 'a', '1', 1, 'DOCUMENT-PRIVATE-A'),
            (SCOPE, ACCOUNT, 'disabled', '1', 0, 'DOCUMENT-PRIVATE-DISABLED'),
            ('other-tenant', ACCOUNT, 'other', '1', 1, 'DOCUMENT-PRIVATE-TENANT'),
            (SCOPE, 'other-provider', 'other', '1', 1, 'DOCUMENT-PRIVATE-PROVIDER')]); db.commit()
        def key_file(name):
            path = work / name
            config = {'current':'old', 'keys':{'old':base64.b64encode(os.urandom(32)).decode()}}
            def save():
                path.write_text(json.dumps(config)); path.chmod(0o600)
            save(); return config, path, save
        provider, provider_file, save_provider = key_file('provider.json')
        seals, seal_file, save_seals = key_file('seals.json')
        mfa, mfa_file, unused_save = key_file('mfa.json')
        # The test-only provisioning tool confirms a factor in a previous time step, without production credentials.
        # Its fixed key label is independent of the publisher and receipt seals.
        mfa_file.write_text(json.dumps({'current':'test','keys':{'test':mfa['keys']['old']}})); mfa_file.chmod(0o600)
        result = subprocess.run([runtime, str(root / 'tests/webhook-setup.php')], input=json.dumps({'directory':str(storage), 'key':mfa['keys']['old']}), text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        factor = json.loads(result.stdout)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        ca = None
        secret = os.urandom(32).hex()
        class Ingress(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass
            def request(self):
                # PHP 7.2's CLI SAPI can erase identical duplicate headers. Reject on the actual wire first.
                raw_headers=list(self.headers.raw_items());names=[name.lower() for name,value in raw_headers]
                length=self.headers.get('Content-Length','0')
                if len(names)!=len(set(names)) or 'transfer-encoding' in names or not length.isascii() or not length.isdigit() or len(length)>6 or int(length)>131072 or any('\r' in value or '\n' in value for name,value in raw_headers):
                    data=b'{"error":"webhook_example.input"}'
                    self.send_response(400);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
                headers=[(k,v) for k,v in raw_headers if k.lower() not in ['connection','content-length','x-test-webhook-ingress']]
                headers.append(('X-Test-Webhook-Ingress',secret))
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                try:
                    connection.putrequest(self.command,self.path,skip_host=True,skip_accept_encoding=True)
                    for name,value in headers:
                        connection.putheader(name,value)
                    connection.putheader('Content-Length',length);connection.endheaders(self.rfile.read(int(length)))
                    response=connection.getresponse();data=response.read(65537)
                    if len(data)>65536:
                        raise RuntimeError('Ingress response budget exceeded')
                    self.send_response(response.status)
                    for name,value in response.getheaders():
                        if name.lower() not in ['connection','transfer-encoding','content-length','server','date']:
                            self.send_header(name,value)
                    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                finally:
                    connection.close()
            do_GET=request;do_POST=request;do_PUT=request
        proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Ingress)
        if tls:
            ca,key=work/'cert.pem',work/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(ca),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],capture_output=True,check=True)
            key.chmod(0o600)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(ca),str(key));proxy.socket=context.wrap_socket(proxy.socket,server_side=True)
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        origin=f'https://localhost:{proxy.server_port}' if tls else f'http://127.0.0.1:{proxy.server_port}'
        env = {k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_WEBHOOK_EXAMPLE_')}
        env.update(SOSECURITY_WEBHOOK_EXAMPLE_ORIGIN=origin, SOSECURITY_WEBHOOK_EXAMPLE_STORAGE=str(storage),
                   SOSECURITY_WEBHOOK_EXAMPLE_DATABASE=str(database), SOSECURITY_WEBHOOK_EXAMPLE_PROVIDER_KEYS=str(provider_file),
                   SOSECURITY_WEBHOOK_EXAMPLE_SEAL_KEYS=str(seal_file), SOSECURITY_WEBHOOK_EXAMPLE_MFA_KEYS=str(mfa_file),
                   SOSECURITY_WEBHOOK_EXAMPLE_DUMMY_HASH=hashed('Dummy-webhook-test-password'),
                   SOSECURITY_WEBHOOK_EXAMPLE_HTTPS='1' if tls else '0', SOSECURITY_TEST_WEBHOOK_INGRESS=secret)
        if processing:
            env.update(SOSECURITY_WEBHOOK_EXAMPLE_PROCESSING='1',SOSECURITY_WEBHOOK_EXAMPLE_WORKER='private-cli-worker',SOSECURITY_WEBHOOK_EXAMPLE_DOCUMENT_ROOT=str(web))
        router = work / 'router.php'
        router.write_text('<?php if(($_SERVER["REMOTE_ADDR"]??"")==="127.0.0.1"&&hash_equals(getenv("SOSECURITY_TEST_WEBHOOK_INGRESS"),$_SERVER["HTTP_X_TEST_WEBHOOK_INGRESS"]??"")){$_SERVER["SOSECURITY_WEBHOOK_HEADERS_VALIDATED"]="1";if(getenv("SOSECURITY_WEBHOOK_EXAMPLE_HTTPS")==="1"){$_SERVER["HTTPS"]="on";}}require '+json.dumps(str(root / 'examples/webhooks.php'))+';')
        if processing:
            router.write_text('<?php if(($_SERVER["REQUEST_URI"]??"")==="/webhook-worker.php"){require '+json.dumps(str(root/'examples/webhook-worker.php'))+';return;} ?>'+router.read_text())
        with (work / 'server.log').open('w+') as log:
            server = subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(web)] + [str(router)], env=env, stdout=log, stderr=log)
            try:
                for unused in range(100):
                    if server.poll() is not None:
                        log.seek(0); raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('Webhook server startup timeout')
                yield dict(work=work, db=db, database=database, sessions=sessions, url=origin+'/webhooks.php', ca=ca,
                           provider=provider, provider_file=provider_file, save_provider=save_provider,
                           seals=seals, seal_file=seal_file, save_seals=save_seals, factor=factor, env=env,
                           backend=f'http://127.0.0.1:{port}/webhooks.php')
                log.flush(); log.seek(0); messages = log.read()
                for warning in ['PHP Warning:', 'PHP Fatal error:', 'PHP Deprecated:']:
                    check(False, warning in messages)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill(); server.wait()
                if proxy:
                    proxy.shutdown(); proxy.server_close()
                db.close()


def payload(identifier='event-1', **fields):
    return json.dumps(dict(id=identifier, type='document.changed', resource='a', version='1', tenant=SCOPE, account=ACCOUNT, **fields), ensure_ascii=False, separators=(',',':')).encode()


def deliver(f, body=None, identifier='event-1', timestamp=None, key=None, headers=None, method='POST', url=None, cookie=None):
    body = payload(identifier) if body is None else body
    timestamp = int(time.time()) if timestamp is None else timestamp
    key = base64.b64decode(f['provider']['keys'][f['provider']['current']]) if key is None else key
    signature = base64.b64encode(hmac.new(key, identifier.encode()+b'.'+str(timestamp).encode()+b'.'+body, hashlib.sha256).digest()).decode()
    values = {'Content-Type':'application/json', 'Accept':'application/json', 'Webhook-Id':identifier, 'Webhook-Timestamp':str(timestamp), 'Webhook-Signature':'v1,'+signature}
    if cookie:
        values['Cookie'] = cookie
    values.update(headers or {})
    request = urllib.request.Request(url or f['url']+'?receive=1',data=body,method=method,headers=values)
    client = urllib.request.build_opener(*([urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(f['ca'])))] if f['ca'] else []))
    try:
        response = client.open(request,timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(); data = json.loads(raw)
        check('no-store, private', response.headers['Cache-Control']); check('no-referrer', response.headers['Referrer-Policy']); check('nosniff', response.headers['X-Content-Type-Options'])
        check(None, response.headers.get('Set-Cookie'))
        for secret in [PASSWORD, 'PAYLOAD-PRIVATE', 'DOCUMENT-PRIVATE', 'descriptor', 'seal_key', 'body_digest']:
            check(False,secret in raw.decode())
        return response.status, data, response.headers


def run(runtime, tls=False, browser=False):
    with fixture(runtime,tls) as f:
        db = f['db']; count = lambda: db.execute('SELECT COUNT(*) FROM sosecurity_webhook_inbox').fetchone()[0]
        documents = db.execute('SELECT * FROM webhook_documents ORDER BY tenant,account,id').fetchall()
        status,data,unused = deliver(f); check(200,status); check(False,data['duplicate']); receipt = data['receipt_id']
        check(1,count()); check([],list(f['sessions'].iterdir()))
        check(payload(),db.execute('SELECT payload FROM sosecurity_webhook_inbox').fetchone()[0])
        status,data,unused = deliver(f,timestamp=int(time.time())+1); check(200,status); check(True,data['duplicate']); check(receipt,data['receipt_id'])
        if browser:
            check(200,deliver(f,identifier='<script>alert(1)</script>')[0])
            env = dict(f['env'],SOSECURITY_TEST_WEBHOOK_PASSWORD=PASSWORD,SOSECURITY_TEST_WEBHOOK_OTP_URI=f['factor']['uri'])
            subprocess.run(['node',str(root/'tests/webhook-browser.cjs'),f['url']],env=env,check=True)
            check(documents,db.execute('SELECT * FROM webhook_documents ORDER BY tenant,account,id').fetchall())
            return
        # Invalid sources, protocol substitutions, raw-body mutation and business associations never allocate receipt state.
        cases = [dict(key=os.urandom(32)), dict(timestamp=int(time.time())-1000), dict(timestamp=int(time.time())+200),
                 dict(headers={'Webhook-Signature':'v1,'+base64.b64encode(bytes(32)).decode()}),
                 dict(headers={'Webhook-Timestamp':'0001'}), dict(headers={'Webhook-Id':'different'}),
                 dict(headers={'Webhook-Signature':'v1a,'+base64.b64encode(bytes(64)).decode()}),
                 dict(body=payload('mismatch')), dict(body=b'not-json'), dict(body=b'[]')]
        for changes in [{'tenant':'other-tenant'}, {'account':'other-provider'}, {'resource':'disabled'}, {'resource':'other'}, {'version':'2'}, {'type':'unknown'}, {'extra':'PAYLOAD-PRIVATE'}]:
            value = json.loads(payload()); value.update(changes); cases.append(dict(body=json.dumps(value).encode()))
        for options in cases:
            status,unused,unused_headers = deliver(f,**options); check(403,status); check(1,count())
        # Preserve real repeated wire headers across the test TLS bridge; never normalize away an ambiguity.
        for duplicate_name in ['Webhook-Timestamp','webhook-timestamp']:
            target=urllib.parse.urlsplit(f['url']);stamp=str(int(time.time()));body=payload()
            key=base64.b64decode(f['provider']['keys'][f['provider']['current']])
            signature='v1,'+base64.b64encode(hmac.new(key,b'event-1.'+stamp.encode()+b'.'+body,hashlib.sha256).digest()).decode()
            connection=http.client.HTTPSConnection(target.hostname,target.port,context=ssl.create_default_context(cafile=str(f['ca'])),timeout=15) if tls else http.client.HTTPConnection(target.hostname,target.port,timeout=15)
            try:
                connection.putrequest('POST',target.path+'?receive=1');connection.putheader('Content-Type','application/json');connection.putheader('Accept','application/json');connection.putheader('Content-Length',str(len(body)));connection.putheader('Webhook-Id','event-1');connection.putheader('Webhook-Timestamp',stamp);connection.putheader(duplicate_name,stamp);connection.putheader('Webhook-Signature',signature);connection.endheaders(body)
                response=connection.getresponse();check(True,response.status in [400,403]);check({'error':'webhook_example.input' if response.status==400 else 'webhook_example.denied'},json.loads(response.read()));check(1,count())
            finally:
                connection.close()
        # Same signed event identity with different bytes is a conflict, even semantically equivalent JSON.
        status,unused,unused_headers = deliver(f,body=payload()+b'\n'); check(409,status); check(1,count())
        for options in [dict(headers={'Content-Type':'text/plain'}),dict(headers={'Content-Encoding':'gzip'}),dict(body=b'x'*65537),dict(url=f['url']+'?receive=1&receive=1'),dict(url=f['url']+'?receive=%31')]:
            status,unused,unused_headers = deliver(f,**options); check(400,status); check(1,count())
        check(405,deliver(f,method='PUT')[0])
        check(503,deliver(f,headers={'Host':'attacker.invalid'})[0])
        check(503,deliver(f,url=f['backend']+'?receive=1',headers={'Host':urllib.parse.urlsplit(f['url']).netloc,'X-Forwarded-Proto':'https','SoSecurity-Webhook-Headers-Validated':'1','X-Test-Webhook-Ingress':'forged'})[0])
        # Current key snapshots are loaded from the private file on each request, independent of receipt seals.
        original_key = base64.b64decode(f['provider']['keys']['old'])
        f['provider']['keys']['new'] = base64.b64encode(os.urandom(32)).decode(); f['provider']['current']='new'; f['save_provider']()
        check(200,deliver(f)[0]); del f['provider']['keys']['old']; f['save_provider']()
        check(403,deliver(f,key=original_key)[0]); check(200,deliver(f)[0]); check(1,count())
        # Cross-purpose key reuse is rejected before receiving a new event.
        separate = dict(f['provider']['keys']); f['provider']['keys']['new']=f['seals']['keys']['old']; f['save_provider']()
        check(503,deliver(f,identifier='key-reuse')[0]); check(1,count())
        f['provider']['keys']=separate; f['save_provider']()
        # Stored payload corruption and an absent sealing key never silently reset or overwrite state.
        db.execute('UPDATE sosecurity_webhook_inbox SET payload=?',(b'x'*len(payload()),)); db.commit()
        check(503,deliver(f)[0]); check(1,count())
        db.execute('UPDATE sosecurity_webhook_inbox SET payload=?',(payload(),)); db.commit()
        check(200,deliver(f)[0])
        # A real held SQLite writer lock causes a bounded operational failure, then the unchanged event can be retried.
        db.execute('BEGIN IMMEDIATE')
        start=time.monotonic()
        try:
            check(503,deliver(f)[0]); check(True,time.monotonic()-start<5)
        finally:
            db.rollback()
        check(200,deliver(f)[0]); check(1,count())
        # Preload inert capacity occupancy; this exercises the host guard, not verified source provenance for these rows.
        template=db.execute('SELECT * FROM sosecurity_webhook_inbox').fetchone()
        columns=[d[0] for d in db.execute('SELECT * FROM sosecurity_webhook_inbox LIMIT 0').description]
        event_index=columns.index('event_key')
        occupancy=[]
        for number in range(999):
            row=list(template);row[event_index]=hashlib.sha256(('occupancy-'+str(number)).encode()).hexdigest();occupancy.append(row)
        db.executemany('INSERT INTO sosecurity_webhook_inbox VALUES('+','.join('?' for unused in columns)+')',occupancy);db.commit()
        check(1000,count());check(503,deliver(f,identifier='capacity-new')[0]);check(1000,count())
        check(200,deliver(f)[0]);check(1000,count())
        db.execute('DELETE FROM sosecurity_webhook_inbox WHERE event_key<>?',(template[event_index],));db.commit();check(1,count())
        saved_seal=dict(f['seals']['keys']); f['seals']['keys']['old']=base64.b64encode(os.urandom(32)).decode(); f['save_seals']()
        check(503,deliver(f)[0]); check(1,count()); f['seals']['keys']=saved_seal; f['save_seals']()
        check(200,deliver(f)[0])
        # Actual business authority changes are observed independently of cryptographic validity.
        db.execute('UPDATE webhook_documents SET enabled=0 WHERE tenant=? AND account=? AND id=?',(SCOPE,ACCOUNT,'a')); db.commit()
        check(403,deliver(f)[0]); check(1,count())
        db.execute('UPDATE webhook_documents SET enabled=1 WHERE tenant=? AND account=? AND id=?',(SCOPE,ACCOUNT,'a')); db.commit()
        # A signed request with a session Cookie still needs its own signature; anonymous deliveries create no sessions.
        v = Visitor(f['url'],f['ca']); check(200,v.call()[0]); check(403,v.call('login',{'username':'admin','password':PASSWORD},csrf='wrong')[0])
        check(200,v.call()[0]); status,data,headers=v.login(); check(200,status); check('mfa_required',data['stage']); check(False,'receipts' in data)
        pending = data['flow_id']; check(403,v.call('second_factor',{'flow_id':'wrong','code':'000000'})[0])
        v.call(); status,data,headers=v.call('second_factor',{'flow_id':pending,'code':otp(f['factor']['uri'])}); check(200,status); check('authenticated',data['stage']); check(1,len(data['receipts'])); check(receipt,data['receipts'][0]['receipt_id'])
        cookie='; '.join(c.name+'='+c.value for c in v.jar)
        check(403,deliver(f,cookie=cookie,key=os.urandom(32))[0]); check(200,deliver(f,cookie=cookie)[0])
        # An ordinary role and an admin password without the second factor cannot inspect receipts.
        for user in ['reader','weakadmin']:
            denied=Visitor(f['url'],f['ca']); denied.call(); status,data,headers=denied.login(user); check(403,status); check(False,'receipts' in data)
        # Current role/version withdrawal invalidates access on the next HTTP request.
        db.execute('UPDATE webhook_accounts SET roles=? WHERE subject=?',('["reader"]','admin')); db.commit()
        status,data,headers=v.call(); check(200,status); check('anonymous',data['stage']); check(False,'receipts' in data)
        check(documents,db.execute('SELECT * FROM webhook_documents ORDER BY tenant,account,id').fetchall())
        # A missing schema is an operational error, never an invitation for request-time DDL.
        db.execute('DROP TABLE sosecurity_webhook_inbox'); db.commit(); check(503,deliver(f,identifier='missing-schema')[0])
        check(None,db.execute("SELECT name FROM sqlite_master WHERE name='sosecurity_webhook_inbox'").fetchone())
    with fixture(runtime,tls,web_storage=True) as f:
        check(503,deliver(f)[0]); check(0,f['db'].execute('SELECT COUNT(*) FROM sosecurity_webhook_inbox').fetchone()[0])


if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('php',nargs='?',default='php'); parser.add_argument('--tls',action='store_true'); parser.add_argument('--browser',action='store_true'); args=parser.parse_args()
    run(args.php,args.tls,args.browser)
    print(f'PASS native webhook {"TLS" if args.tls else "HTTP"}: {checks} assertions; actual raw signed delivery, SQLite duplicate/conflict/integrity, current business/key authority and independent password/TOTP operator access; no provider network or business execution')
