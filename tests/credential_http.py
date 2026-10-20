#!/usr/bin/env python3
"""Native password/TOTP management and independent Bearer reads/writes; private SQLite + FileStore."""
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
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parent.parent
SCOPE = 'credential-example'
PASSWORD = 'Correct-credential-test-password'
checks = 0


def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)


def otp(uri):
    seed = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)['secret'][0]
    key = base64.b32decode(seed + '=' * ((-len(seed)) % 8))
    # Provisioning ran with an isolated clock 90 seconds earlier; HTTP verification uses actual current time.
    mac = hmac.new(key, struct.pack('!Q', int(time.time()) // 30), hashlib.sha1).digest()
    offset = mac[-1] & 15
    return str((struct.unpack('!I', mac[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


class Visitor:
    def __init__(self, url, ca=None):
        self.url, self.csrf = url, ''
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if ca:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
        self.client = urllib.request.build_opener(*handlers)

    def call(self, action=None, fields=None, csrf=None, url=None, method=None, headers=None, body=None):
        if action is not None:
            body = urllib.parse.urlencode(dict(fields or {}, action=action, _csrf=self.csrf if csrf is None else csrf), doseq=True).encode()
        request = urllib.request.Request(url or self.url, data=body, method=method,
                                         headers=dict({'Accept': 'application/json'}, **(headers or {})))
        try:
            response = self.client.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            check('no-store, private', response.headers['Cache-Control'])
            check('no-referrer', response.headers['Referrer-Policy'])
            check('nosniff', response.headers['X-Content-Type-Options'])
            data = json.loads(raw) if response.headers.get_content_type() == 'application/json' else raw
            if isinstance(data, dict):
                self.csrf = data.get('csrf', self.csrf)
                for secret in [PASSWORD, '$2y$', 'soss_']:
                    check(False, secret in raw.decode())
            return response.status, data, response.headers

    def login(self, username='demo'):
        return self.call('login', {'username': username, 'password': PASSWORD})

    def issue(self, scopes=None, name='部署工具 <script>alert(1)</script>'):
        status, data, headers = self.call('issue', {'name': name, 'scopes[]': scopes or ['documents:read']})
        check(200, status)
        return data['issued_token'], data['issued']

    def api(self, token=None, document='a', title=None, version=None, cookie=False):
        client = self if cookie else Visitor(self.url, getattr(self, 'ca', None))
        headers = {} if token is None else {'Authorization': 'Bearer ' + token}
        body = None
        if title is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps({'title': title, 'version': version}).encode()
        return client.call(url=self.url.split('?')[0] + '?api=document&document_id=' + document, headers=headers, body=body)


@contextlib.contextmanager
def fixture(runtime, tls=False, web_storage=False, ttl=None):
    with tempfile.TemporaryDirectory(prefix='sosecurity-credential-http-') as directory:
        work = Path(directory)
        storage, sessions = work / 'state', work / 'sessions'
        storage.mkdir(mode=0o700); sessions.mkdir(mode=0o700)
        web = root / 'examples'
        if web_storage:
            web = work / 'web'; web.mkdir(mode=0o700)
            storage.rmdir(); storage = web / 'state'; storage.mkdir(mode=0o700)
            (web / 'api-credentials.php').write_text('<?php require ' + json.dumps(str(root / 'examples/api-credentials.php')) + ';')
        def hashed(value):
            return subprocess.check_output([runtime, '-r', 'echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);', value], text=True)
        saved_hash = hashed(PASSWORD)
        database = work / 'credentials.sqlite'
        db = sqlite3.connect(database); database.chmod(0o600)
        db.execute('CREATE TABLE credential_accounts(tenant TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,password_hash TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,roles TEXT NOT NULL,mfa_required INTEGER NOT NULL,kind TEXT NOT NULL,PRIMARY KEY(tenant,subject),UNIQUE(tenant,username))')
        db.executemany('INSERT INTO credential_accounts VALUES(?,?,?,?,?,?,?,?,?)', [
            (SCOPE, 'alice', 'demo', saved_hash, '1', 1, '["editor"]', 0, 'user'),
            (SCOPE, 'bob', 'other', saved_hash, '1', 1, '["editor"]', 0, 'user'),
            (SCOPE, 'admin', 'admin', saved_hash, '1', 1, '["admin"]', 1, 'user'),
            (SCOPE, 'service', 'service', saved_hash, '1', 1, '["reader"]', 0, 'service')])
        db.execute('CREATE TABLE credential_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,id))')
        db.executemany('INSERT INTO credential_documents VALUES(?,?,?,?,?,?)', [
            (SCOPE, 'a', 'alice', '1', 'Original', 'ALICE-PRIVATE-BODY'),
            (SCOPE, 'b', 'bob', '1', 'Other', 'BOB-PRIVATE-BODY'),
            (SCOPE, 's', 'service', '1', 'Service', 'SERVICE-PRIVATE-BODY'),
            ('another-tenant', 'a', 'alice', '1', 'Tenant', 'OTHER-TENANT-PRIVATE')]); db.commit()
        keys = {'current': 'old', 'keys': {'old': base64.b64encode(os.urandom(32)).decode()}}
        keyfile = work / 'keys.json'
        def save_keys():
            keyfile.write_text(json.dumps(keys)); keyfile.chmod(0o600)
        save_keys()
        mfa_key = base64.b64encode(os.urandom(32)).decode()
        mfa_file = work / 'mfa.json'
        mfa_file.write_text(json.dumps({'current': 'test', 'keys': {'test': mfa_key}})); mfa_file.chmod(0o600)
        result = subprocess.run([runtime, str(root / 'tests/credential-setup.php')],
                                input=json.dumps({'directory': str(storage), 'key': mfa_key}), text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        factor = json.loads(result.stdout)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        proxy, ca = None, None
        origin = f'http://127.0.0.1:{port}'
        secret = os.urandom(32).hex()
        if tls:
            ca, key = work / 'cert.pem', work / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(key), '-out', str(ca), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], capture_output=True, check=True)
            key.chmod(0o600)
            class Proxy(http.server.BaseHTTPRequestHandler):
                def log_message(self, *unused):
                    pass
                def request(self):
                    length = int(self.headers.get('Content-Length', '0'))
                    if length < 0 or length > 16384:
                        self.send_error(413); return
                    headers = {k: v for k, v in self.headers.items() if k.lower() not in ['connection', 'transfer-encoding', 'content-length', 'x-test-credential-tls']}
                    headers['X-Test-Credential-Tls'] = secret
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                    try:
                        connection.request(self.command, self.path, self.rfile.read(length), headers)
                        response = connection.getresponse(); data = response.read(65537)
                        if len(data) > 65536:
                            raise RuntimeError('TLS response budget exceeded')
                        self.send_response(response.status)
                        for name, value in response.getheaders():
                            if name.lower() not in ['connection', 'transfer-encoding', 'content-length', 'server', 'date']:
                                self.send_header(name, value)
                        self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
                    finally:
                        connection.close()
                do_GET = request; do_POST = request; do_PUT = request
            proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(ca), str(key)); proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            origin = f'https://localhost:{proxy.server_port}'
        env = {k: v for k, v in os.environ.items() if not k.startswith('SOSECURITY_CREDENTIAL_EXAMPLE_')}
        env.update(SOSECURITY_CREDENTIAL_EXAMPLE_DATABASE=str(database), SOSECURITY_CREDENTIAL_EXAMPLE_STORAGE=str(storage),
                   SOSECURITY_CREDENTIAL_EXAMPLE_KEYS=str(keyfile), SOSECURITY_CREDENTIAL_EXAMPLE_MFA_KEYS=str(mfa_file),
                   SOSECURITY_CREDENTIAL_EXAMPLE_ORIGIN=origin, SOSECURITY_CREDENTIAL_EXAMPLE_DUMMY_HASH=hashed('Dummy-credential-test-password'),
                   SOSECURITY_CREDENTIAL_EXAMPLE_HTTPS='1' if tls else '0', SOSECURITY_TEST_CREDENTIAL_TLS=secret)
        if ttl is not None:
            env['SOSECURITY_CREDENTIAL_EXAMPLE_TTL'] = str(ttl)
        router = work / 'router.php'
        router.write_text('<?php if(($_SERVER["REMOTE_ADDR"]??"")==="127.0.0.1"&&hash_equals(getenv("SOSECURITY_TEST_CREDENTIAL_TLS"),$_SERVER["HTTP_X_TEST_CREDENTIAL_TLS"]??"")){$_SERVER["HTTPS"]="on";}require ' + json.dumps(str(root / 'examples/api-credentials.php')) + ';')
        with (work / 'server.log').open('w+') as log:
            server = subprocess.Popen([runtime, '-d', 'session.save_path=' + str(sessions), '-S', f'127.0.0.1:{port}', '-t', str(web)] + ([str(router)] if tls else []), env=env, stdout=log, stderr=log)
            try:
                for unused in range(100):
                    if server.poll() is not None:
                        log.seek(0); raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('Credential server startup timeout')
                yield dict(work=work, db=db, database=database, state=storage, sessions=sessions,
                           url=origin + '/api-credentials.php', origin=origin, ca=ca, factor=factor,
                           keys=keys, keyfile=keyfile, save_keys=save_keys, env=env,
                           backend=f'http://127.0.0.1:{port}/api-credentials.php')
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


def run(runtime, tls=False, browser=False):
    sodium = subprocess.run([runtime, '-r', 'exit(extension_loaded("sodium") ? 0 : 1);'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not sodium:
        if os.getenv('SOSECURITY_REQUIRE_CRYPTO') == '1':
            raise RuntimeError('Required ext-sodium missing for native API credential HTTP')
        print('NOT RUN native API credential HTTP/TLS: ext-sodium required')
        return
    if browser:
        with fixture(runtime, tls) as f:
            env = dict(f['env'], SOSECURITY_TEST_CREDENTIAL_PASSWORD=PASSWORD,
                       SOSECURITY_TEST_CREDENTIAL_OTP_URI=f['factor']['uri'])
            subprocess.run(['node', str(root / 'tests/credential-browser.cjs'), f['url']], env=env, check=True)
            check('Original', f['db'].execute('SELECT title FROM credential_documents WHERE tenant=? AND id=?', (SCOPE, 'a')).fetchone()[0])
        return
    with fixture(runtime, tls) as f:
        db = f['db']
        def visitor():
            v = Visitor(f['url'], f['ca']); v.ca = f['ca']; return v
        def snapshot():
            return db.execute('SELECT * FROM credential_documents ORDER BY tenant,id').fetchall()
        before = snapshot()
        v = visitor(); status, data, headers = v.call(); check(200, status); check('anonymous', data['stage'])
        cookie = ';'.join(headers.get_all('Set-Cookie', [])); check(True, 'HttpOnly' in cookie); check(True, 'SameSite=Lax' in cookie)
        if tls:
            check(True, 'Secure' in cookie)
        check(403, v.call('issue', {'name': 'Forbidden', 'scopes[]': ['documents:read']})[0])
        check(403, v.call('login', {'username': 'demo', 'password': PASSWORD}, csrf='wrong')[0])
        check(405, v.call(method='PUT')[0]); old_csrf = v.csrf
        old_sid = next(iter(v.jar)).value
        check('authenticated', v.login()[1]['stage']); check(False, old_sid == next(iter(v.jar)).value)
        check(403, v.call('issue', {'name': 'Stale', 'scopes[]': ['documents:read']}, csrf=old_csrf)[0])
        token, metadata = v.issue(['documents:write', 'documents:read'])
        check(1, metadata['generation']); check(['documents:read', 'documents:write'], metadata['scopes'])
        status, listing, unused = v.call(); check(200, status); check(1, len(listing['credentials'])); check(False, token in json.dumps(listing))
        check(403, v.api(cookie=True)[0]); check(403, v.api('invalid', cookie=True)[0])
        status, document, headers = v.api(token); check(200, status); check('ALICE-PRIVATE-BODY', document['document']['body'])
        check(None, headers.get('Set-Cookie')); check(403, v.api(token, 'b')[0]); check(403, v.api(token, 'missing')[0])
        check(before, snapshot())
        status, updated, unused = v.api(token, title='Updated <script>alert(1)</script>', version=document['version']); check(200, status); check(True, updated['updated'])
        check(400, v.api(token, title='Stale write', version=document['version'])[0]); check('Updated <script>alert(1)</script>', v.api(token)[1]['document']['title'])
        other = visitor(); other.call(); check('authenticated', other.login('other')[1]['stage'])
        check(False, other.call('revoke', {'id': metadata['id'], 'generation': '1'})[1]['revoked'])
        check(403, other.call(url=f['url'] + '?owner=alice')[0])
        check(400, v.call('issue', {'name': 'Injected', 'scopes[]': ['documents:read'], 'owner': 'bob'})[0])
        status, rotated, unused = v.call('rotate', {'id': metadata['id'], 'generation': '1'}); check(200, status)
        replacement = rotated['issued_token']; check(2, rotated['issued']['generation']); check(403, v.api(token)[0]); check(200, v.api(replacement)[0])
        check(409, v.call('rotate', {'id': metadata['id'], 'generation': '1'})[0]); check(200, v.api(replacement)[0])
        status, reduced, unused = v.call('replace', {'id': metadata['id'], 'generation': '2', 'name': 'Read only', 'scopes[]': ['documents:read']}); check(200, status)
        token = reduced['issued_token']; check(3, reduced['issued']['generation']); check(metadata['expires_at'], reduced['issued']['expires_at'])
        check(403, v.api(replacement)[0]); check(200, v.api(token)[0]); check(403, v.api(token, title='Scope bypass', version=updated['version'])[0])
        check('anonymous', v.call('logout')[1]['stage']); check(200, v.api(token)[0]); v.call(); v.login()
        check(True, v.call('revoke', {'id': metadata['id'], 'generation': '3'})[1]['revoked']); check(403, v.api(token)[0])
        token, unused = v.issue(['documents:read','documents:write']); f['keys']['keys']['new'] = base64.b64encode(os.urandom(32)).decode(); f['keys']['current'] = 'new'; f['save_keys']()
        check(200, v.api(token)[0]); rotated = v.call('rotate', {'id': unused['id'], 'generation': '1'})[1]; token = rotated['issued_token']; check('new', rotated['issued']['key_id'])
        f['keys']['keys'].pop('old'); f['save_keys'](); check(200, v.api(token)[0])
        # Transient dependency failures deny this request without destroying a valid credential.
        f['keyfile'].write_text('{broken'); check(503, v.api(token)[0]); f['save_keys'](); check(200, v.api(token)[0])
        db.execute('ALTER TABLE credential_documents RENAME TO offline_documents'); db.commit(); check(503, v.api(token)[0])
        db.execute('ALTER TABLE offline_documents RENAME TO credential_documents'); db.commit(); check(200, v.api(token)[0])
        db.execute('UPDATE credential_documents SET body=? WHERE tenant=? AND id=?', ('x' * 8193, SCOPE, 'a')); db.commit(); check(403, v.api(token)[0])
        db.execute('UPDATE credential_documents SET body=? WHERE tenant=? AND id=?', ('ALICE-PRIVATE-BODY', SCOPE, 'a')); db.commit()
        before_invalid = snapshot()
        api_url = f['url'] + '?api=document&document_id=a'
        for body in [b'{broken', b'{"title":"bad","version":"1","owner":"bob"}', b'x' * 8193]:
            check(400, v.call(url=api_url, body=body, headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})[0])
        check(before_invalid, snapshot())
        check(1, v.call('revoke_all')[1]['revoked_count']); check(403, v.api(token)[0])
        # Real TOTP administrator can delegate to a noninteractive service account.
        admin = visitor(); admin.call(); status, pending, unused = admin.login('admin'); check(200, status); check('mfa_required', pending['stage'])
        check(403, admin.call('second_factor', {'flow_id': 'stale', 'code': otp(f['factor']['uri'])})[0])
        status, strong, unused = admin.call('second_factor', {'flow_id': pending['flow_id'], 'code': otp(f['factor']['uri'])}); check(200, status); check('authenticated', strong['stage'])
        admin.url = f['url'] + '?owner=service'; check(200, admin.call()[0])
        check(403, admin.call('issue', {'name': 'Excess', 'scopes[]': ['documents:write']})[0])
        service_token, service_metadata = admin.issue(); check('admin', admin.call()[1]['operator']); check(200, admin.api(service_token, 's')[0]); check(403, admin.api(service_token, 'a')[0])
        service = visitor(); service.call(); check(401, service.login('service')[0])
        normal = visitor(); normal.call(); normal.login(); normal.url += '?owner=service'; check(403, normal.call()[0])
        # Changing operator authority removes management access; the target credential remains independently active.
        db.execute('UPDATE credential_accounts SET roles=?,version=? WHERE tenant=? AND subject=?', ('["reader"]', '2', SCOPE, 'admin')); db.commit()
        check(403, admin.call('revoke', {'id': service_metadata['id'], 'generation': '1'})[0]); check(200, v.api(service_token, 's')[0])
        db.execute('UPDATE credential_accounts SET enabled=0 WHERE tenant=? AND subject=?', (SCOPE, 'service')); db.commit()
        check(403, v.api(service_token, 's')[0]); db.execute('UPDATE credential_accounts SET enabled=1 WHERE tenant=? AND subject=?', (SCOPE, 'service')); db.commit(); check(403, v.api(service_token, 's')[0])
        # Definitive owner identity changes revoke old credentials, even after restoring the original saved row.
        token, unused = v.issue(); row = db.execute('SELECT password_hash,roles,version FROM credential_accounts WHERE tenant=? AND subject=?', (SCOPE, 'alice')).fetchone()
        db.execute('UPDATE credential_accounts SET roles=? WHERE tenant=? AND subject=?', ('["reader"]', SCOPE, 'alice')); db.commit(); check(403, v.api(token)[0])
        db.execute('UPDATE credential_accounts SET roles=? WHERE tenant=? AND subject=?', (row[1], SCOPE, 'alice')); db.commit(); check(403, v.api(token)[0])
        # The actual web root is used for private-state rejection.
        check(400, v.call(url=f['url'] + '?owner=alice&owner=bob')[0])
        check(400, v.call(url=f['url'] + '?api=document&document_id=a&document_id=b')[0])
        check(503, v.call(headers={'Host': 'attacker.invalid'})[0])
        if tls:
            direct = Visitor(f['backend']); check(503, direct.call(headers={'Host': urllib.parse.urlsplit(f['origin']).netloc, 'X-Forwarded-Proto': 'https'})[0])
    with fixture(runtime, tls, web_storage=True) as f:
        check(503, Visitor(f['url'], f['ca']).call()[0])
    with fixture(runtime, tls, ttl=2) as f:
        short = Visitor(f['url'], f['ca']); short.ca = f['ca']; short.call(); short.login(); token, metadata = short.issue()
        check(200, short.api(token)[0]); time.sleep(max(0, metadata['expires_at'] - time.time()) + .1)
        check(403, short.api(token)[0]); check([], short.call()[1]['credentials'])
    print(f'PASS native API credential {"TLS" if tls else "HTTP"}: {checks} checks on {runtime}; actual password/TOTP, '
          'CSRF/session rotation, once-only secrets, service delegation, Bearer-only SQL read/write, scope/owner/tenant, '
          'CAS/revoke/key rotation and private-state/transport refusal; isolated local data')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('runtime', nargs='?', default='php'); parser.add_argument('--tls', action='store_true'); parser.add_argument('--browser', action='store_true')
    args = parser.parse_args(); run(args.runtime, args.tls, args.browser)
