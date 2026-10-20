#!/usr/bin/env python3
"""Complete native HTTP/cookie integration against the shipped explicit authentication adapter."""
import base64
import copy
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
checks = 0

def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)

def native_hash(password):
    return subprocess.check_output([runtime, '-r', 'echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);', password], text=True)

def otp(uri):
    config = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
    seed = config['secret'][0]; key = base64.b32decode(seed + '=' * ((-len(seed)) % 8))
    mac = hmac.new(key, struct.pack('!Q', int(time.time()) // 30 + 1), hashlib.sha1).digest(); offset = mac[-1] & 15
    return str((struct.unpack('!I', mac[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)

class Visitor:
    def __init__(self, url):
        self.jar = http.cookiejar.CookieJar(); self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.url = url; self.csrf = None
    def call(self, action=None, fields=None, csrf=None, method=None):
        data = None
        if action is not None:
            values = dict(fields or {}); values.update(action=action, _csrf=self.csrf if csrf is None else csrf)
            data = urllib.parse.urlencode(values).encode()
        request = urllib.request.Request(self.url, data=data, method=method, headers={'Accept': 'application/json'})
        try: response = self.client.open(request, timeout=10)
        except urllib.error.HTTPError as error: response = error
        with response:
            check('no-store', response.headers['Cache-Control'])
            result = json.load(response); self.csrf = result.get('csrf', self.csrf)
            return response.status, result, response.headers
    def sid(self):
        return next((cookie.value for cookie in self.jar if cookie.name == 'SoSecurityAuthExample'), None)

sodium = subprocess.call([runtime, '-r', 'exit(extension_loaded("sodium")?0:1);']) == 0
if not sodium and os.getenv('SOSECURITY_REQUIRE_CRYPTO') == '1':
    raise RuntimeError('Required ext-sodium missing')

password_hash = native_hash('Correct-test-password'); replacement_hash = native_hash('Changed-test-password'); dummy_hash = native_hash('Dummy-test-password')
for mfa in ([False, True] if sodium else [False]):
    with tempfile.TemporaryDirectory(prefix='sosecurity-auth-http-') as directory:
        work = Path(directory); storage = work/'state'; storage.mkdir(mode=0o700); sessions = work/'sessions'; sessions.mkdir(mode=0o700)
        account = {'username': 'demo', 'subject': 'demo-account', 'hash': password_hash, 'version': '1', 'enabled': True, 'roles': ['member'], 'mfa_required': mfa}
        config = work/'account.json'
        def save():
            config.write_text(json.dumps(account)); config.chmod(0o600)
        save(); original = config.read_text(); fixture = None
        key = base64.b64encode(os.urandom(32)).decode()
        if mfa:
            result = subprocess.run([runtime, str(root/'tests/auth-setup.php')], input=json.dumps({'directory': str(storage), 'key': key}), text=True, capture_output=True, check=True)
            check('', result.stderr); fixture = json.loads(result.stdout)
        with socket.socket() as probe: probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        env = {k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_AUTH_EXAMPLE_')}; env.update(SOSECURITY_AUTH_EXAMPLE_CONFIG=str(config), SOSECURITY_AUTH_EXAMPLE_STORAGE=str(storage),
            SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH=dummy_hash, SOSECURITY_AUTH_EXAMPLE_HTTPS='0')
        env.pop('SOSECURITY_AUTH_EXAMPLE_KEY', None)
        if mfa: env['SOSECURITY_AUTH_EXAMPLE_KEY'] = key
        with open(work/'server.log', 'w+') as log:
            server = subprocess.Popen([runtime, '-d', 'session.save_path='+str(sessions), '-S', f'127.0.0.1:{port}', '-t', str(root/'examples')], env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None: log.seek(0); raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Authentication example startup timed out')
                url = f'http://127.0.0.1:{port}/authentication.php'
                first = Visitor(url); status, initial, headers = first.call(); check(200, status); check('anonymous', initial['stage'])
                cookie = ';'.join(headers.get_all('Set-Cookie', [])); check(True, 'HttpOnly' in cookie); check(True, 'SameSite=Lax' in cookie)
                check(403, first.call('login', {'username': 'demo', 'password': 'Correct-test-password'}, csrf='wrong')[0])
                unknown = first.call('login', {'username': 'missing', 'password': 'wrong'})
                incorrect = first.call('login', {'username': 'demo', 'password': 'wrong'})
                check(401, unknown[0]); check(401, incorrect[0]); check(unknown[1]['error'], incorrect[1]['error']); check(original, config.read_text())
                check(405, first.call(method='PUT')[0]); before = first.sid(); before_csrf = first.csrf
                old_cookies = [copy.copy(cookie) for cookie in first.jar]
                status, result, _ = first.call('login', {'username': 'demo', 'password': 'Correct-test-password'}); check(200, status)
                if mfa:
                    check('mfa_required', result['stage']); check(None, result['session']); check(before, first.sid())
                    check(401, first.call('list')[0]); check(401, first.call('mfa', {'type': 'totp', 'proof': 'bad'})[0])
                    status, result, _ = first.call('mfa', {'type': 'totp', 'proof': otp(fixture['uri'])}); check(200, status)
                check('authenticated', result['stage']); check(False, before == first.sid()); check(False, 'token' in json.dumps(result))
                stale = Visitor(url)
                for cookie in old_cookies: stale.jar.set_cookie(cookie)
                check('anonymous', stale.call()[1]['stage'])
                check(403, first.call('list', csrf=before_csrf)[0])
                check(2 if mfa else 1, result['session']['strength']); first_id = result['session']['id']
                check(200, first.call('sensitive')[0]); check(original, config.read_text())
                second = Visitor(url); second.call(); second.call('login', {'username': 'demo', 'password': 'Correct-test-password'})
                if mfa: check(200, second.call('mfa', {'type': 'recovery', 'proof': fixture['recovery'][0]})[0])
                status, listed, _ = first.call('list'); check(200, status); check(2, len(listed['sessions'])); check(False, 'digest' in json.dumps(listed))
                second_id = second.call()[1]['session']['id']
                check(True, first.call('revoke', {'session_id': second_id})[1]['revoked']); check('anonymous', second.call()[1]['stage']); check('authenticated', first.call()[1]['stage'])
                if mfa:
                    waiting = Visitor(url); waiting.call(); check('mfa_required', waiting.call('login', {'username': 'demo', 'password': 'Correct-test-password'})[1]['stage'])
                check(200, first.call('logout_all')[0]); check('anonymous', first.call()[1]['stage'])
                if mfa:
                    check(401, waiting.call('mfa', {'type': 'recovery', 'proof': fixture['recovery'][1]})[0])
                    waiting.call('login', {'username': 'demo', 'password': 'Correct-test-password'})
                    check(200, waiting.call('mfa', {'type': 'recovery', 'proof': fixture['recovery'][1]})[0])
                    first = waiting
                else: first.call('login', {'username': 'demo', 'password': 'Correct-test-password'})
                account['roles'] = ['reader']; save(); check('anonymous', first.call()[1]['stage'])
                first.call('login', {'username': 'demo', 'password': 'Correct-test-password'})
                if mfa: first.call('mfa', {'type': 'recovery', 'proof': fixture['recovery'][2]})
                account['hash'] = replacement_hash; save(); check('anonymous', first.call()[1]['stage'])
                check(401, first.call('login', {'username': 'demo', 'password': 'Correct-test-password'})[0])
                first.call('login', {'username': 'demo', 'password': 'Changed-test-password'})
                if mfa: first.call('mfa', {'type': 'recovery', 'proof': fixture['recovery'][3]})
                current = first.call()[1]['session']; check(True, current is not None)
                # Real time, not a public test-clock override: recent authentication must expire.
                time.sleep(5.1); check(403, first.call('sensitive')[0]); old_sid = first.sid()
                first.call('reauthenticate', {'username': 'demo', 'password': 'Changed-test-password'})
                if mfa: first.call('mfa', {'type': 'recovery', 'proof': fixture['recovery'][4]})
                status, result, _ = first.call(); check(200, status); check(current['id'], result['session']['id']); check(current['expires_at'], result['session']['expires_at'])
                check(False, old_sid == first.sid()); check(200, first.call('sensitive')[0])
                for field in ['enabled', 'mfa_required']:
                    config.write_text(json.dumps(dict(account, **{field: None})))
                    check(503, first.call()[0]); save()
                check('authenticated', first.call()[1]['stage'])
                config.chmod(0o000); check(503, first.call()[0]); config.chmod(0o600)
                check('authenticated', first.call()[1]['stage'])
                config.rename(work/'source-offline.json'); check(503, first.call()[0]); (work/'source-offline.json').rename(config)
                check('authenticated', first.call()[1]['stage'])
                account['enabled'] = False; account['version'] = '2'; save(); check('anonymous', first.call()[1]['stage'])
                check(401, first.call('login', {'username': 'demo', 'password': 'Changed-test-password'})[0])
                check(False, 'Correct-test-password' in ''.join(path.read_text(errors='replace') for path in storage.glob('*.json')))
                print(f'PASS HTTP authentication ({"TOTP/recovery" if mfa else "password"}): {checks} cumulative assertions; native Session rotation, CSRF, MFA, per-session/all revocation, live password/role/disable checks, source outage and reauthentication')
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()
if not sodium: print('NOT RUN HTTP encrypted TOTP branch: ext-sodium required')
