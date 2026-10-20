#!/usr/bin/env python3
"""Exercise native persistent-login risk responses with server-controlled local signals."""
import base64
import contextlib
import copy
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
assertions = 0

def check(expected, actual):
    global assertions
    assertions += 1
    assert expected == actual, (expected, actual)

class Visitor:
    def __init__(self, url):
        self.url = url
        self.csrf = ''
        self.jar = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, action=None, fields=None):
        body = None if action is None else urllib.parse.urlencode(dict(fields or {}, action=action, _csrf=self.csrf)).encode()
        request = urllib.request.Request(self.url, data=body, headers={'Accept': 'application/json'})
        try:
            response = self.client.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            check('no-store', response.headers['Cache-Control'])
            data = json.load(response)
            self.csrf = data.get('csrf', self.csrf)
            return response.status, data, response.headers

    def cookie(self, name='SoSecurityRememberLocal'):
        return next((cookie.value for cookie in self.jar if cookie.name == name), None)

    def persistent_only(self):
        visitor = Visitor(self.url)
        for cookie in self.jar:
            if cookie.name == 'SoSecurityRememberLocal':
                visitor.jar.set_cookie(copy.copy(cookie))
        return visitor

with tempfile.TemporaryDirectory(prefix='sosecurity-device-risk-http-') as directory:
    work = Path(directory)
    storage = work / 'state'; storage.mkdir(mode=0o700)
    sessions = work / 'sessions'; sessions.mkdir(mode=0o700)
    password_hash = subprocess.check_output([runtime, '-r', 'echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);', 'Correct-test-password'], text=True)
    dummy_hash = subprocess.check_output([runtime, '-r', 'echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);', 'Dummy-test-password'], text=True)
    account = work / 'account.json'
    account.write_text(json.dumps({'username': 'demo', 'subject': 'demo-account', 'hash': password_hash, 'version': '1', 'mfa_required': False}))
    account.chmod(0o600)
    remember_key = base64.b64encode(os.urandom(32)).decode()

    @contextlib.contextmanager
    def server(signals):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        env = {key: value for key, value in os.environ.items() if not key.startswith('SOSECURITY_AUTH_EXAMPLE_')}
        env.update(SOSECURITY_AUTH_EXAMPLE_CONFIG=str(account), SOSECURITY_AUTH_EXAMPLE_STORAGE=str(storage),
                   SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH=dummy_hash, SOSECURITY_AUTH_EXAMPLE_HTTPS='0',
                   SOSECURITY_AUTH_EXAMPLE_REMEMBER_KEY=remember_key,
                   SOSECURITY_AUTH_EXAMPLE_RISK_SIGNALS=json.dumps(signals))
        with open(work / ('server-' + str(port) + '.log'), 'w+') as log:
            process = subprocess.Popen([runtime, '-d', 'session.save_path=' + str(sessions), '-S',
                                        '127.0.0.1:' + str(port), '-t', str(root / 'examples')],
                                       env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('Local server startup timed out.')
                yield 'http://127.0.0.1:' + str(port) + '/authentication.php'
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)

    base = {'anomalous': False, 'changed': False, 'compromised': False, 'reauth_required': False}
    with server(base) as url:
        owner = Visitor(url); owner.call()
        status, data, _ = owner.call('login', {'username': 'demo', 'password': 'Correct-test-password'})
        check(200, status); check('authenticated', data['stage'])
        check(200, owner.call('remember')[0]); original = owner.cookie()
        check(True, isinstance(original, str) and original.startswith('sorp1.'))
        step = owner.persistent_only(); recovered = owner.persistent_only()

    changed = dict(base, changed=True)
    with server(changed) as url:
        step.url = url; step.call()
        status, data, headers = step.call('restore')
        check(403, status); check('auth.reauthentication_required', data['error'])
        check('anonymous', data['stage']); check(None, data['session'])
        check(None, step.cookie())
        check(True, any(header.startswith('SoSecurityRememberLocal=') for header in headers.get_all('Set-Cookie', [])))
        status, data, _ = step.call('login', {'username': 'demo', 'password': 'Correct-test-password'})
        check(200, status); check('authenticated', data['stage']); check(False, data['session']['resumed'])
        check(200, step.call('remember')[0])
        renewed = step.persistent_only()

    with server(base) as url:
        recovered.url = url; recovered.call()
        status, data, _ = recovered.call('restore')
        check(401, status); check('auth.denied', data['error']); check(None, recovered.cookie())
        renewed.url = url; renewed.call()
        status, data, _ = renewed.call('restore')
        check(200, status); check('authenticated', data['stage']); check(True, data['session']['resumed'])
        check(False, original == renewed.cookie())
        blocked = renewed.persistent_only()

    compromised = dict(base, compromised=True)
    with server(compromised) as url:
        blocked.url = url; blocked.call()
        status, data, _ = blocked.call('restore')
        check(401, status); check('auth.denied', data['error'])
        check('anonymous', data['stage']); check(None, blocked.cookie())
        renewed.url = url
        check('anonymous', renewed.call()[1]['stage'])

print('PASS native trusted-device risk HTTP: ' + str(assertions) + ' assertions PHP ' + runtime)
