#!/usr/bin/env python3
"""Real HTTP/cookie integration through PHP's isolated built-in server. No external packages."""
import http.cookiejar
import json
import os
import re
import socket
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parent
cfg = json.loads((root / 'var/config.json').read_text())
runtime = cfg['php']
password = dict(line.split('=', 1) for line in (root / 'var/demo-login.txt').read_text().splitlines())['password']
assert not (root / 'var/verification.json').exists(), 'Use one fresh consumer; do not reset security state to repeat verification'
assertions = 0

def check(expected, actual):
    global assertions
    assertions += 1
    assert expected == actual, (expected, actual)

def browser():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar

with tempfile.TemporaryDirectory(prefix='sosecurity-http-') as directory:
    os.chmod(directory, 0o700)
    state = Path(cfg['state'])
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    log = open(root / 'var/http-server.log', 'w+')
    server = subprocess.Popen([sys.executable, str(root / 'serve.py'), '--port', str(port)], stdout=log, stderr=log, start_new_session=True)
    url = f'http://127.0.0.1:{port}/'
    def request(client, data=None, method=None):
        encoded = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=encoded, headers={'Accept': 'application/json'}, method=method)
        try:
            response = client.open(req, timeout=5)
        except urllib.error.HTTPError as response:
            return response.code, json.load(response), response.headers
        with response:
            return response.status, json.load(response), response.headers
    def form_data(form, password='wrong', user='demo'):
        match = re.match(r'(\d+) \+ (\d+)', form['captcha']['prompt'])
        return {'_csrf': form['csrf'], 'captcha_id': form['captcha']['id'],
                'captcha_answer': str(int(match[1]) + int(match[2])), 'username': user, 'password': password}
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError('PHP test server exited')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('PHP test server startup timed out')
        client, jar = browser()
        code, first, headers = request(client)
        check(200, code)
        check('no-store', headers['Cache-Control'])
        with urllib.request.urlopen(url, timeout=5) as html:
            check(True, '<form method="post">' in html.read().decode())
        cookie_headers = ';'.join(headers.get_all('Set-Cookie', []))
        check(True, 'HttpOnly' in cookie_headers)
        check(True, 'SameSite=Lax' in cookie_headers)
        _, second, _ = request(client)
        stranger, _ = browser()
        check(403, request(stranger, form_data(first))[0])
        check(403, request(client, {'_csrf[]': 'array', 'username': 'demo', 'password': 'wrong'})[0])
        wrong_captcha = form_data(first)
        wrong_captcha['captcha_answer'] = 'not-an-answer'
        check(403, request(client, wrong_captcha)[0])
        check(401, request(client, form_data(first))[0])
        # A consumed challenge cannot be reused even though ordinary CSRF permits resubmission.
        check(403, request(client, form_data(first))[0])
        old_session = next(iter(jar)).value
        check(200, request(client, form_data(second, password))[0])
        check(False, old_session == next(iter(jar)).value)
        check('已登录。', request(client)[1]['message'])
        for _ in range(5):
            attacker, _ = browser()  # A new session must still share the same account/IP budget.
            _, form, _ = request(attacker)
            check(401, request(attacker, form_data(form, user='blocked'))[0])
        attacker, _ = browser()
        _, form, _ = request(attacker)
        code, _, headers = request(attacker, form_data(form, user='blocked'))
        check(429, code)
        check(True, int(headers['Retry-After']) > 0)
        check(405, request(attacker, method='PUT')[0])
        # Break only this test's storage permissions: the next sensitive request must be rejected.
        os.chmod(state, 0o755)
        check(503, request(attacker, form_data(form, user='another'))[0])
        print(f'PASS PHP7.2 consumer HTTP: {assertions} assertions; original form, CSRF, CAPTCHA, session rotation, cross-session shared budget, fail-closed')
    finally:
        os.chmod(state, 0o700)
        os.killpg(server.pid, signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(server.pid, signal.SIGKILL)
            server.wait()
        log.seek(0)
        output = log.read()
        if 'Fatal error' in output or 'Deprecated' in output or 'Warning:' in output:
            print(output, file=sys.stderr)
            raise RuntimeError('PHP server emitted runtime errors')
        log.close()

(root / 'var/verification.json').write_text(json.dumps({'passed': True, 'assertions': assertions, 'php': subprocess.check_output([runtime, '-r', 'echo PHP_VERSION;']).decode(), 'shared_budget_across_independent_sessions': True, 'storage_permissions_restored': True, 'server_stopped': server.poll() is not None, 'E_enabled': False}, indent=2) + '\n')
