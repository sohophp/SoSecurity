#!/usr/bin/env python3
"""HTTP acceptance for the demo, locally isolated or against its explicitly selected entry URL."""
import argparse
import base64
import http.cookiejar
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('runtime', nargs='?', default='php')
parser.add_argument('--url')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
checks = 0

def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)

def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def acceptance(base):
    browser = client()
    controls = None
    def call(module, action=None, fields=None, visitor=None, csrf=None):
        nonlocal controls
        fields = dict(fields or {})
        if action is not None:
            fields.update(action=action, _csrf=controls if csrf is None else csrf)
        data = urllib.parse.urlencode(fields).encode() if action is not None else None
        request = urllib.request.Request(base + '?module=' + module, data=data, headers={'Accept': 'application/json'})
        try:
            response = (visitor or browser).open(request, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = json.load(response)
            if visitor is None and body.get('controls_token'):
                controls = body['controls_token']
            return response.status, body, response.headers
    for module in ['home', 'configuration', 'captcha', 'csrf', 'rate', 'password', 'reset', 'session', 'http', 'output', 'audit', 'storage']:
        status, body, headers = call(module)
        check(200, status)
        check(module, body['module'])
        check('no-store', headers['Cache-Control'])
    check(403, call('rate', 'consume', csrf='tampered')[0])
    check(400, call('rate', 'hash')[0])
    _, config_body, _ = call('configuration', 'construct')
    check(True, config_body['result']['session_unchanged'])
    check(True, config_body['result']['csrf_valid'])
    check(400, call('configuration', 'bad_option')[0])
    check(400, call('configuration', 'immutable')[0])
    check(503, call('configuration', 'store_failure')[0])
    status, config_body, _ = call('configuration', 'lock_timeout')
    check(503, status)
    check('storage.lock_timeout', config_body['result']['reason'])
    check(200, call('configuration', 'diagnose')[0])
    malformed = urllib.request.Request(base + '?module=rate', data=urllib.parse.urlencode(
        {'action[]': 'consume', '_csrf': controls}).encode(), headers={'Accept': 'application/json'})
    try:
        browser.open(malformed, timeout=8)
        raise AssertionError('Malformed action was accepted')
    except urllib.error.HTTPError as error:
        check(400, error.code)
    _, body, _ = call('csrf', 'issue')
    token = body['state']['token']
    check(200, call('csrf', 'verify', {'token': token})[0])
    check(403, call('csrf', 'tamper', {'token': token})[0])
    check(403, call('csrf', 'cross_scope', {'token': token})[0])
    stranger = client()
    _, stranger_body, _ = call('csrf', visitor=stranger)
    check(403, call('csrf', 'verify', {'token': token}, visitor=stranger, csrf=stranger_body['controls_token'])[0])
    check(200, call('csrf', 'once', {'token': token})[0])
    check(403, call('csrf', 'replay')[0])
    _, body, _ = call('csrf', 'issue')
    token = body['state']['token']
    call('csrf', 'expire')
    check(403, call('csrf', 'verify', {'token': token})[0])
    _, body, _ = call('captcha', 'math')
    challenge = body['state']['challenge']
    numbers = re.match(r'(\d+) \+ (\d+)', challenge['prompt'])
    answer = str(int(numbers[1]) + int(numbers[2]))
    check(200, call('captcha', 'verify', {'challenge_id': challenge['id'], 'answer': answer})[0])
    check(403, call('captcha', 'verify', {'challenge_id': challenge['id'], 'answer': answer})[0])
    _, body, _ = call('captcha', 'math')
    challenge = body['state']['challenge']
    call('captcha', 'expire')
    check(403, call('captcha', 'verify', {'challenge_id': challenge['id'], 'answer': '1'})[0])
    _, body, _ = call('captcha', 'image')
    image = body['state']['challenge']['image']
    check(b'\x89PNG\r\n\x1a\n', base64.b64decode(image.split(',')[1])[:8])
    check(False, body['state']['turnstile_configured'])
    check(503, call('captcha', 'turnstile')[0])
    call('rate', 'reset')
    for _ in range(3): check(200, call('rate', 'consume')[0])
    status, body, headers = call('rate', 'consume')
    check(429, status)
    check(True, int(headers['Retry-After']) > 0)
    call('rate', 'reset')
    call('rate', 'permanent')
    check(403, call('rate', 'consume')[0])
    call('rate', 'reset')
    call('password', 'hash', {'password': 'Demo-test-password'})
    check(200, call('password', 'verify', {'password': 'Demo-test-password'})[0])
    check(403, call('password', 'verify', {'password': 'incorrect'})[0])
    check(400, call('password', 'policy', {'password': 'short'})[0])
    check(200, call('password', 'legacy', {'password': 'Demo-only-7.2!'})[0])
    _, body, _ = call('reset', 'issue')
    token = body['state']['token']
    check(200, call('reset', 'consume', {'token': token})[0])
    check(403, call('reset', 'replay')[0])
    _, body, _ = call('reset', 'issue')
    token = body['state']['token']
    call('reset', 'change_version')
    check(403, call('reset', 'consume', {'token': token})[0])
    _, body, _ = call('session', 'rotate')
    fingerprint = body['state']['fingerprint']
    check(403, call('session', 'idle')[0])
    _, body, _ = call('session', 'rotate')
    check(False, body['state']['fingerprint'] == fingerprint)
    check(403, call('session', 'absolute')[0])
    call('session', 'rotate')
    _, body, _ = call('http', 'resolve', {'remote': '10.0.0.1', 'trusted': '10.0.0.0/8', 'forwarded': '1.1.1.1, 203.0.113.2, 10.0.0.2'})
    check('203.0.113.2', body['result']['resolved_ip'])
    check(400, call('http', 'resolve', {'remote': 'bad', 'trusted': '', 'forwarded': ''})[0])
    _, body, _ = call('http', 'headers', {'csp': "default-src 'self'"})
    check(True, 'Content-Security-Policy-Report-Only' in body['result']['headers'])
    _, body, _ = call('output', 'encode', {'text': '<script>alert("demo")</script>'})
    check(True, body['result']['html'].startswith('&lt;script'))
    check(False, '<script>' in body['result']['javascript_json'])
    _, body, _ = call('audit', 'record')
    check(False, 'DEMO-SENSITIVE-VALUE' in json.dumps(body['state']))
    check(False, 'DEMO-TOKEN' in json.dumps(body['state']))
    check(True, len(body['state']['events']) <= 20)
    for backend in ['session', 'file']:
        _, body, _ = call('storage', 'increment', {'backend': backend})
        check(1, body['result']['count'])
        _, body, _ = call('storage', 'read', {'backend': backend})
        check(1, body['result']['count'])
        _, body, _ = call('storage', 'isolation', {'backend': backend})
        check(0, body['result']['other_namespace_count'])
    _, body, _ = call('storage', 'increment', {'backend': 'memory'})
    check(1, body['result']['count'])
    _, body, _ = call('storage', 'read', {'backend': 'memory'})
    check(0, body['result']['count'])
    # An HTML response uses escaped text, not executable output, and never echoes plaintext passwords.
    request = urllib.request.Request(base + '?module=password', data=urllib.parse.urlencode(
        {'action': 'hash', '_csrf': controls, 'password': 'Never-echo-this-secret'}).encode())
    with browser.open(request, timeout=8) as response:
        html = response.read().decode()
        check(False, 'Never-echo-this-secret' in html)
        check(True, 'data-ajax' in html)
        check(True, 'SameSite=Lax' in ';'.join(response.headers.get_all('Set-Cookie', [])))
    print(f'PASS demo HTTP: {checks} assertions; all modules, form/JSON, rejection paths, replay, expiry, visitor isolation')

if args.url:
    acceptance(args.url.rstrip('/') + '/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-demo-test-') as directory:
        storage = Path(directory, 'storage'); storage.mkdir(mode=0o700)
        sessions = Path(directory, 'sessions'); sessions.mkdir(mode=0o700)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        env = os.environ.copy()
        env['SOSECURITY_DEMO_STORAGE'] = str(storage)
        for name in ['SOSECURITY_DEMO_TURNSTILE_SECRET', 'SOSECURITY_DEMO_TURNSTILE_SITE_KEY', 'SOSECURITY_DEMO_REDIS_SOCKET']:
            env.pop(name, None)
        with open(Path(directory, 'server.log'), 'w+') as log:
            server = subprocess.Popen([args.runtime, '-d', f'session.save_path={sessions}', '-S', f'127.0.0.1:{port}',
                                       '-t', str(root / 'demo/public')], stdout=log, stderr=log, env=env)
            try:
                for _ in range(100):
                    if server.poll() is not None: raise RuntimeError('Demo test server exited')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Demo test server startup timed out')
                acceptance(f'http://127.0.0.1:{port}/')
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()
                log.seek(0); output = log.read()
                if any(marker in output for marker in ['Fatal error', 'Deprecated', 'Warning:']):
                    raise RuntimeError('Demo test server emitted runtime errors')
