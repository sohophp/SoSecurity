#!/usr/bin/env python3
"""Owned SQLite/localhost HTTP acceptance for the managed MFA factory."""
import base64
import copy
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parent.parent
browser_requested = '--browser' in sys.argv[1:]
arguments = [value for value in sys.argv[1:] if value != '--browser']
if len(arguments) > 1:
    raise SystemExit('Use [--browser] [php-runtime]')
runtime = arguments[0] if arguments else 'php'
checks = 0

def check(expected, actual):
    global checks
    checks += 1
    if expected != actual:
        raise AssertionError((expected, actual))

def code(secret):
    seed = base64.b32decode(secret + '=' * ((-len(secret)) % 8))
    counter = int(time.time()) // 30
    mac = hmac.new(seed, struct.pack('!Q', counter), hashlib.sha1).digest()
    offset = mac[-1] & 15
    return str((struct.unpack('!I', mac[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)

class Visitor:
    def __init__(self, url):
        self.jar = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.url = url
        self.csrf = None

    def call(self, action=None, fields=None, csrf=None, method=None, accept='application/json'):
        data = None
        if action is not None:
            values = dict(fields or {})
            values.update(action=action, _csrf=self.csrf if csrf is None else csrf)
            data = urllib.parse.urlencode(values).encode()
        request = urllib.request.Request(self.url, data=data, method=method,
                                         headers={'Accept': accept})
        try:
            response = self.client.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            check('no-store', response.headers.get('Cache-Control'))
            check('nosniff', response.headers.get('X-Content-Type-Options'))
            check(True, "frame-ancestors 'none'" in response.headers.get('Content-Security-Policy', ''))
            body = response.read()
            if accept == 'text/html':
                return response.status, body.decode(), response.headers
            result = json.loads(body)
            self.csrf = result.get('csrf', self.csrf)
            return response.status, result, response.headers

    def sid(self):
        return next((cookie.value for cookie in self.jar if cookie.name == 'SoSecurityManagedExample'), None)

setup = subprocess.run([runtime, str(root / 'tests/managed-auth-http-setup.php')],
                       check=True, capture_output=True, text=True)
fixture = json.loads(setup.stdout)
directory = Path(fixture['directory'])
if (directory.is_symlink() or directory.parent != Path(tempfile.gettempdir())
        or not directory.name.startswith('sosecurity-test-') or not directory.is_dir()):
    raise RuntimeError('Owned local fixture directory required')
server = None
try:
    sessions = directory / 'sessions'; sessions.mkdir(mode=0o700)
    budget = directory / 'request-budget'; budget.mkdir(mode=0o700)
    bootstrap = directory / 'managed-bootstrap.php'
    shutil.copyfile(root / 'tests/managed-auth-http-bootstrap.php', bootstrap)
    bootstrap.chmod(0o600)
    with sqlite3.connect(str(directory / 'managed.sqlite')) as database:
        before = database.execute('SELECT * FROM account_example').fetchall()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
    env = dict(os.environ)
    env.update(SOSECURITY_MANAGED_AUTH_EXAMPLE_BOOTSTRAP=str(bootstrap),
               SOSECURITY_MANAGED_AUTH_EXAMPLE_STATE=str(budget),
               SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP='1',
               SOSECURITY_MANAGED_AUTH_TEST_ROOT=str(root),
               SOSECURITY_MANAGED_AUTH_TEST_FIXTURE=str(directory))
    with open(directory / 'server.log', 'w+') as log:
        server = subprocess.Popen([runtime, '-d', 'session.save_path=' + str(sessions), '-S',
                                   '127.0.0.1:' + str(port), '-t', str(root / 'examples')],
                                  env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    log.seek(0); raise RuntimeError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('Managed authentication server startup timed out')
            url = 'http://127.0.0.1:' + str(port) + '/managed-authentication.php'
            visitor = Visitor(url)
            status, initial, headers = visitor.call()
            check(200, status); check('anonymous', initial['stage'])
            check(True, len(initial['csrf']) == 64)
            cookie_headers = ';'.join(headers.get_all('Set-Cookie', []))
            check(True, 'HttpOnly' in cookie_headers and 'SameSite=Lax' in cookie_headers)
            status, html, _ = visitor.call(accept='text/html')
            check(200, status); check(True, '<form method="post">' in html)
            check(False, fixture['secret'] in html)
            old_csrf = visitor.csrf; old_sid = visitor.sid()
            stale_cookies = [copy.copy(cookie) for cookie in visitor.jar]
            check(403, visitor.call('login', {'username':'owned@example.test', 'password':fixture['password']}, csrf='invalid')[0])
            check(403, visitor.call('login', {'username':'owned@example.test', 'password':fixture['password'], 'padding':'x' * 9000})[0])
            check(405, visitor.call(method='PUT')[0])
            check(401, visitor.call('mfa', {'type':'totp', 'proof':'000000'})[0])
            check(401, visitor.call('login', {'username':'owned@example.test', 'password':'wrong'})[0])
            status, waiting, _ = visitor.call('login', {'username':'owned@example.test', 'password':fixture['password']})
            check(200, status); check('mfa_required', waiting['stage'])
            check(False, 'session' in waiting); check(old_sid, visitor.sid())
            check(401, visitor.call('mfa', {'type':'totp', 'proof':'bad'})[0])
            status, authenticated, _ = visitor.call('mfa', {'type':'totp', 'proof':code(fixture['secret'])})
            check(200, status); check('authenticated', authenticated['stage'])
            check(2, authenticated['session']['strength']); check('totp', authenticated['session']['method'])
            check(False, old_sid == visitor.sid())
            stale = Visitor(url)
            for cookie in stale_cookies:
                stale.jar.set_cookie(cookie)
            check('anonymous', stale.call()[1]['stage'])
            check(False, fixture['password'] in json.dumps(authenticated) or fixture['secret'] in json.dumps(authenticated))
            check(403, visitor.call('logout', csrf=old_csrf)[0])
            other = Visitor(url); check('anonymous', other.call()[1]['stage'])
            check(200, visitor.call('logout')[0]); check('anonymous', visitor.call()[1]['stage'])
            with sqlite3.connect(str(directory / 'managed.sqlite')) as database:
                check(before, database.execute('SELECT * FROM account_example').fetchall())
            if browser_requested:
                browser_env = dict(env)
                browser_env.update(SOSECURITY_MANAGED_AUTH_URL=url,
                                   SOSECURITY_MANAGED_AUTH_PASSWORD=fixture['password'],
                                   SOSECURITY_MANAGED_AUTH_RECOVERY=fixture['recovery'])
                subprocess.run(['node', str(root / 'tests/managed-auth-browser.cjs')],
                               env=browser_env, cwd=root, check=True, timeout=60)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait(timeout=10)
    print('PASS managed MFA native HTTP: ' + str(checks) +
          ' assertions PHP runtime ' + runtime + '; owned SQLite, POST/CSRF/cache, password/TOTP/session/logout' +
          (' and Chromium' if browser_requested else ''), flush=True)
finally:
    if server is not None and server.poll() is None:
        server.kill(); server.wait(timeout=10)
    shutil.rmtree(directory)
