#!/usr/bin/env python3
"""Owned local SQLite/PHP/clamd only. Native authentication, multipart uploads and private download."""
import argparse
import contextlib
import hashlib
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SITE = 'native-quarantine'
PASSWORD = 'Owned-quarantine-test-password'
BODY = b'Private native upload bytes.\n'
MARKER = b'SoSecurity antivirus acceptance marker.\n'
CHECKS = 0


def check(expected, actual):
    global CHECKS
    CHECKS += 1
    assert expected == actual, (expected, actual)


class Visitor:
    def __init__(self, fixture):
        self.f = fixture
        self.csrf = ''
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if fixture['ca']:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(fixture['ca']))))
        self.client = urllib.request.build_opener(*handlers)

    def call(self, action=None, fields=None, upload=None, path='/', method=None, token=None, origin=None, headers=None):
        body = None
        sent = dict({'Accept': 'application/json'}, **(headers or {}))
        if action is not None:
            fields = dict(fields or {}, action=action, _csrf=self.csrf if token is None else token)
            sent['Origin'] = self.f['origin'] if origin is None else origin
            if upload is None:
                body = urllib.parse.urlencode(fields).encode()
            else:
                boundary = 'owned-' + os.urandom(12).hex()
                parts = []
                for key, value in fields.items():
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
                filename, contents = upload
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + contents + b'\r\n')
                parts.append(f'--{boundary}--\r\n'.encode())
                body = b''.join(parts)
                sent['Content-Type'] = 'multipart/form-data; boundary=' + boundary
        request = urllib.request.Request(self.f['origin'] + path, data=body, method=method, headers=sent)
        try:
            response = self.client.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            check('no-store, private', response.headers['Cache-Control'])
            check('same-origin', response.headers['Referrer-Policy'])
            check('nosniff', response.headers['X-Content-Type-Options'])
            raw = response.read()
            data = json.loads(raw) if raw and response.headers.get_content_type() == 'application/json' else raw
            if isinstance(data, dict):
                self.csrf = data.get('csrf', self.csrf)
                encoded = json.dumps(data)
                for private in [PASSWORD, str(self.f['work']), '$2y$', 'soss_']:
                    check(False, private in encoded)
            return response.status, data, response.headers

    def login(self, name):
        self.call()
        status, data, headers = self.call('login', {'username': name, 'password': PASSWORD})
        check(200, status)
        check('authenticated', data['stage'])
        return data


@contextlib.contextmanager
def fixture(runtime, tls=False, package=ROOT):
    daemon = shutil.which('clamd')
    if not daemon:
        raise RuntimeError('NOT RUN native quarantine: private clamd required')
    with tempfile.TemporaryDirectory(prefix='sosecurity-quarantine-http-') as name:
        work = Path(name)
        for child in ['state', 'spool', 'sessions', 'web', 'av', 'av/database']:
            (work / child).mkdir(mode=0o700)
        hashes = subprocess.check_output([runtime, '-r', 'echo json_encode([password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]),password_hash("dummy-only-unusable",PASSWORD_BCRYPT,["cost"=>12])]);', PASSWORD], text=True)
        saved_hash, dummy = json.loads(hashes)
        database = work / 'business.sqlite'
        db = sqlite3.connect(database)
        db.executescript((package / 'resources/sql/upload-quarantine-example-sqlite.sql').read_text())
        for site, subject, roles in [(SITE, 'alice', ['uploader']), (SITE, 'bob', ['uploader']), (SITE, 'admin', ['uploader', 'upload-admin']), (SITE, 'oldadmin', ['uploader', 'upload-admin']), ('other-site', 'alice', ['uploader'])]:
            db.execute('INSERT INTO quarantine_example_accounts VALUES(?,?,?,?,?,?,?,?)', (site, subject, subject, saved_hash, '1', 1, json.dumps(roles), 0))
        db.commit()
        database.chmod(0o600)
        av = work / 'av'
        socket_path = av / 'scan.sock'
        (av / 'database/local.hdb').write_text(hashlib.md5(MARKER).hexdigest() + ':' + str(len(MARKER)) + ':SoSecurity.Native.Acceptance\n')
        av_config = av / 'clamd.conf'
        av_config.write_text('\n'.join(['Foreground yes', 'LocalSocket ' + str(socket_path), 'LocalSocketMode 600', 'FixStaleSocket no', 'DatabaseDirectory ' + str(av / 'database'), 'TemporaryDirectory ' + str(av), 'PidFile ' + str(av / 'pid'), 'LogFile ' + str(av / 'clamd.log'), 'MaxThreads 1', 'MaxQueue 4', 'MaxConnectionQueueLength 4', 'ReadTimeout 2', 'CommandReadTimeout 2', 'SendBufTimeout 200', 'MaxScanTime 2000', 'StreamMaxLength 2M', 'MaxFileSize 2M', 'MaxScanSize 4M', 'AlertExceedsMax yes', 'Bytecode no']) + '\n')
        av_log = (av / 'launch.log').open('w')
        owned = {'clamd': None}

        def stop_av():
            process = owned['clamd']
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        def start_av():
            assert owned['clamd'] is None or owned['clamd'].poll() is not None
            if socket_path.exists():
                socket_path.unlink()
            process = subprocess.Popen([daemon, '--foreground', '--config-file=' + str(av_config)], stdout=av_log, stderr=subprocess.STDOUT)
            owned['clamd'] = process
            until = time.monotonic() + 20
            while time.monotonic() < until:
                if process.poll() is not None:
                    raise RuntimeError('Owned clamd exited: ' + (av / 'launch.log').read_text())
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(.2)
                        client.connect(str(socket_path))
                        client.sendall(b'zPING\0')
                        if client.recv(64) == b'PONG\0':
                            return
                except OSError:
                    pass
                time.sleep(.02)
            raise RuntimeError('Owned clamd startup timed out')

        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        secret = os.urandom(32).hex()
        proxy = None
        ca = None
        if tls:
            ca = work / 'cert.pem'
            key = work / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(key), '-out', str(ca), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
            key.chmod(0o600)

            class Proxy(http.server.BaseHTTPRequestHandler):
                def log_message(self, *unused):
                    pass

                def request(self):
                    length = int(self.headers.get('Content-Length', '0'))
                    if length < 0 or length > 3 * 1048576:
                        self.send_error(413)
                        return
                    headers = {k: v for k, v in self.headers.items() if k.lower() not in ['connection', 'transfer-encoding', 'content-length', 'x-quarantine-test-tls']}
                    headers['X-Quarantine-Test-Tls'] = secret
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
                    try:
                        connection.request(self.command, self.path, self.rfile.read(length), headers)
                        response = connection.getresponse()
                        data = response.read(2 * 1048576)
                        self.send_response(response.status)
                        for key, value in response.getheaders():
                            if key.lower() not in ['connection', 'transfer-encoding', 'content-length', 'server', 'date']:
                                self.send_header(key, value)
                        self.send_header('Content-Length', response.getheader('Content-Length', '0') if self.command == 'HEAD' else str(len(data)))
                        self.end_headers()
                        if self.command != 'HEAD':
                            self.wfile.write(data)
                    finally:
                        connection.close()

                do_GET = request
                do_HEAD = request
                do_POST = request
                do_PUT = request

            proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(ca), str(key))
            proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            origin = f'https://localhost:{proxy.server_port}'
        config = work / 'config.json'
        config.write_text(json.dumps(dict(site=SITE, origin=origin, database=str(database), state=str(work / 'state'), spool=str(work / 'spool'), document_root=str(work / 'web'), socket=str(socket_path), dummy_hash=dummy)))
        config.chmod(0o600)
        router = work / 'router.php'
        router.write_text("<?php $secret=getenv('SOSECURITY_QUARANTINE_TEST_TLS');if(is_string($secret)&&$secret!==''&&hash_equals($secret,$_SERVER['HTTP_X_QUARANTINE_TEST_TLS']??'')){$_SERVER['HTTPS']='on';}require " + json.dumps(str(package / 'examples/upload-quarantine-http.php')) + ';')
        env = {k: v for k, v in os.environ.items() if not k.startswith('SOSECURITY_QUARANTINE_EXAMPLE_')}
        env.update(SOSECURITY_QUARANTINE_EXAMPLE_CONFIG=str(config), SOSECURITY_QUARANTINE_EXAMPLE_ALLOW_HTTP='0' if tls else '1', SOSECURITY_QUARANTINE_TEST_TLS=secret if tls else '')
        log = (work / 'php.log').open('w')
        server = None
        try:
            start_av()
            server = subprocess.Popen([runtime, '-d', 'memory_limit=32M', '-d', 'display_errors=0', '-d', 'log_errors=1', '-d', 'session.save_path=' + str(work / 'sessions'), '-d', 'session.name=QUARANTINE_SESSION', '-d', 'upload_max_filesize=2M', '-d', 'post_max_size=3M', '-S', f'127.0.0.1:{port}', '-t', str(work / 'web'), str(router)], env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            until = time.monotonic() + 10
            while time.monotonic() < until:
                if server.poll() is not None:
                    raise RuntimeError((work / 'php.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.02)
            else:
                raise RuntimeError('Owned PHP startup timed out')
            value = dict(work=work, origin=origin, ca=ca, config=config, db=db, runtime=runtime, env=env, stop_av=stop_av, start_av=start_av, package=package)
            yield value
        except BaseException:
            log.flush()
            print('OWNED_PHP_FAILURE_LOG\n' + (work / 'php.log').read_text()[-8000:], file=sys.stderr)
            raise
        finally:
            if server is not None and server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            stop_av()
            if proxy is not None:
                proxy.shutdown()
                proxy.server_close()
            db.close()
            av_log.close()
            log.close()


def worker(f):
    result = subprocess.run([f['runtime'], '-d', 'memory_limit=32M', str(f['package'] / 'examples/upload-quarantine-worker.php'), str(f['config']), '64'], env=f['env'], cwd=ROOT, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    check('', result.stderr)
    return json.loads(result.stdout)['processed']


def old_admin(f, visitor):
    # Create an actually valid historical SDK password session with one consistent injected past clock.
    visitor.call()
    cookie = next(x.value for x in visitor.jar if x.name == 'QUARANTINE_SESSION')
    script = r'''require $argv[1].'/vendor/autoload.php';require $argv[1].'/examples/upload-quarantine-business.php';
$config=SoSecurity\Examples\QuarantineHttp\configuration($argv[2]);$services=SoSecurity\Examples\QuarantineHttp\services($config);
$clock=new class implements SoSecurity\Support\Clock{private $now;public function __construct(){$this->now=time()-301;}public function now():int{return $this->now;}};
$store=new SoSecurity\Storage\FileStore($config['state'],$config['site'].':native-upload',$clock);
$registry=new SoSecurity\Auth\SessionRegistry($store,$services['provider'],null,$clock);
session_save_path($argv[3]);session_name('QUARANTINE_SESSION');session_id($argv[4]);session_start();
$flow=new SoSecurity\Auth\AuthenticationFlow($store,$services['provider'],$registry,static function():bool{return true;},null,$clock);
$result=$flow->password($config['site'],$_SESSION['quarantine_binding'],'oldadmin',$argv[5]);
if($result->status()!=='authenticated'){exit(40);}$_SESSION['quarantine_subject']='oldadmin';$_SESSION['quarantine_token']=$result->credential()->token();session_write_close();'''
    subprocess.run([f['runtime'], '-r', script, str(f['package']), str(f['config']), str(f['work'] / 'sessions'), cookie, PASSWORD], env=f['env'], cwd=ROOT, check=True, capture_output=True)
    check('authenticated', visitor.call()[1]['stage'])


def exercise(f):
    alice, bob, admin, anonymous = [Visitor(f) for unused in range(4)]
    check(200, anonymous.call()[0])
    before = list((f['work'] / 'spool').iterdir())
    check(403, anonymous.call('upload', upload=('anonymous.txt', BODY))[0])
    check(before, list((f['work'] / 'spool').iterdir()))
    alice.login('alice')
    bob.login('bob')
    admin.login('admin')
    token = alice.csrf
    check(403, bob.call('upload', upload=('cross.txt', BODY), token=token)[0])
    status, data, unused = alice.call('upload', upload=('file.txt', BODY))
    check(200, status)
    check(1, len(data['files']))
    identifier = data['files'][0]['id']
    check('pending', data['files'][0]['state'])
    path = '/?download=' + identifier
    foreign = 'f' * 32
    f['db'].execute('INSERT INTO quarantine_example_files VALUES(?,?,?,?)', ('other-site', foreign, 'alice', int(time.time())))
    f['db'].commit()
    check([identifier], [x['id'] for x in alice.call()[1]['files']])
    check(403, admin.call('reject', {'id': foreign})[0])
    check(409, alice.call(path=path)[0])
    for visitor in [bob, admin, anonymous]:
        check(403, visitor.call(path=path)[0])
    check(400, admin.call(path='/?action=reject&id=' + identifier)[0])
    check(403, alice.call('reject', {'id': identifier})[0])
    check(403, admin.call('reject', {'id': identifier}, origin='https://attacker.invalid')[0])
    f['stop_av']()
    check('retry', worker(f)[0]['state'])
    check(409, alice.call(path=path)[0])
    f['start_av']()
    time.sleep(1.05)
    check('available', worker(f)[0]['state'])
    status, body, headers = alice.call(path=path)
    check(200, status)
    check(BODY, body)
    check('attachment; filename="upload.txt"', headers['Content-Disposition'])
    check('application/octet-stream', headers.get_content_type())
    check(200, alice.call(path=path, method='HEAD')[0])
    check(400, alice.call(path=path + '&download=' + identifier)[0])
    check(400, alice.call(path=path, headers={'Range': 'bytes=0-0'})[0])
    check(409, admin.call('remove', {'id': identifier})[0])
    check(BODY, alice.call(path=path)[1])
    stale = Visitor(f)
    old_admin(f, stale)
    check(403, stale.call('reject', {'id': identifier})[0])
    check(200, alice.call(path=path)[0])
    check(200, stale.call('reauthenticate', {'username': 'oldadmin', 'password': PASSWORD})[0])
    check(200, stale.call('rescan', {'id': identifier})[0])
    check(409, alice.call(path=path)[0])
    check('available', worker(f)[0]['state'])
    old_token = admin.csrf
    check(200, admin.call('rescan', {'id': identifier})[0])
    check(403, admin.call('rescan', {'id': identifier}, token=old_token)[0])
    check(409, alice.call(path=path)[0])
    check('available', worker(f)[0]['state'])
    f['db'].execute('UPDATE quarantine_example_accounts SET roles=? WHERE site=? AND subject=?', ('["uploader"]', SITE, 'admin'))
    f['db'].commit()
    check(403, admin.call('reject', {'id': identifier})[0])
    check(200, alice.call(path=path)[0])
    f['db'].execute('UPDATE quarantine_example_accounts SET roles=? WHERE site=? AND subject=?', ('["uploader","upload-admin"]', SITE, 'admin'))
    f['db'].commit()
    admin = Visitor(f)
    admin.login('admin')
    check(200, admin.call('reject', {'id': identifier})[0])
    check(409, alice.call(path=path)[0])
    check(200, admin.call('remove', {'id': identifier})[0])
    png = subprocess.check_output([f['runtime'], '-r', '$i=imagecreatetruecolor(2,2);imagepng($i);'])
    check(True, b'\0' in png)
    status, data, unused = alice.call('upload', upload=('binary.png', png))
    check(200, status)
    identifier = data['files'][0]['id']
    check('available', worker(f)[0]['state'])
    body = alice.call(path='/?download=' + identifier)[1]
    check(b'\x89PNG\r\n\x1a\n', body[:8])
    check((f['work'] / 'spool' / (identifier + '.png')).read_bytes(), body)
    check(200, admin.call('reject', {'id': identifier})[0])
    check(200, admin.call('remove', {'id': identifier})[0])
    check(403, alice.call(path=path)[0])
    for filename, contents in [('nul.txt', b'a\0b'), ('large.txt', b'x' * 1048577), ('bad.php.txt', BODY)]:
        check(400, alice.call('upload', upload=(filename, contents))[0])
    check(400, alice.call('upload', {'owner': 'bob'}, upload=('forged.txt', BODY))[0])
    status, data, unused = alice.call('upload', upload=('signature.txt', MARKER))
    check(200, status)
    identifier = data['files'][0]['id']
    check('rejected', worker(f)[0]['state'])
    check(409, alice.call(path='/?download=' + identifier)[0])
    check(200, admin.call('remove', {'id': identifier})[0])
    f['db'].execute('UPDATE quarantine_example_accounts SET roles=CAST(zeroblob(16777216) AS TEXT) WHERE site=? AND subject=?', (SITE, 'alice'))
    f['db'].commit()
    check(503, alice.call()[0])
    f['db'].execute('UPDATE quarantine_example_accounts SET roles=? WHERE site=? AND subject=?', ('["uploader"]', SITE, 'alice'))
    f['db'].commit()
    check(200, alice.call()[0])
    for index in range(8):
        check(200, alice.call('upload', upload=(f'quota-{index}.txt', BODY))[0])
    check(429, alice.call('upload', upload=('quota-over.txt', BODY))[0])
    ids = [row[0] for row in f['db'].execute('SELECT id FROM quarantine_example_files WHERE site=?', (SITE,))]
    check(8, len(ids))
    for identifier in ids:
        check(200, admin.call('reject', {'id': identifier})[0])
        check(200, admin.call('remove', {'id': identifier})[0])
    status, data, unused = bob.call('upload', upload=('revocation.txt', BODY))
    check(200, status)
    identifier = data['files'][0]['id']
    check('available', worker(f)[0]['state'])
    check(200, bob.call(path='/?download=' + identifier)[0])
    f['db'].execute('UPDATE quarantine_example_accounts SET password_hash=? WHERE site=? AND subject=?', (json.loads(f['config'].read_text())['dummy_hash'], SITE, 'bob'))
    f['db'].commit()
    check(403, bob.call(path='/?download=' + identifier)[0])
    check('anonymous', bob.call()[1]['stage'])
    check(200, admin.call('reject', {'id': identifier})[0])
    check(200, admin.call('remove', {'id': identifier})[0])
    check(200, alice.call('logout')[0])
    check('anonymous', alice.call()[1]['stage'])
    check(0, f['db'].execute('SELECT COUNT(*) FROM quarantine_example_files WHERE site=?', (SITE,)).fetchone()[0])
    check(1, f['db'].execute('SELECT COUNT(*) FROM quarantine_example_files WHERE site=?', ('other-site',)).fetchone()[0])


def authority_check(f, recent=False):
    alice = Visitor(f)
    alice.login('alice')
    status, data, unused = alice.call('upload', upload=('authority.txt', BODY))
    check(200, status)
    identifier = data['files'][0]['id']
    check('available', worker(f)[0]['state'])
    actor = Visitor(f)
    if recent:
        old_admin(f, actor)
        status, data, unused = actor.call('reject', {'id': identifier})
        if status == 200 and alice.call(path='/?download=' + identifier)[0] == 409:
            raise RuntimeError('UNSAFE_NATIVE_QUARANTINE_STALE_ADMIN_REJECTED_FILE')
        check(403, status)
        check(BODY, alice.call(path='/?download=' + identifier)[1])
    else:
        actor.login('bob')
        status, data, unused = actor.call(path='/?download=' + identifier)
        if status == 200 and data == BODY:
            raise RuntimeError('UNSAFE_NATIVE_QUARANTINE_OTHER_OWNER_READ_ACTUAL_BYTES')
        check(403, status)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('runtime', nargs='?', default='php')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--browser', action='store_true')
    parser.add_argument('--owner-check', action='store_true')
    parser.add_argument('--recent-check', action='store_true')
    parser.add_argument('--package', type=Path, default=ROOT)
    args = parser.parse_args()
    if args.browser and not args.tls:
        parser.error('Browser acceptance requires the owned TLS fixture')
    if args.package != ROOT and (not str(args.package.resolve()).startswith('/tmp/sosecurity-') or not args.package.is_dir()):
        parser.error('A current SDK or owned temporary test package is required')
    with fixture(args.runtime, args.tls, args.package) as value:
        if args.browser:
            env = dict(value['env'], SOSECURITY_TEST_QUARANTINE_PASSWORD=PASSWORD)
            subprocess.run(['node', str(ROOT / 'tests/upload-quarantine-browser.cjs'), value['origin'], args.runtime, str(value['config']), str(args.package)], env=env, cwd=ROOT, check=True, timeout=90)
        elif args.owner_check or args.recent_check:
            authority_check(value, args.recent_check)
        else:
            exercise(value)
    print(f'PASS native quarantine {"Chromium" if args.browser else "HTTP"} {"TLS" if args.tls else "loopback"}: {CHECKS} HTTP assertions; {args.runtime}; owned SQLite/PHP/clamd stopped and fixtures removed')


if __name__ == '__main__':
    main()
