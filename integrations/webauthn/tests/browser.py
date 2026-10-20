#!/usr/bin/env python3
"""Private HTTPS origins and SQLite for a Chromium virtual WebAuthn authenticator."""
import http.server
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading

root = Path(__file__).resolve().parents[3]
package = Path(__file__).resolve().parents[1]
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php82'
autoload = Path(os.environ.get('SOSECURITY_WEBAUTHN_AUTOLOAD', ''))
if not autoload.is_file():
    raise RuntimeError('SOSECURITY_WEBAUTHN_AUTOLOAD must name local Composer consumer autoload.php')

class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<!doctype html><html lang="en"><meta charset="utf-8"><title>WebAuthn browser test</title><body>Local test origin</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *unused):
        pass

with tempfile.TemporaryDirectory(prefix='sosecurity-webauthn-browser-') as directory:
    work = Path(directory)
    work.chmod(0o700)
    (work / 'owned-webauthn-test').write_text('Local WebAuthn test only\n')
    state = work / 'state'
    state.mkdir(mode=0o700)
    with sqlite3.connect(work / 'credentials.sqlite') as db:
        db.executescript((package / 'schema.sqlite.sql').read_text())
    cert, key = work / 'cert.pem', work / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    key.chmod(0o600)
    servers = []
    try:
        for _ in range(2):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Page)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(cert), str(key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        primary = 'https://localhost:' + str(servers[0].server_port)
        alternate = 'https://localhost:' + str(servers[1].server_port)
        env = os.environ.copy()
        env.update(SOSECURITY_WEBAUTHN_TEST_DIR=str(work),
                   SOSECURITY_WEBAUTHN_TEST_ORIGIN=primary,
                   SOSECURITY_WEBAUTHN_TEST_AUTOLOAD=str(autoload))
        subprocess.run(['node', str(package / 'tests/browser.cjs'), runtime,
            str(package / 'tests/browser-backend.php'), primary, alternate],
            cwd=root, env=env, check=True, timeout=120)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
