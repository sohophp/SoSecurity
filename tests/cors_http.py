#!/usr/bin/env python3
"""Actual CORS headers; optional Chromium uses two independently controlled frontend origins."""
import argparse, http.server, json, os, socket, subprocess, tempfile, threading, time, urllib.error, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--browser',action='store_true');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
class Front(http.server.BaseHTTPRequestHandler):
    def log_message(self,*unused):pass
    def do_GET(self):self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(b'<!doctype html><title>CORS test environment</title>')
front=http.server.ThreadingHTTPServer(('127.0.0.1',0),Front);denied=http.server.ThreadingHTTPServer(('127.0.0.1',0),Front)
for server in [front,denied]:threading.Thread(target=server.serve_forever,daemon=True).start()
origin=f'http://127.0.0.1:{front.server_port}'
try:
    with tempfile.TemporaryDirectory(prefix='sosecurity-cors-') as directory:
        storage=Path(directory,'storage');storage.mkdir(mode=0o700)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        env=os.environ.copy();env.update(SOSECURITY_DEMO_STORAGE=str(storage),SOSECURITY_DEMO_CORS_ORIGIN=origin)
        with open(Path(directory,'server.log'),'w+') as log:
            backend=subprocess.Popen([args.runtime,'-S',f'127.0.0.1:{port}','-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            url=f'http://127.0.0.1:{port}/cors.php';checks=0
            def call(method,headers=None):
                request=urllib.request.Request(url,method=method,headers=headers or {})
                try:response=urllib.request.urlopen(request,timeout=4)
                except urllib.error.HTTPError as error:response=error
                with response:return response.status,response.headers,response.read()
            def check(expected,actual):
                global checks
                checks+=1;assert expected==actual,(expected,actual)
            try:
                for _ in range(100):
                    if backend.poll() is not None:raise RuntimeError('CORS test server exited')
                    try:call('GET');break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('CORS server startup failed')
                status,headers,body=call('OPTIONS',{'Origin':origin,'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'X-Demo-Token'})
                check(204,status);check(origin,headers['Access-Control-Allow-Origin']);check(b'',body)
                check('origin, access-control-request-method, access-control-request-headers',headers['Vary'])
                status,headers,body=call('GET',{'Origin':origin});check(200,status);check(True,json.loads(body)['demo']);check(None,headers.get('Set-Cookie'))
                check(None,headers.get('Access-Control-Allow-Credentials'))
                check(403,call('OPTIONS',{'Origin':'https://evil.invalid','Access-Control-Request-Method':'GET'})[0])
                check(403,call('OPTIONS',{'Origin':origin,'Access-Control-Request-Method':'DELETE'})[0])
                check(403,call('OPTIONS',{'Origin':origin,'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization'})[0])
                check(405,call('POST')[0]);print(f'PASS CORS HTTP: {checks} assertions; actual headers, preflight, static anonymous data only')
                if args.browser:subprocess.run(['node',str(root/'tests/cors-browser.cjs'),url,origin,f'http://127.0.0.1:{denied.server_port}'],env=os.environ.copy(),check=True,timeout=45)
            finally:
                backend.terminate()
                try:backend.wait(timeout=5)
                except subprocess.TimeoutExpired:backend.kill();backend.wait()
finally:
    for server in [front,denied]:server.shutdown();server.server_close()
