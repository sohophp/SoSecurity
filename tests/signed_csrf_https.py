#!/usr/bin/env python3
"""Real private TLS terminator + PHP backend. Per-test CA, no host CA/proxy/session changes."""
import argparse, http.client, http.cookiejar, http.server, json, os, socket, ssl, subprocess, tempfile, threading, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php72');parser.add_argument('--browser',action='store_true');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='sosecurity-signed-https-') as directory:
    base=Path(directory);cert=base/'cert.pem';key=base/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    key.chmod(0o600)
    config=base/'private.json';config.write_text(json.dumps({'secret_hex':os.urandom(32).hex(),'users':{user:{'credential':os.urandom(32).hex(),'binding':'verified-login-'+os.urandom(16).hex()} for user in ['alice','bob']}}));config.chmod(0o600)
    sessions=base/'sessions';sessions.mkdir(mode=0o700)
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));php_port=probe.getsockname()[1]
    env=os.environ.copy();env.update(SOSECURITY_TEST_SIGNED_CSRF_CONFIG=str(config),SOSECURITY_TEST_SIGNED_CSRF_HTTPS='1')
    log=open(base/'server.log','w+');php=subprocess.Popen([args.runtime,'-d','session.auto_start=0','-d','session.save_path='+str(sessions),'-S','127.0.0.1:'+str(php_port),str(root/'tests/http-signed-csrf.php')],env=env,stdout=log,stderr=log)
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self,*unused):pass
        def handle_request(self):
            length=int(self.headers.get('Content-Length','0'))
            if length<0 or length>8192:self.send_error(413);return
            body=self.rfile.read(length);connection=http.client.HTTPConnection('127.0.0.1',php_port,timeout=5)
            try:
                headers={name:value for name,value in self.headers.items() if name.lower() not in ('host','connection','transfer-encoding','content-length')}
                connection.request(self.command,self.path,body,headers);response=connection.getresponse();data=response.read(65537)
                if len(data)>65536:raise RuntimeError('Private proxy response exceeded budget')
                self.send_response(response.status)
                for name,value in response.getheaders():
                    if name.lower() not in ('connection','transfer-encoding','content-length','server','date'):self.send_header(name,value)
                self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            finally:connection.close()
        do_GET=handle_request;do_POST=handle_request;do_OPTIONS=handle_request
    class Attacker(http.server.BaseHTTPRequestHandler):
        def log_message(self,*unused):pass
        def do_GET(self):
            html='<!doctype html><title>Same-site hostile origin test</title><form method="POST" action="'+origin+'/update"><input name="_csrf" value="forged"><button>attack</button></form>'
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(html.encode())
    proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy);attacker=http.server.ThreadingHTTPServer(('127.0.0.1',0),Attacker)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key))
    for server in [proxy,attacker]:server.socket=context.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
    origin='https://localhost:'+str(proxy.server_port);attack_origin='https://localhost:'+str(attacker.server_port)
    checks=0
    def check(expected,actual):
        global checks
        checks+=1;assert expected==actual,(expected,actual)
    try:
        for _ in range(100):
            if php.poll() is not None:raise RuntimeError('Private PHP backend exited')
            try:
                with socket.create_connection(('127.0.0.1',php_port),timeout=.2):break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('Private PHP backend startup failed')
        client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))))
        def call(path,fields=None):
            request=urllib.request.Request(origin+path,data=None if fields is None else urllib.parse.urlencode(fields).encode())
            try:response=client.open(request,timeout=5)
            except urllib.error.HTTPError as error:response=error
            with response:return response.status,response.headers,json.load(response)
        status,headers,_=call('/test-login',{'user':'alice'});check(200,status);check(True,headers['Set-Cookie'].startswith('__Host-test-auth='));check(True,'Secure' in headers['Set-Cookie']);check(False,'Domain=' in headers['Set-Cookie'])
        status,headers,result=call('/form');check(200,status);check(True,headers['Set-Cookie'].startswith('__Host-test-csrf='));check(True,'Secure' in headers['Set-Cookie']);check(True,'HttpOnly' in headers['Set-Cookie']);check(True,'Path=/' in headers['Set-Cookie']);check(False,'Domain=' in headers['Set-Cookie']);check(False,result['session_started'])
        check(200,call('/update',{'_csrf':result['token']})[0]);check(403,call('/update',{'_csrf':'forged'})[0]);check([],list(sessions.iterdir()))
        print('PASS {}: {} real TLS/proxy signed-CSRF assertions; per-test CA validation, Secure/HttpOnly/__Host cookies, no PHP Session'.format(args.runtime,checks))
        if args.browser:subprocess.run(['node',str(root/'tests/signed-csrf-browser.cjs'),origin,attack_origin],env=os.environ.copy(),check=True,timeout=45)
    finally:
        for server in [proxy,attacker]:server.shutdown();server.server_close()
        php.terminate()
        try:php.wait(timeout=5)
        except subprocess.TimeoutExpired:php.kill();php.wait()
        log.close()
