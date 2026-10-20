#!/usr/bin/env python3
"""Real TLS terminator, verified private CA and Secure __Host persistent Cookie against native PHP."""
import copy, http.client, http.cookiejar, http.server, json, os, socket, ssl, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path
runtime = sys.argv[1] if len(sys.argv)>1 else 'php'
root = Path(__file__).resolve().parent.parent; checks = 0
def check(expected,actual):
    global checks
    checks += 1
    assert expected==actual,(expected,actual)
with tempfile.TemporaryDirectory(prefix='sosecurity-remember-tls-') as directory:
    work=Path(directory); cert=work/'cert.pem'; key=work/'key.pem'; storage=work/'state'; storage.mkdir(mode=0o700); sessions=work/'sessions'; sessions.mkdir(mode=0o700)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    key.chmod(0o600)
    def hashed(value):return subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',value],text=True)
    config=work/'account.json'; config.write_text(json.dumps({'username':'demo','subject':'demo-account','hash':hashed('Correct-test-password'),'version':'1'})); config.chmod(0o600)
    with socket.socket() as probe:probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_AUTH_EXAMPLE_')}
    import base64
    env.update(SOSECURITY_AUTH_EXAMPLE_CONFIG=str(config),SOSECURITY_AUTH_EXAMPLE_STORAGE=str(storage),SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH=hashed('Dummy-test-password'),SOSECURITY_AUTH_EXAMPLE_REMEMBER_KEY=base64.b64encode(os.urandom(32)).decode())
    with open(work/'server.log','w+') as log:
        php=subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'examples')],env=env,stdout=log,stderr=log)
        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self,*unused):pass
            def request(self):
                length=int(self.headers.get('Content-Length','0'))
                if length<0 or length>8192:self.send_error(413);return
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
                try:
                    connection.request(self.command,self.path,self.rfile.read(length),{k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','transfer-encoding','content-length')})
                    response=connection.getresponse();data=response.read(65537)
                    if len(data)>65536:raise RuntimeError('TLS test response budget exceeded')
                    self.send_response(response.status)
                    for name,value in response.getheaders():
                        if name.lower() not in ('connection','transfer-encoding','content-length','server','date'):self.send_header(name,value)
                    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                finally:connection.close()
            do_GET=request;do_POST=request
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(str(cert),str(key));server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start(); url=f'https://localhost:{server.server_port}/authentication.php'
        try:
            for _ in range(100):
                if php.poll() is not None:log.seek(0);raise RuntimeError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('TLS backend startup timed out')
            jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))))
            def call(action=None,fields=None,csrf=''):
                body=None if action is None else urllib.parse.urlencode(dict(fields or {},action=action,_csrf=csrf)).encode()
                try:response=client.open(urllib.request.Request(url,data=body,headers={'Accept':'application/json'}),timeout=10)
                except urllib.error.HTTPError as error:response=error
                with response:check('no-store',response.headers['Cache-Control']);return response.status,json.load(response),response.headers
            status,data,_=call();check(200,status)
            status,data,_=call('login',{'username':'demo','password':'Correct-test-password'},data['csrf']);check(200,status)
            status,data,headers=call('remember',csrf=data['csrf']);check(200,status)
            persistent=next(c for c in jar if c.name=='__Host-SoSecurityRemember'); original=persistent.value
            check(True,persistent.secure);check('/',persistent.path);check(False,persistent.domain_specified);check(True,persistent.has_nonstandard_attr('HttpOnly'))
            check('Lax',persistent.get_nonstandard_attr('SameSite'));check(True,persistent.expires>time.time())
            header=next(h for h in headers.get_all('Set-Cookie') if h.startswith('__Host-SoSecurityRemember='));check(False,'Domain=' in header)
            jar.clear();jar.set_cookie(copy.copy(persistent));status,data,_=call();check('anonymous',data['stage'])
            status,data,headers=call('restore',csrf=data['csrf']);check(200,status);check(True,data['session']['resumed'])
            check(False,original==next(c.value for c in jar if c.name=='__Host-SoSecurityRemember'))
            status,data,_=call('sensitive',csrf=data['csrf']);check(403,status);check('auth.reauthentication_required',data['error'])
            status,data,_=call('logout',csrf=data['csrf']);check(200,status);check(False,any(c.name=='__Host-SoSecurityRemember' for c in jar))
            print(f'PASS real TLS persistent login: {checks} assertions on {runtime}; private CA verification, Secure/HttpOnly/__Host Cookie, rotation, freshness and logout')
        finally:
            server.shutdown();server.server_close();php.terminate()
            try:php.wait(timeout=5)
            except subprocess.TimeoutExpired:php.kill();php.wait()
