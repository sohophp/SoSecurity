#!/usr/bin/env python3
"""Native fixed-provider HTTPS transport, isolated network and hosts mounts; no real credentials."""
import argparse, http.server, json, os, shutil, ssl, subprocess, sys, tempfile, threading, time, urllib.parse
from pathlib import Path
root=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser();parser.add_argument('runtimes',nargs='*',default=['php']);parser.add_argument('--inside');args=parser.parse_args()
if not args.inside:
    if sys.platform!='linux' or not all(shutil.which(tool) for tool in ['unshare','ip','openssl','mount','sudo']):
        print('NOT RUN native CAPTCHA transport: Linux unshare/mount/ip/OpenSSL/sudo required')
        sys.exit(1 if os.getenv('SOSECURITY_REQUIRE_NATIVE_HTTP')=='1' else 0)
    with tempfile.TemporaryDirectory(prefix='sosecurity-native-captcha-') as directory:
        base=Path(directory)
        def openssl(*options):
            result=subprocess.run(['openssl',*options],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if result.returncode: raise RuntimeError('Private CAPTCHA certificate creation failed')
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=SoSecurity CAPTCHA Test CA','-keyout',str(base/'ca.key'),'-out',str(base/'ca.crt'))
        openssl('req','-newkey','rsa:2048','-nodes','-subj','/CN=api.hcaptcha.com','-keyout',str(base/'server.key'),'-out',str(base/'server.csr'))
        (base/'extensions').write_text('subjectAltName=DNS:api.hcaptcha.com,DNS:www.google.com,DNS:challenges.cloudflare.com\n')
        openssl('x509','-req','-in',str(base/'server.csr'),'-CA',str(base/'ca.crt'),'-CAkey',str(base/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(base/'extensions'),'-out',str(base/'server.crt'))
        (base/'hosts').write_text('127.0.0.1 localhost api.hcaptcha.com www.google.com challenges.cloudflare.com\n')
        subprocess.run(['sudo','-n','unshare','--net','--mount','--propagation','private','--',sys.executable,str(Path(__file__).resolve()),'--inside',directory,*[shutil.which(runtime) or runtime for runtime in args.runtimes]],check=True,timeout=120)
    sys.exit(0)
base=Path(args.inside)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['mount','--bind',str(base/'hosts'),'/etc/hosts'],check=True)
subprocess.run(['mount','-o','remount,bind,ro','/etc/hosts'],check=True)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(base/'server.crt'),str(base/'server.key'))
requests=[]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*unused): pass
    def do_POST(self):
        payload=urllib.parse.parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode());requests.append((self.headers['Host'],self.path,payload))
        token=payload.get('response',[''])[0]
        data={'success':token!='reject'}
        if self.headers['Host']=='www.google.com':
            data['hostname']='www.google.com'
            if payload.get('secret')==['native-test-secret-only-v3']: data.update(action='login',score=0.7)
        elif self.headers['Host']=='challenges.cloudflare.com': data.update(hostname='challenges.cloudflare.com',action='login')
        if token=='slow': time.sleep(9)
        body=json.dumps(data).encode();status=200
        if token=='malformed': body=b'{"success":"true"}'
        elif token=='redirect': status=302
        elif token=='unavailable': status=503
        elif token=='body-limit': body=b' ' * 16385
        try:
            self.send_response(status)
            if token=='redirect': self.send_header('Location','https://www.google.com/unexpected-redirect')
            if token=='header-limit': self.send_header('X-Oversize','a'*17000)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass
    def do_GET(self):
        requests.append(('unexpected-get',self.path,{}));self.send_response(500);self.end_headers()
server=http.server.ThreadingHTTPServer(('127.0.0.1',443),Handler);server.daemon_threads=True
server.socket=context.wrap_socket(server.socket,server_side=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    for index,runtime in enumerate(args.runtimes):
        requests.clear();env=os.environ.copy();env['HTTPS_PROXY']='http://127.0.0.1:9';env['ALL_PROXY']='http://127.0.0.1:9';env['NO_PROXY']='';env['SOSECURITY_CAPTCHA_TIMEOUT_CASE']='1' if index in [0,len(args.runtimes)-1] else '0'
        # v2 and v3 must each get their native provider response shape, independent of user inputs.
        subprocess.run([runtime,'-d','curl.cainfo='+str(base/'ca.crt'),str(root/'tests/native-captcha.php')],env=env,check=True,timeout=45)
        assert all(r[0]!='unexpected-get' for r in requests)
        assert all(r[2]['secret'] in [['native-test-secret-only'],['native-test-secret-only-v3']] for r in requests)
        assert all(r[2].get('sitekey')==['expected-site-key'] for r in requests if r[0]=='api.hcaptcha.com')
        assert all(r[1] in ['/siteverify','/recaptcha/api/siteverify','/turnstile/v0/siteverify'] for r in requests)
        env['SOSECURITY_CAPTCHA_BAD_CA']='1'
        subprocess.run([runtime,str(root/'tests/native-captcha.php')],env=env,check=True,timeout=45)
finally: server.shutdown();server.server_close()
