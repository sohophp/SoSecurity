#!/usr/bin/env python3
"""Native transport integration in a disposable Linux network namespace, with a per-process test CA."""
import argparse, gzip, http.server, json, os, shutil, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.parse
from pathlib import Path
root=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser();parser.add_argument('runtimes',nargs='*',default=['php']);parser.add_argument('--inside');args=parser.parse_args()
if not args.inside:
    if sys.platform!='linux' or not shutil.which('unshare') or not shutil.which('ip') or not shutil.which('openssl'):
        print('NOT RUN native transport: Linux unshare/ip/OpenSSL required');sys.exit(1 if os.getenv('SOSECURITY_REQUIRE_NATIVE_HTTP')=='1' else 0)
    with tempfile.TemporaryDirectory(prefix='sosecurity-network-') as directory:
        base=Path(directory)
        def openssl(*options):
            result=subprocess.run(['openssl',*options],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if result.returncode: raise RuntimeError('Private test certificate generation failed')
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=SoSecurity integration CA','-keyout',str(base/'ca.key'),'-out',str(base/'ca.crt'))
        openssl('req','-newkey','rsa:2048','-nodes','-subj','/CN=api.example.com','-keyout',str(base/'server.key'),'-out',str(base/'server.csr'))
        (base/'extensions').write_text('subjectAltName=DNS:api.example.com,DNS:cdn.example.com,DNS:rebind.example.com,DNS:v6.example.com,DNS:dns.google\n')
        openssl('x509','-req','-in',str(base/'server.csr'),'-CA',str(base/'ca.crt'),'-CAkey',str(base/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(base/'extensions'),'-out',str(base/'server.crt'))
        command=['sudo','-n','unshare','--net','--',sys.executable,str(Path(__file__).resolve()),'--inside',directory]
        command.extend(shutil.which(runtime) or runtime for runtime in args.runtimes)
        subprocess.run(command,check=True,timeout=90)
    sys.exit(0)
base=Path(args.inside)
subprocess.run(['ip','link','set','lo','up'],check=True)
for address in ['8.8.8.8/32','1.1.1.1/32','2001:4860:4860::8888/128']:
    subprocess.run(['ip','address','add',address,'dev','lo'],check=True)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(base/'server.crt'),str(base/'server.key'))
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'; rebind=0
    def log_message(self,*unused): pass
    def send(self,status,body=b'',headers=None):
        try:
            self.send_response(status)
            for name,value in (headers or {}).items(): self.send_header(name,value)
            self.send_header('Content-Length',str(len(body)));self.end_headers()
            if self.command!='HEAD':self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
    def do_HEAD(self):self.do_GET()
    def do_POST(self):
        data=self.rfile.read(int(self.headers.get('Content-Length','0')))
        if self.path=='/redirect':self.send(302,headers={'Location':'https://cdn.example.com/ok'})
        else:self.send(200,b'POST:'+data)
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path)
        if path.path=='/resolve':
            query=urllib.parse.parse_qs(path.query);host=query['name'][0];kind=int(query['type'][0]);answers=[]
            if host=='dns-slow.example.com':time.sleep(2)
            if kind==1:
                if host=='rebind.example.com':
                    Handler.rebind+=1;ip='8.8.8.8' if Handler.rebind==1 else '127.0.0.1'
                else:ip='1.1.1.1' if host=='cdn.example.com' else '8.8.8.8'
                if host!='v6.example.com':answers=[{'name':host+'.','type':1,'data':ip}]
            elif host=='v6.example.com':answers=[{'name':host+'.','type':28,'data':'2001:4860:4860::8888'}]
            self.send(200,json.dumps({'Status':0,'Question':[{'name':host+'.','type':kind}],'Answer':answers}).encode(),{'Content-Type':'application/json'});return
        if path.path=='/redirect':self.send(302,headers={'Location':'https://cdn.example.com/ok'})
        elif path.path=='/private':self.send(302,headers={'Location':'https://127.0.0.1/ok'})
        elif path.path=='/start':self.send(302,headers={'Location':'/next'})
        elif path.path=='/loop':self.send(302,headers={'Location':'/loop'})
        elif path.path=='/large':self.send(200,b'x'*100000)
        elif path.path=='/gzip':self.send(200,gzip.compress(b'x'*1000000),{'Content-Encoding':'gzip'})
        elif path.path=='/headers':self.send(200,headers={'X-Padding':'x'*20000})
        elif path.path=='/folded':
            try:self.wfile.write(b'HTTP/1.1 200 OK\r\nX-A: value\r\n continued\r\nContent-Length: 0\r\n\r\n')
            except OSError:pass
        elif path.path=='/cookie':self.send(200,b'cookie-set',{'Set-Cookie':'fake_session=fixture-only'})
        elif path.path=='/cookie-check':self.send(200,b'no-cookie' if not self.headers.get('Cookie') else b'cookie-leaked')
        elif path.path=='/slow':time.sleep(2);self.send(200,b'late')
        else:
            if self.headers.get('Host')=='cdn.example.com':
                self.send(200,b'credentials-not-forwarded' if not self.headers.get('Authorization') and not self.headers.get('X-Test') else b'credential-leak')
            else:self.send(200,b'bounded-ok')
class Server(http.server.ThreadingHTTPServer):daemon_threads=True
class V6Server(Server):
    address_family=socket.AF_INET6
    def server_bind(self):self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);super().server_bind()
servers=[Server(('0.0.0.0',443),Handler),V6Server(('::',443),Handler)]
for server in servers:
    server.socket=context.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
env=os.environ.copy();env['SOSECURITY_TEST_NATIVE_HTTP']='1';env['HTTPS_PROXY']='http://127.0.0.1:9';env['ALL_PROXY']='http://127.0.0.1:9'
try:
    for runtime in args.runtimes:
        Handler.rebind=0
        subprocess.run([runtime,'-d','curl.cainfo='+str(base/'ca.crt'),str(root/'tests/native-outbound.php')],env=env,check=True,timeout=20)
finally:
    for server in servers:server.shutdown();server.server_close()
print('PASS native namespace: public IPv4/IPv6 pins, isolated TLS CA, no host routes or trust store changed')
