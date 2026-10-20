#!/usr/bin/env python3
"""Native HIBP-shaped HTTPS in a private network/hosts mount; no real passwords or host CA changes."""
import argparse, hashlib, http.server, json, os, shutil, socketserver, ssl, subprocess, sys, tempfile, threading, time, urllib.parse
from pathlib import Path
root=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser();parser.add_argument('runtimes',nargs='*',default=['php']);parser.add_argument('--inside');args=parser.parse_args()
if not args.inside:
    if sys.platform!='linux' or not all(shutil.which(tool) for tool in ['sudo','unshare','mount','ip','openssl']):
        print('NOT RUN native password HTTPS: Linux namespace/process tools required');sys.exit(1 if os.getenv('SOSECURITY_REQUIRE_NATIVE_HTTP')=='1' else 0)
    with tempfile.TemporaryDirectory(prefix='sosecurity-password-native-') as directory:
        base=Path(directory)
        def cert(*options):subprocess.run(['openssl',*options],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        cert('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Private Password Test CA','-keyout',str(base/'ca.key'),'-out',str(base/'ca.crt'))
        cert('req','-newkey','rsa:2048','-nodes','-subj','/CN=api.pwnedpasswords.com','-keyout',str(base/'server.key'),'-out',str(base/'server.csr'))
        (base/'extensions').write_text('subjectAltName=DNS:api.pwnedpasswords.com,DNS:dns.google\n')
        cert('x509','-req','-in',str(base/'server.csr'),'-CA',str(base/'ca.crt'),'-CAkey',str(base/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(base/'extensions'),'-out',str(base/'server.crt'))
        (base/'hosts').write_text('127.0.0.1 localhost api.pwnedpasswords.com\n')
        subprocess.run(['sudo','-n','unshare','--net','--mount','--propagation','private','--',sys.executable,str(Path(__file__).resolve()),'--inside',directory,*[shutil.which(runtime) or runtime for runtime in args.runtimes]],check=True,timeout=120)
    sys.exit(0)
base=Path(args.inside);subprocess.run(['ip','link','set','lo','up'],check=True);subprocess.run(['mount','--bind',str(base/'hosts'),'/etc/hosts'],check=True);subprocess.run(['mount','-o','remount,bind,ro','/etc/hosts'],check=True)
for address in ['8.8.8.8','93.184.216.34']:subprocess.run(['ip','addr','add',address+'/32','dev','lo'],check=True)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(base/'server.crt'),str(base/'server.key'))
modes={};requests=[];doh_slow=False
for mode in ['pwned','clean','padding','malformed','redirect','unavailable','body-limit','header-limit','slow']:
    digest=hashlib.sha1(('Native-public-'+mode+'-password').encode()).hexdigest().upper();modes[digest[:5]]=(mode,digest[5:])
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*unused):pass
    def do_GET(self):
        requests.append((self.path,{k.lower():v for k,v in self.headers.items()}))
        if self.headers.get('Host')=='dns.google':
            query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query);kind=int(query['type'][0]);host=query['name'][0]
            if doh_slow:time.sleep(.8)
            body=json.dumps({'Status':0,'Question':[{'name':host+'.','type':kind}],'Answer':([{'name':host+'.','type':1,'data':'93.184.216.34'}] if kind==1 else [])}).encode()
            try:self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
            return
        prefix=self.path.removeprefix('/range/');mode,suffix=modes.get(prefix,('unexpected','0'*35))
        body=(suffix+':'+('3' if mode=='pwned' else '0')+'\r\n').encode();status=200
        if mode=='clean':body=('F'*35+':4\r\n').encode()
        if mode=='malformed':body+=b'invalid'
        if mode=='redirect':status=302
        if mode=='unavailable':status=503
        if mode=='body-limit':body=b'A'*262145
        if mode=='slow':time.sleep(.8)
        if mode=='unexpected':status=404
        try:
            self.send_response(status)
            if mode=='redirect':self.send_header('Location','https://api.pwnedpasswords.com/should-not-follow')
            if mode=='header-limit':self.send_header('X-Oversize','a'*17000)
            self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
server=http.server.ThreadingHTTPServer(('0.0.0.0',443),Handler);server.daemon_threads=True;server.socket=context.wrap_socket(server.socket,server_side=True);threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    for runtime in args.runtimes:
        requests.clear();env=os.environ.copy();env.update(HTTPS_PROXY='http://127.0.0.1:9',ALL_PROXY='http://127.0.0.1:9',NO_PROXY='');env.pop('SOSECURITY_PASSWORD_BAD_CA',None)
        subprocess.run([runtime,'-d','curl.cainfo='+str(base/'ca.crt'),str(root/'tests/native-password.php')],env=env,check=True,timeout=15)
        assert len([r for r in requests if r[1].get('host')=='api.pwnedpasswords.com'])==9,requests
        for path,headers in requests:
            if headers.get('host')=='dns.google':
                assert urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['name']==['api.pwnedpasswords.com'];continue
            assert path.startswith('/range/') and path[7:] in modes,path
            assert headers.get('add-padding')=='true' and headers.get('host')=='api.pwnedpasswords.com',headers
            assert not any(k.lower() in ['cookie','authorization'] for k in headers),headers
            assert len(path)==12,path
        env['SOSECURITY_PASSWORD_BAD_CA']='1';subprocess.run([runtime,str(root/'tests/native-password.php')],env=env,check=True,timeout=15)
    # Exercise DNS itself, not just a slow HTTP response: isolated resolv.conf and an intentionally silent local resolver.
    (base/'hosts-dns').write_text('127.0.0.1 localhost\n');(base/'resolv').write_text('nameserver 127.0.0.1\noptions timeout:5 attempts:2\n')
    subprocess.run(['mount','--bind',str(base/'hosts-dns'),'/etc/hosts'],check=True);subprocess.run(['mount','--bind',str(base/'resolv'),'/etc/resolv.conf'],check=True)
    queries=[]
    class SilentDns(socketserver.BaseRequestHandler):
        def handle(self):queries.append(len(self.request[0]))
    dns=socketserver.UDPServer(('127.0.0.1',53),SilentDns);threading.Thread(target=dns.serve_forever,daemon=True).start()
    try:
        for runtime in args.runtimes:
            queries.clear();env=os.environ.copy();env['SOSECURITY_PASSWORD_DNS_PINNING']='1';env.pop('SOSECURITY_PASSWORD_BAD_CA',None)
            doh_slow=False;started=time.monotonic();subprocess.run([runtime,'-d','curl.cainfo='+str(base/'ca.crt'),str(root/'tests/native-password.php')],env=env,check=True,timeout=3)
            assert not queries and time.monotonic()-started<2.5,(runtime,'Unexpected OS DNS or deadline overrun')
            env.pop('SOSECURITY_PASSWORD_DNS_PINNING');env['SOSECURITY_PASSWORD_DNS_TIMEOUT']='1';doh_slow=True
            started=time.monotonic();subprocess.run([runtime,'-d','curl.cainfo='+str(base/'ca.crt'),str(root/'tests/native-password.php')],env=env,check=True,timeout=3)
            assert not queries and .4<=time.monotonic()-started<2.5,(runtime,'DNS exceeded bounded rejection or failed before timeout')
    finally:dns.shutdown();dns.server_close()
finally:server.shutdown();server.server_close()
