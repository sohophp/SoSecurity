#!/usr/bin/env python3
"""Real local HTTP authority contract; does not claim a production identity provider or TLS acceptance."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

runtime=sys.argv[1] if len(sys.argv)>1 else 'php';root=Path(__file__).resolve().parent.parent;checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
state={'offline':False,'enabled':True,'version':'1','roles':['member'],'scope':'tenant','extra':False}
class Authority(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        if self.headers.get('Authorization')!='Bearer fixed-integration-service':self.send_response(401);self.end_headers();return
        if state['offline']:self.send_response(503);self.end_headers();return
        length=int(self.headers.get('Content-Length','0'))
        if length>4096:self.send_response(413);self.end_headers();return
        request=json.loads(self.rfile.read(length));account=None;code=200
        if self.path=='/authenticate':
            if request.get('identifier')!='demo' or request.get('password')!='remote-test-password':code=401
            elif state['enabled']:account={'scope':state['scope'],'subject':'remote-subject','version':state['version'],'enabled':True,'roles':state['roles'],'mfa_required':False}
        elif self.path=='/current' and request.get('subject')=='remote-subject' and state['enabled']:
            account={'scope':state['scope'],'subject':'remote-subject','version':state['version'],'enabled':True,'roles':state['roles'],'mfa_required':False}
        if account is not None and state['extra']:account['is_admin']=True
        data=json.dumps({'account':account}).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
with tempfile.TemporaryDirectory(prefix='sosecurity-authority-') as directory:
    os.chmod(directory,0o700);server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Authority);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    env=os.environ.copy();env.update(SOSECURITY_TEST_AUTHORITY=f'http://127.0.0.1:{server.server_port}',SOSECURITY_TEST_AUTHORITY_STORAGE=directory)
    def call(operation,**fields):
        result=subprocess.run([runtime,str(root/'tests/remote-auth.php')],input=json.dumps(dict(fields,operation=operation)),capture_output=True,text=True,env=env,check=True)
        check('',result.stderr);return json.loads(result.stdout)
    try:
        check('denied',call('login',password='wrong')['status'])
        result=call('login',password='remote-test-password');check('authenticated',result['status']);token=result['token']
        check(True,call('verify',token=token)['valid'])
        state['offline']=True;check('auth.source_unavailable',call('verify',token=token)['error']);state['offline']=False
        check(True,call('verify',token=token)['valid'])
        state['roles']=['reader'];check(False,call('verify',token=token)['valid'])
        token=call('login',password='remote-test-password')['token'];state['version']='2';check(False,call('verify',token=token)['valid'])
        token=call('login',password='remote-test-password')['token'];state['enabled']=False;check(False,call('verify',token=token)['valid'])
        state['enabled']=True;state['version']='3';check(False,call('verify',token=token)['valid'])
        state['scope']='other-tenant';check('auth.provider',call('login',password='remote-test-password')['error'])
        state['scope']='tenant';state['extra']=True;check('auth.provider',call('login',password='remote-test-password')['error'])
        print(f'PASS remote authority HTTP contract: {checks} assertions; fresh scope/version/role/disable checks, bounded I/O and outage refusal; isolated test service only')
    finally:server.shutdown();server.server_close();thread.join(timeout=5)
