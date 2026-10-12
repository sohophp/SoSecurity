#!/usr/bin/env python3
"""Real local HTTP boundary using an independent Python signer; never sends production credentials."""
import argparse, base64, json, os, socket, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from api_vectors import signed_headers
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php72');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent; checks=0

def check(expected,actual):
    global checks
    checks+=1
    assert expected==actual,(expected,actual)
with tempfile.TemporaryDirectory(prefix='sosecurity-api-http-') as directory:
    storage=Path(directory,'storage');storage.mkdir(mode=0o700)
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    origin='http://127.0.0.1:'+str(port);env=os.environ.copy();env.update(SOSECURITY_TEST_API_STORAGE=str(storage),SOSECURITY_TEST_API_ORIGIN=origin)
    with open(Path(directory,'server.log'),'w+') as log:
        server=subprocess.Popen([args.runtime,'-S','127.0.0.1:'+str(port),str(root/'tests/http-api.php')],env=env,stdout=log,stderr=log)
        def request(target,body=b'',headers=None,method='POST'):
            req=urllib.request.Request(origin+target,data=body,headers=headers or {},method=method)
            try:response=urllib.request.urlopen(req,timeout=5)
            except urllib.error.HTTPError as error:response=error
            with response:return response.status,json.load(response)
        def sign(target,body=b'{}',method='POST',created=None,lifetime=60,key_id='python-http-key',nonce=None):
            return signed_headers(method,origin+target,body,'application/json',int(time.time()) if created is None else created,lifetime,nonce or 'nonce_'+os.urandom(16).hex(),key_id,b'k'*32)
        try:
            for _ in range(100):
                if server.poll() is not None:raise RuntimeError('API HTTP server exited')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('API HTTP startup failed')
            target='/signed?q=a%20b&x=1&x=2';body=b'{"name":"'+ '中文'.encode()+b'"}'
            headers=sign(target,body)
            status,result=request(target,body,headers);check(200,status);check('http-client',result['subject'])
            check(401,request(target,body,headers)[0])
            headers=sign(target,body);check(401,request(target,body+b' ',headers)[0]);check(200,request(target,body,headers)[0])
            headers=sign(target,body);changed=dict(headers);changed['Content-Type']='text/plain';check(401,request(target,body,changed)[0]);check(200,request(target,body,headers)[0])
            headers=sign(target,body);check(401,request(target+'&x=3',body,headers)[0]);check(200,request(target,body,headers)[0])
            check(401,request(target,body,sign(target,body,created=int(time.time())-121))[0])
            check(401,request(target,body,sign(target,body,created=int(time.time())+121))[0])
            check(401,request(target,body,sign(target,body,lifetime=301))[0])
            check(401,request(target,body,sign(target,body,key_id='unknown'))[0])
            check(401,request('/signed-write',b'{}',sign('/signed-write'))[0])
            check(200,request('/signed',bytes(range(256)),sign('/signed',bytes(range(256))))[0])
            check(413,request('/signed',b'x'*1025,sign('/signed',b'x'*1025))[0])
            for fault,reason in [('store','storage.unavailable'),('provider','api.key_provider')]:
                target='/signed?fault='+fault;headers=sign(target);status,result=request(target,b'{}',headers);check(503,status);check(reason,result['reason']);check(False,'private' in json.dumps(result))
            target='/signed?fault=store';bad=sign(target);bad['Signature']='sig1=:'+base64.b64encode(b'x'*32).decode()+':'
            check(401,request(target,b'{}',bad)[0])
            status,credential=request('/test-issue');check(200,status)
            check(200,request('/bearer',headers={'Authorization':'Bearer '+credential['token']})[0])
            check(401,request('/bearer',headers={'Authorization':'Bearer '+credential['token'][:-1]+'z'})[0])
            check(200,request('/test-revoke',urllib.parse.urlencode({'id':credential['id']}).encode(),{'Content-Type':'application/x-www-form-urlencoded'})[0])
            check(401,request('/bearer',headers={'Authorization':'Bearer '+credential['token']})[0])
            print('PASS {}: {} real HTTP API assertions; Python signatures, raw body/query/Content-Type, replay, scope, fault, bearer revocation'.format(args.runtime,checks))
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait()
