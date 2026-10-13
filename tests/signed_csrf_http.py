#!/usr/bin/env python3
"""Actual cookies/form/AJAX signed double-submit, private verified host identities and no PHP Session."""
import argparse, http.cookiejar, json, os, socket, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php72');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
with tempfile.TemporaryDirectory(prefix='sosecurity-signed-http-') as directory:
    config=Path(directory,'private.json');config.write_text(json.dumps({'secret_hex':os.urandom(32).hex(),'users':{user:{'credential':os.urandom(32).hex(),'binding':'verified-login-'+os.urandom(16).hex()} for user in ['alice','bob']}}));config.chmod(0o600)
    sessions=Path(directory,'sessions');sessions.mkdir(mode=0o700)
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    env=os.environ.copy();env['SOSECURITY_TEST_SIGNED_CSRF_CONFIG']=str(config);base='http://127.0.0.1:'+str(port)
    with open(Path(directory,'server.log'),'w+') as log:
        server=subprocess.Popen([args.runtime,'-d','session.auto_start=0','-d','session.save_path='+str(sessions),'-S','127.0.0.1:'+str(port),str(root/'tests/http-signed-csrf.php')],env=env,stdout=log,stderr=log)
        def browser():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def call(client,path,fields=None,headers=None):
            request=urllib.request.Request(base+path,data=None if fields is None else urllib.parse.urlencode(fields).encode(),headers=headers or {})
            try:response=client.open(request,timeout=5)
            except urllib.error.HTTPError as error:response=error
            with response:return response.status,response.headers,json.load(response)
        try:
            for _ in range(100):
                if server.poll() is not None:raise RuntimeError('Signed CSRF server exited')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('Signed CSRF startup failed')
            alice=browser();bob=browser();anonymous=browser()
            check(401,call(anonymous,'/form')[0]);check(401,call(anonymous,'/update',{'_csrf':'forged'})[0])
            check(200,call(alice,'/test-login',{'user':'alice'})[0]);check(200,call(bob,'/test-login',{'user':'bob'})[0])
            status,headers,result=call(alice,'/form');check(200,status);check(False,result['session_started']);token=result['token']
            check(True,'HttpOnly' in headers['Set-Cookie']);check(True,'SameSite=Lax' in headers['Set-Cookie']);check(False,'PHPSESSID' in headers['Set-Cookie'])
            check(token,call(alice,'/form')[2]['token']) # second tab doesn't replace valid pair
            check(403,call(alice,'/update',{})[0]);check(403,call(alice,'/update',{'_csrf':token+'x'})[0])
            status,_,result=call(alice,'/update',{'_csrf':token});check(200,status);check(False,result['session_started'])
            check(200,call(alice,'/update',{'_csrf':token})[0]);check(200,call(alice,'/update',{}, {'X-CSRF-Token':token})[0])
            check(403,call(alice,'/update',{'_csrf':token},{'X-CSRF-Token':'different'})[0])
            bob_token=call(bob,'/form')[2]['token'];check(403,call(bob,'/update',{'_csrf':token})[0])
            # Attacker's correctly signed token put in both Cookie and submitted field cannot pass Alice binding.
            alice_auth=json.loads(config.read_text())['users']['alice']['credential']
            check(403,call(alice,'/update',{'_csrf':bob_token},{'Cookie':'test-auth='+alice_auth+'; test-csrf='+bob_token})[0])
            check(403,call(alice,'/update',{'_csrf':token},{'Cookie':'test-auth='+alice_auth})[0])
            check(405,call(alice,'/update')[0]);check(404,call(alice,'/update/alias',{'_csrf':token})[0]);check([],list(sessions.iterdir()))
            check(False,any(path.suffix=='.json' and path.name!='private.json' for path in Path(directory).iterdir()))
            print('PASS {}: {} real signed-CSRF HTTP assertions; stable multitab cookie, form/header, injection/identity mismatch, no PHP Session/token state'.format(args.runtime,checks))
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait()
