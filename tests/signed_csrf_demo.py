#!/usr/bin/env python3
import argparse, http.cookiejar, json, os, socket, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
def acceptance(base):
    browser=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));controls=None
    def call(module,action=None,fields=None):
        nonlocal controls
        data=None
        if action is not None:
            values=dict(fields or {});values.update(action=action,_csrf=controls);data=urllib.parse.urlencode(values).encode()
        request=urllib.request.Request(base+'?module='+module,data=data,headers={'Accept':'application/json'})
        try:response=browser.open(request,timeout=8)
        except urllib.error.HTTPError as error:response=error
        with response:
            try:result=json.load(response)
            except ValueError:raise RuntimeError('Signed-CSRF demo returned HTTP {}; run native suites in separate rate windows (entry budget remains enabled)'.format(response.status))
            controls=result.get('controls_token',controls);return response.status,result
    check(200,call('stateless')[0]);status,result=call('stateless','issue');check(200,status);token=result['state']['token']
    check(200,call('stateless','verify',{'token':token})[0]);check(200,call('stateless','reuse',{'token':token})[0])
    check(200,call('stateless','double',{'token':token})[0]);check(403,call('stateless','cookie_mismatch',{'token':token})[0])
    for action in ['tamper','cross_scope','cross_binding']:check(403,call('stateless',action,{'token':token})[0])
    check(200,call('stateless','issue')[0]);check(token,call('stateless')[1]['state']['token'])
    check(200,call('stateless','rotate_keep')[0]);check(200,call('stateless','verify',{'token':token})[0])
    check(200,call('stateless','rotate_drop')[0]);check(403,call('stateless','verify',{'token':token})[0])
    _,result=call('stateless','issue');token=result['state']['token'];check(200,call('stateless','verify',{'token':token})[0])
    check(200,call('stateless','binding_change')[0]);check(403,call('stateless','verify',{'token':token})[0])
    _,result=call('stateless','issue');token=result['state']['token'];check(200,call('stateless','expire')[0]);check(403,call('stateless','verify',{'token':token})[0])
    check(400,call('stateless','bad_key')[0])
    for path,required in [('/hooks/demo',False),('/hooks/demo/child',True),('/account/change',True)]:
        status,result=call('stateless','policy',{'method':'POST','path':path});check(200,status);check(required,result['result']['requires_token'])
    check(400,call('stateless','policy',{'method':'POST','path':'/hooks/demo?x=1'})[0])
    check(False,'secret' in json.dumps(result.get('state',{})));req=urllib.request.Request(base+'?module=stateless',data=urllib.parse.urlencode({'_csrf':'bad-controls','action':'issue'}).encode(),headers={'Accept':'application/json'})
    try:response=browser.open(req,timeout=8)
    except urllib.error.HTTPError as error:response=error
    with response:check(403,response.status)
    print('PASS signed-CSRF demo: {} assertions; cookie double submit, scope/login binding, reuse/expiry, key rotation, exact exemption preview'.format(checks))

if args.url:acceptance(args.url.rstrip('/')+'/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-signed-demo-') as directory:
        storage=Path(directory,'storage');storage.mkdir(mode=0o700);sessions=Path(directory,'sessions');sessions.mkdir(mode=0o700)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        env=os.environ.copy();env['SOSECURITY_DEMO_STORAGE']=str(storage)
        with open(Path(directory,'server.log'),'w+') as log:
            server=subprocess.Popen([args.runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:raise RuntimeError('Signed-CSRF demo server exited')
                    try:urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=.2).close();break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('Signed-CSRF demo startup failed')
                acceptance(f'http://127.0.0.1:{port}/')
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
