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
            except ValueError:raise RuntimeError('API demo returned HTTP {}; run native suites in separate rate windows (entry budget remains enabled)'.format(response.status))
            controls=result.get('controls_token',controls);return response.status,result
    check(200,call('api')[0]);check(403,call('api','check_key',{'api_token':'malformed'})[0])
    status,result=call('api','issue_key');check(200,status);token=result['result']['token'];check(False,'token' in result['state'])
    check(200,call('api','check_key',{'api_token':token})[0]);check(403,call('api','scope_key',{'api_token':token})[0])
    other=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    with other.open(urllib.request.Request(base+'?module=api',headers={'Accept':'application/json'}),timeout=8) as response:other_token=json.load(response)['controls_token']
    req=urllib.request.Request(base+'?module=api',data=urllib.parse.urlencode({'_csrf':other_token,'action':'check_key','api_token':token}).encode(),headers={'Accept':'application/json'})
    try:response=other.open(req,timeout=8)
    except urllib.error.HTTPError as error:response=error
    with response:check(403,response.status);check(False,json.load(response)['result']['valid'])
    status,result=call('api','rotate_key');check(200,status);replacement=result['result']['token'];check(False,replacement==token)
    check(403,call('api','check_key',{'api_token':token})[0]);check(200,call('api','check_key',{'api_token':replacement})[0])
    check(200,call('api','revoke_key')[0]);check(403,call('api','check_key',{'api_token':replacement})[0])
    check(200,call('api','sign')[0]);check(403,call('api','tamper')[0]);check(200,call('api','verify')[0]);check(403,call('api','replay')[0])
    check(403,call('api','expire')[0]);check(200,call('api','sign')[0]);status,result=call('api','store_failure');check(503,status);check('storage.unavailable',result['result']['reason'])
    check(False,'secret' in json.dumps(result['state']));check(200,call('api','verify')[0])
    print('PASS API demo: {} assertions; short-lived credential rotation/revocation, visitor isolation, signed request tamper/replay/expiry, explicit storage fault'.format(checks))

if args.url:acceptance(args.url.rstrip('/')+'/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-api-demo-') as directory:
        storage=Path(directory,'storage');storage.mkdir(mode=0o700);sessions=Path(directory,'sessions');sessions.mkdir(mode=0o700)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        env=os.environ.copy();env['SOSECURITY_DEMO_STORAGE']=str(storage)
        with open(Path(directory,'server.log'),'w+') as log:
            server=subprocess.Popen([args.runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:raise RuntimeError('API demo server exited')
                    try:urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=.2).close();break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('API demo startup failed')
                acceptance(f'http://127.0.0.1:{port}/')
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
