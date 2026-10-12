#!/usr/bin/env python3
import argparse, http.cookiejar, json, os, socket, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');parser.add_argument('--live',action='store_true');args=parser.parse_args()
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
            result=json.load(response);controls=result.get('controls_token',controls);return response.status,result
    check(200,call('http')[0]);status,result=call('http','redirect',{'target':'/SoSecurity/?module=home'});check(200,status);check('http://72.rocky.wsl/SoSecurity/?module=home',result['result']['location'])
    check(400,call('http','redirect',{'target':'//evil.invalid/'})[0])
    status,result=call('http','cors',{'origin':'http://72.rocky.wsl:3000','method':'GET','request_headers':'x-demo-token'});check(200,status);check(204,result['result']['preflight_status'])
    check(403,call('http','cors',{'origin':'http://evil.invalid','method':'GET','request_headers':'x-demo-token'})[0])
    status,result=call('http','permissions');check(200,status);check(True,result['result']['Permissions-Policy'].startswith('camera=()'))
    check(200,call('network')[0])
    for action,status,reason in [('private',400,'http.address'),('redirect_private',400,'http.address'),('rebind',400,'http.address'),('peer',503,'http.peer'),('oversize',503,'http.response_limit')]:
        actual,result=call('network',action);check(status,actual);check(reason,result['result']['reason'])
    if args.live:
        status,result=call('network','fetch');check(200,status);check(200,result['result']['status']);check(True,result['result']['bytes']>0);check(False,'body' in result['result'])
    print(f'PASS network demo: {checks} assertions; target/CORS/permissions, fixed refusal samples'+('; actual fixed HTTPS fetch' if args.live else '; no public network call'))
if args.url:acceptance(args.url.rstrip('/')+'/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-network-demo-') as directory:
        storage=Path(directory,'storage');storage.mkdir(mode=0o700);sessions=Path(directory,'sessions');sessions.mkdir(mode=0o700)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        env=os.environ.copy();env['SOSECURITY_DEMO_STORAGE']=str(storage)
        with open(Path(directory,'server.log'),'w+') as log:
            server=subprocess.Popen([args.runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:raise RuntimeError('Network demo server exited')
                    try:urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=.2).close();break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('Network demo startup failed')
                acceptance(f'http://127.0.0.1:{port}/')
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
