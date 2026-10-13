#!/usr/bin/env python3
import argparse, http.cookiejar, json, os, socket, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');parser.add_argument('--browser',action='store_true');args=parser.parse_args()
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
            except ValueError:raise RuntimeError('HTML demo returned HTTP {}; run native suites in separate rate windows (entry budget remains enabled)'.format(response.status))
            controls=result.get('controls_token',controls);return response.status,result
    check(200,call('html')[0]);status,result=call('html','normal');check(200,status);check(True,'<strong>' in result['result']['output'])
    status,result=call('html','attack');check(200,status);check('<p>安全文字</p>',result['result']['output']);check(True,result['result']['changed'])
    status,result=call('html','links',{'html':'<a href="https://example.com" onclick="bad()">好</a><a href="javascript:bad()">坏</a>'});check(200,status);check(False,result['result']['preview']);check(True,'href="https://example.com"' in result['result']['output']);check(False,'javascript' in result['result']['output'])
    for action,reason in [('size_limit','html.input_limit'),('tree_limit','html.tree_limit')]:
        status,result=call('html',action);check(422,status);check(reason,result['result']['reason'])
    status,result=call('html','provider_failure');check(503,status);check('html.provider',result['result']['reason']);check(False,'private' in json.dumps(result['result']))
    check(400,call('html','clean',{'html[]':'array'})[0])
    request=urllib.request.Request(base+'?module=html',data=urllib.parse.urlencode({'action':'normal','_csrf':'forged'}).encode(),headers={'Accept':'application/json'})
    try:response=browser.open(request,timeout=8)
    except urllib.error.HTTPError as error:response=error
    with response:check(403,response.status)
    print('PASS HTML demo: {} assertions; native cleanup/links, resource/dependency failure, inert raw output and CSRF'.format(checks))
    if args.browser:subprocess.run(['node',str(root/'tests/html-browser.cjs'),base],env=os.environ.copy(),check=True,timeout=60)

if args.url:acceptance(args.url.rstrip('/')+'/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-html-demo-') as directory:
        storage=Path(directory,'storage');storage.mkdir(mode=0o700);sessions=Path(directory,'sessions');sessions.mkdir(mode=0o700)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        env=os.environ.copy();env['SOSECURITY_DEMO_STORAGE']=str(storage)
        with open(Path(directory,'server.log'),'w+') as log:
            server=subprocess.Popen([args.runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:raise RuntimeError('HTML demo server exited')
                    try:urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=.2).close();break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('HTML demo startup failed')
                acceptance(f'http://127.0.0.1:{port}/')
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
