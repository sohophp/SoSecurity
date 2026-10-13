#!/usr/bin/env python3
"""Additional CAPTCHA HTTP acceptance; native PHP, private sessions, no provider credentials."""
import argparse, base64, http.cookiejar, json, os, re, socket, subprocess, tempfile, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
checks=0

def check(expected,actual):
    global checks
    checks+=1
    assert expected==actual,(expected,actual)

def accept(base):
    visitor=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    token=None
    def call(action=None, **fields):
        nonlocal token
        if action: fields.update(action=action,_csrf=token)
        request=urllib.request.Request(base+'?module=captcha',data=urllib.parse.urlencode(fields).encode() if action else None,headers={'Accept':'application/json'})
        try: response=visitor.open(request,timeout=10)
        except urllib.error.HTTPError as error: response=error
        with response:
            result=json.load(response);token=result.get('controls_token',token)
            return response.status,result,response.headers
    check(200,call()[0])
    for action in ['math','subtract','multiply','divide','mixed']:
        status,data,_=call(action);check(200,status)
        challenge=data['state']['challenge'];left,op,right=re.match(r'^(\d+) ([+*/-]) (\d+) = \?$',challenge['prompt']).groups()
        left,right=int(left),int(right)
        answer={'+':lambda:left+right,'-':lambda:left-right,'*':lambda:left*right,'/':lambda:left//right}[op]()
        check(200,call('verify',challenge_id=challenge['id'],answer=str(answer))[0])
        check(403,call('verify',challenge_id=challenge['id'],answer=str(answer))[0])
    for action in ['image','digits','letters','image_math','slider','click']:
        status,data,_=call(action);check(200,status);challenge=data['state']['challenge']
        check(b'\x89PNG\r\n\x1a\n',base64.b64decode(challenge['image'].split(',')[1])[:8])
        check(False,'answer' in challenge);check(False,'digest' in json.dumps(challenge))
        check(False,'target_x' in json.dumps(challenge));check(False,'alternatives' in json.dumps(challenge))
        if action=='slider':
            check('slider',challenge['presentation']['kind']);check(40,challenge['presentation']['piece_width'])
            check(b'\x89PNG\r\n\x1a\n',base64.b64decode(challenge['presentation']['piece'].split(',')[1])[:8])
        elif action=='click': check('click',challenge['presentation']['kind']);check(3,challenge['presentation']['count'])
        else: check('',challenge['prompt'])
        check(403,call('verify',challenge_id=challenge['id'],answer='-1')[0])
        check(403,call('verify',challenge_id=challenge['id'],answer='999999')[0])
        check(403,call('verify',challenge_id=challenge['id'],answer='0,0,0')[0])
    _,data,_=call('math');old=data['state']['challenge'];left,_,right=old['prompt'].split(' ',2);old_answer=int(left)+int(right.split(' ')[0])
    call('refresh');check(403,call('verify',challenge_id=old['id'],answer=str(old_answer))[0])
    for provider in ['turnstile','hcaptcha','recaptcha','recaptcha_v3']:
        _,data,headers=call()
        if data['state'][provider+'_configured']:
            print('NOT RUN real provider '+provider+': HTTP acceptance does not obtain external challenge tokens')
        else: check(503,call(provider)[0])
    with visitor.open(base+'?module=captcha',timeout=10) as response:
        html=response.read().decode()
        for action in ['digits','letters','subtract','multiply','divide','image_math','slider','click']:
            check(True,'value="'+action+'"' in html)
        check(False,'siteverify' in html)
        for provider,host in [('turnstile','challenges.cloudflare.com'),('hcaptcha','hcaptcha.com'),('recaptcha','www.google.com')]:
            if not data['state'][provider+'_configured']: check(False,host in response.headers['Content-Security-Policy'])
    print(f'PASS extended CAPTCHA HTTP: {checks} assertions; new generators, server rejection, exhaustion, refresh, provider-not-configured refusal')

if args.url: accept(args.url.rstrip('/')+'/')
else:
    with tempfile.TemporaryDirectory(prefix='sosecurity-captcha-http-') as directory:
        base=Path(directory);(base/'storage').mkdir(mode=0o700);(base/'sessions').mkdir(mode=0o700)
        with socket.socket() as probe: probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        env=os.environ.copy();env['SOSECURITY_DEMO_STORAGE']=str(base/'storage')
        for name in list(env):
            if name.startswith(('SOSECURITY_DEMO_TURNSTILE_','SOSECURITY_DEMO_HCAPTCHA_','SOSECURITY_DEMO_RECAPTCHA_')): env.pop(name)
        with (base/'server.log').open('w+') as log:
            server=subprocess.Popen([args.runtime,'-d','session.save_path='+str(base/'sessions'),'-S','127.0.0.1:'+str(port),'-t',str(root/'demo/public')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None: raise RuntimeError('Isolated CAPTCHA HTTP server exited')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1): break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Isolated server startup timed out')
                accept('http://127.0.0.1:'+str(port)+'/')
            finally:
                server.terminate();server.wait(timeout=5);log.seek(0)
                output=log.read()
                assert not any(text in output for text in ['PHP Fatal','PHP Warning','PHP Deprecated']),output
