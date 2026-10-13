#!/usr/bin/env python3
"""Optional real CoreRepo component pilot; isolated worktree, fresh SoSecurity consumer and test identity only."""
import http.cookiejar, json, os, re, socket, subprocess, sys, tempfile, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path
root=Path(__file__).resolve().parent.parent
runtime=sys.argv[1] if len(sys.argv)>1 else 'php72'
core=Path(sys.argv[2]).resolve()
host_autoload=Path(sys.argv[3]).resolve()
assert (core/'App/Components/Session/Session.php').is_file() and host_autoload.is_file()
count=0

def check(expected,actual):
    global count
    count+=1
    assert expected==actual,(expected,actual)

def browser():
    jar=http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)),jar

with tempfile.TemporaryDirectory(prefix='sosecurity-core-pilot-') as directory:
    work=Path(directory);work.chmod(0o700)
    state=work/'state';state.mkdir(mode=0o700)
    sessions=work/'sessions';sessions.mkdir(mode=0o700)
    consumer=work/'consumer';consumer.mkdir()
    (consumer/'composer.json').write_text(json.dumps({'name':'sosecurity/core-pilot-consumer',
        'repositories':[{'type':'path','url':str(root),'options':{'symlink':False}}],
        'require':{'sohophp/sosecurity':'@dev'},'config':{'allow-plugins':False}}))
    result=subprocess.run([runtime,'/usr/local/bin/composer','install','--working-dir='+str(consumer),
        '--no-interaction','--no-progress','--no-scripts','--no-plugins'],capture_output=True,text=True)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    public=work/'public';(public/'pilot').mkdir(parents=True)
    (public/'pilot/index.php').write_text('<?php require '+json.dumps(str(root/'integrations/core-repo/login.php'))+';')
    with socket.socket() as probe: probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    password_hash=subprocess.check_output([runtime,'-r','echo password_hash("pilot-test-password",PASSWORD_BCRYPT,["cost"=>10]);'],text=True)
    env=os.environ.copy();env.update({'SOSECURITY_PILOT_AUTOLOAD':str(consumer/'vendor/autoload.php'),
        'SOSECURITY_PILOT_CORE':str(core),'SOSECURITY_PILOT_HOST_AUTOLOAD':str(host_autoload),
        'SOSECURITY_PILOT_SESSIONS':str(sessions),'SOSECURITY_PILOT_STATE':str(state),
        'SOSECURITY_PILOT_USER':'pilot-user','SOSECURITY_PILOT_PASSWORD_HASH':password_hash})
    with (work/'server.log').open('w+') as log:
        server=subprocess.Popen([runtime,'-S','127.0.0.1:'+str(port),'-t',str(public)],env=env,stdout=log,stderr=log)
        endpoint='http://127.0.0.1:'+str(port)+'/pilot/'
        def request(client,fields=None,accept='application/json',method=None):
            data=None if fields is None else urllib.parse.urlencode(fields).encode()
            req=urllib.request.Request(endpoint,data=data,headers={'Accept':accept},method=method)
            try: response=client.open(req,timeout=5)
            except urllib.error.HTTPError as error: response=error
            raw=response.read().decode()
            return response.status,json.loads(raw) if accept=='application/json' else raw,response.headers
        try:
            a,jar=browser();b,_=browser()
            for _ in range(100):
                try: first=request(a);break
                except (urllib.error.URLError,ConnectionError): time.sleep(.05)
            else: raise RuntimeError('Pilot startup timeout')
            check(200,first[0]);check(True,first[1]['component_origin_verified'])
            check('preserved-host-data',first[1]['host_marker']);check('_csrf_token',first[1]['csrf']['name'])
            cookie=next(c for c in jar if c.name=='COREPILOT')
            check('/pilot/',cookie.path);check(False,cookie.domain_specified)
            check(True,'HttpOnly' in cookie._rest);check('Lax',cookie._rest.get('SameSite'))
            old_sid=cookie.value
            second=request(a)[1]
            check(first[1]['csrf']['value'],second['csrf']['value'])
            def fields(page,user='pilot-user',password='pilot-test-password'):
                nums=[int(n) for n in re.findall(r'\d+',page['captcha']['prompt'])]
                if len(nums)!=2 or '+' not in page['captcha']['prompt']: raise RuntimeError('Unexpected arithmetic prompt')
                return {'_csrf_token':page['csrf']['value'],'captcha_id':page['captcha']['id'],
                    'captcha_answer':str(sum(nums)),'username':user,'password':password}
            check(403,request(a,{'username':'pilot-user','password':'pilot-test-password'})[0])
            forged=fields(first[1]);forged['_csrf_token']='bad';check(403,request(a,forged)[0])
            check(403,request(b,fields(first[1]))[0])
            status,body,_=request(a,fields(first[1]));check(200,status);check('登录成功',body['message'])
            check('preserved-host-data',body['host_marker'])
            check(False,old_sid==next(c for c in jar if c.name=='COREPILOT').value)
            check(403,request(a,fields(first[1]))[0])
            signed_in=request(a)[1];check('pilot-user',signed_in['user']);check('preserved-host-data',signed_in['host_marker'])
            check(401,request(b,fields(request(b)[1],user='unknown-account'))[0])
            for _ in range(3): check(401,request(b,fields(request(b)[1],user='brute-account',password='bad'))[0])
            status,_,headers=request(b,fields(request(b)[1],user='brute-account',password='bad'))
            check(429,status);check(True,int(headers['Retry-After'])>0)
            html=request(a,accept='text/html')[1]
            check(True,'name="_csrf_token"' in html);check(True,'name="captcha_answer"' in html)
            check(405,request(a,method='PUT')[0])
            state.rename(work/'state-paused')
            check(503,request(a)[0])
            (work/'state-paused').rename(state)
            check(200,request(a)[0]);check('pilot-user',request(a)[1]['user'])
            files=list(sessions.iterdir());check(True,len(files)>=2)
            check(True,all(f.is_file() for f in files))
            print(f'PASS CoreRepo component pilot: {count} real HTTP assertions on PHP '+subprocess.check_output([runtime,'-r','echo PHP_VERSION;'],text=True))
            print('BOUNDARY: actual isolated CoreRepo Session/Symfony CSRF/Twig plus fresh Composer SoSecurity; test identity, no full admin/router/SSO/production acceptance')
        finally:
            server.terminate();server.wait(timeout=5)
            log.seek(0);report=log.read()
            if 'Fatal error' in report or 'Warning:' in report: raise RuntimeError(report)
            if sys.exc_info()[0] is not None: print(report,file=sys.stderr)
