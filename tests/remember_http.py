#!/usr/bin/env python3
"""Native Cookie/Session + persistent restoration; fixed public test passwords only."""
import base64, copy, hashlib, hmac, http.cookiejar, json, os, socket, struct, subprocess, sys, tempfile, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
checks = 0
def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)

class Visitor:
    def __init__(self, url):
        self.url = url; self.csrf = ''; self.jar = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
    def call(self, action=None, fields=None, csrf=None):
        body = None if action is None else urllib.parse.urlencode(dict(fields or {}, action=action, _csrf=self.csrf if csrf is None else csrf)).encode()
        try: response = self.client.open(urllib.request.Request(self.url, data=body, headers={'Accept':'application/json'}), timeout=10)
        except urllib.error.HTTPError as error: response = error
        with response:
            check('no-store', response.headers['Cache-Control']); data = json.load(response); self.csrf = data.get('csrf', self.csrf)
            return response.status, data, response.headers
    def cookie(self, name='SoSecurityRememberLocal'):
        return next((c.value for c in self.jar if c.name == name), None)
    def persistent_only(self):
        visitor = Visitor(self.url)
        for cookie in self.jar:
            if cookie.name == 'SoSecurityRememberLocal': visitor.jar.set_cookie(copy.copy(cookie))
        return visitor

def otp(uri):
    seed = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)['secret'][0]
    mac = hmac.new(base64.b32decode(seed+'='*((-len(seed))%8)), struct.pack('!Q', int(time.time())//30+1), hashlib.sha1).digest()
    return str((struct.unpack('!I',mac[mac[-1]&15:][:4])[0]&0x7fffffff)%1000000).zfill(6)

def hashed(value): return subprocess.check_output([runtime,'-r','echo password_hash($argv[1],PASSWORD_BCRYPT,["cost"=>12]);',value],text=True)
password_hash = hashed('Correct-test-password'); dummy = hashed('Dummy-test-password')
sodium = subprocess.call([runtime,'-r','exit(extension_loaded("sodium")?0:1);']) == 0
if not sodium and os.getenv('SOSECURITY_REQUIRE_CRYPTO') == '1': raise RuntimeError('Required ext-sodium missing')
for mfa in ([False,True] if sodium else [False]):
    with tempfile.TemporaryDirectory(prefix='sosecurity-remember-http-') as directory:
        work = Path(directory); storage = work/'state'; storage.mkdir(mode=0o700); sessions = work/'sessions'; sessions.mkdir(mode=0o700)
        account = {'username':'demo','subject':'demo-account','hash':password_hash,'version':'1','mfa_required':mfa}
        config = work/'account.json'
        def save(): config.write_text(json.dumps(account)); config.chmod(0o600)
        save(); key = base64.b64encode(os.urandom(32)).decode(); fixture = None
        if mfa:
            setup = subprocess.run([runtime,str(root/'tests/auth-setup.php')],input=json.dumps({'directory':str(storage),'key':key}),text=True,capture_output=True,check=True)
            check('',setup.stderr); fixture = json.loads(setup.stdout)
        with socket.socket() as probe: probe.bind(('127.0.0.1',0)); port = probe.getsockname()[1]
        env = {k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_AUTH_EXAMPLE_')}; env.update(SOSECURITY_AUTH_EXAMPLE_CONFIG=str(config),SOSECURITY_AUTH_EXAMPLE_STORAGE=str(storage),
            SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH=dummy,SOSECURITY_AUTH_EXAMPLE_HTTPS='0',SOSECURITY_AUTH_EXAMPLE_REMEMBER_KEY=base64.b64encode(os.urandom(32)).decode())
        env.pop('SOSECURITY_AUTH_EXAMPLE_KEY',None)
        if mfa: env['SOSECURITY_AUTH_EXAMPLE_KEY'] = key
        with open(work/'server.log','w+') as log:
            server = subprocess.Popen([runtime,'-d','session.save_path='+str(sessions),'-S',f'127.0.0.1:{port}','-t',str(root/'examples')],env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None: log.seek(0); raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1): break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Startup timeout')
                url = f'http://127.0.0.1:{port}/authentication.php'; first = Visitor(url); first.call()
                check(None,first.cookie()); first.call('login',{'username':'demo','password':'Correct-test-password'})
                if mfa: check(200,first.call('mfa',{'type':'totp','proof':otp(fixture['uri'])})[0])
                original = first.call()[1]['session']; check(None,first.cookie())
                check(403,first.call('remember',csrf='wrong')[0]); check(None,first.cookie())
                status,data,headers = first.call('remember'); check(200,status); check(True,data['remembered']); original_cookie = first.cookie()
                cookie_headers = ';'.join(headers.get_all('Set-Cookie',[]))
                for flag in ['HttpOnly','SameSite=Lax','Path=/','Max-Age=']: check(True,flag in cookie_headers)
                check(False,original_cookie in json.dumps(data)); check(True,original_cookie.startswith('sorp1.current.'))
                restored = first.persistent_only(); stale = first.persistent_only(); forgotten = first.persistent_only()
                status,data,headers = restored.call(); check(200,status); check('anonymous',data['stage']); check(original_cookie,restored.cookie())
                before_sid = restored.cookie('SoSecurityAuthExample'); old_csrf = restored.csrf
                check(403,restored.call('restore',csrf='bad')[0]); check(original_cookie,restored.cookie())
                status,data,headers = restored.call('restore'); check(200,status); check('authenticated',data['stage']); check(True,data['session']['resumed'])
                check(original['method'],data['session']['method']); check(original['strength'],data['session']['strength'])
                check(False,before_sid == restored.cookie('SoSecurityAuthExample')); check(False,original_cookie == restored.cookie())
                check(403,restored.call('sensitive',csrf=old_csrf)[0]); check(403,restored.call('sensitive')[0]); check(403,restored.call('remember')[0])
                # The losing concurrent response carries no persistent Set-Cookie, preserving the winner.
                stale.call(); status,data,headers = stale.call('restore'); check(409,status); check('auth.remember_retry',data['error'])
                check(False,any(header.startswith('SoSecurityRememberLocal=') for header in headers.get_all('Set-Cookie',[])))
                check(original_cookie,stale.cookie()); check('authenticated',restored.call()[1]['stage'])
                # Genuine reauthentication unblocks sensitive actions without moving the session deadline.
                before = restored.call()[1]['session']; restored.call('reauthenticate',{'username':'demo','password':'Correct-test-password'})
                if mfa: check(200,restored.call('mfa',{'type':'recovery','proof':fixture['recovery'][0]})[0])
                after = restored.call()[1]['session']; check(before['id'],after['id']); check(before['expires_at'],after['expires_at']); check(False,after['resumed'])
                check(200,restored.call('sensitive')[0]); check(1,len(restored.call('remember_list')[1]['grants']))
                # Exact original credential becomes a replay after grace, invalidating even the fresh child session.
                time.sleep(5.1); check(401,stale.call('restore')[0]); check(None,stale.cookie()); check('anonymous',restored.call()[1]['stage'])
                # Explicitly forgetting from an anonymous browser revokes the server grant as well.
                first.call('login',{'username':'demo','password':'Correct-test-password'})
                if mfa: first.call('mfa',{'type':'recovery','proof':fixture['recovery'][1]})
                check(200,first.call('remember')[0]); forgotten = first.persistent_only(); stolen = first.persistent_only()
                forgotten.call(); check(200,forgotten.call('forget')[0]); check(None,forgotten.cookie()); stolen.call(); check(401,stolen.call('restore')[0])
                # Logout revokes persistence; disabling the authority also prevents new restoration.
                first.call('login',{'username':'demo','password':'Correct-test-password'})
                if mfa: first.call('mfa',{'type':'recovery','proof':fixture['recovery'][2]})
                check(200,first.call('remember')[0]); stolen = first.persistent_only(); check(200,first.call('logout')[0]); check(None,first.cookie()); stolen.call(); check(401,stolen.call('restore')[0])
                first.call('login',{'username':'demo','password':'Correct-test-password'})
                if mfa: first.call('mfa',{'type':'recovery','proof':fixture['recovery'][3]})
                # Fresh server avoids resource-budget differences being mistaken for auth success; remaining calls stay bounded.
                check(200,first.call('remember')[0]); stolen = first.persistent_only(); account['enabled'] = False; save(); stolen.call(); check(401,stolen.call('restore')[0])
                check(False,any(original_cookie in path.read_text(errors='replace') for path in storage.glob('*.json')))
                print(f'PASS native persistent login ({"TOTP/recovery" if mfa else "password"}): {checks} cumulative assertions; opt-in, POST/CSRF, cookies, grace/replay, freshness, forget/logout and authority')
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()
if not sodium: print('NOT RUN persistent-login native TOTP branch: ext-sodium required')
