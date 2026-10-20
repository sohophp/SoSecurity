#!/usr/bin/env python3
import argparse
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request
from isolated_demo import demo_server

parser = argparse.ArgumentParser(); parser.add_argument('runtime', nargs='?', default='php'); parser.add_argument('--url')
args = parser.parse_args(); checks = 0
def check(expected, actual):
    global checks
    checks += 1; assert expected == actual, (expected, actual)
class Visitor:
    def __init__(self, base):
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.url = base+'?module=auth'; self.csrf = None
    def call(self, action=None, fields=None, csrf=None):
        data = None
        if action is not None:
            data = urllib.parse.urlencode(dict(fields or {}, action=action, _csrf=self.csrf if csrf is None else csrf)).encode()
        request = urllib.request.Request(self.url, data=data, headers={'Accept': 'application/json'})
        try: response = self.client.open(request, timeout=10)
        except urllib.error.HTTPError as error: response = error
        with response:
            check('no-store', response.headers['Cache-Control']); result = json.load(response); self.csrf = result.get('controls_token', self.csrf)
            return response.status, result
def acceptance(base):
    first = Visitor(base); check(False, first.call()[1]['state']['authenticated'])
    check(403, first.call('login', {'auth_password':'Demo-only-7.2!'}, csrf='invalid')[0])
    check(403, first.call('login', {'auth_password':'wrong'})[0])
    status, result = first.call('login', {'auth_password':'Demo-only-7.2!'}); check(200,status); check(True,result['state']['authenticated'])
    first_id = result['state']['current_id']; check(False,'token' in json.dumps(result['state'])); check(200,first.call('verify')[0])
    other = Visitor(base); other.call(); other.call('login', {'auth_password':'Demo-only-7.2!'})
    check(403,other.call('revoke', {'auth_session_id':first_id})[0]); check(200,first.call('verify')[0])
    result = first.call('login', {'auth_password':'Demo-only-7.2!'})[1]; check(2,len(result['state']['sessions'])); check(False,first_id==result['state']['current_id'])
    check(200,first.call('login', {'auth_password':'Demo-only-7.2!'})[0]); check(200,first.call('login', {'auth_password':'Demo-only-7.2!'})[0])
    status,capacity=first.call('login', {'auth_password':'Demo-only-7.2!'});check(409,status);check(4,len(capacity['state']['sessions']))
    check(200,first.call('revoke', {'auth_session_id':first_id})[0]); check(200,first.call('verify')[0])
    check(False,first.call('revoke_all')[1]['state']['authenticated'])
    first.call('login', {'auth_password':'Demo-only-7.2!'})
    check(False,first.call('roles_change')[1]['state']['authenticated'])
    check(['reader'],first.call('login', {'auth_password':'Demo-only-7.2!'})[1]['state']['roles'])
    check(False,first.call('password_change')[1]['state']['authenticated'])
    check(403,first.call('login', {'auth_password':'Demo-only-7.2!'})[0]); check(200,first.call('login', {'auth_password':'Changed-demo-7.2!'})[0])
    check(False,first.call('disable')[1]['state']['authenticated']); first.call('enable')
    first.call('login', {'auth_password':'Changed-demo-7.2!'})
    check(403,first.call('recent')[0]); check(200,first.call('reauthenticate', {'auth_password':'Changed-demo-7.2!'})[0])
    check(False,first.call('absolute')[1]['state']['authenticated']); check(200,first.call('clear')[0])
    check(503,first.call('source_failure')[0]); check(200,first.call('login', {'auth_password':'Demo-only-7.2!'})[0])
    check(False,first.call('idle')[1]['state']['authenticated']); check(200,first.call('clear')[0])
    other.call('clear')
    print(f'PASS authentication demo HTTP: {checks} assertions; CSRF, visitor isolation, login/reauthentication, revocation, credential/role/disable changes, expiry and source failure')
if args.url: acceptance(args.url.rstrip('/')+'/')
else:
    with demo_server(args.runtime) as url: acceptance(url)
