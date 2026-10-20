#!/usr/bin/env python3
"""Native Cookie/CSRF -> visitor-owned lease manager, credentials stay server-side."""
import argparse,http.cookiejar,json,subprocess,urllib.error,urllib.parse,urllib.request
from pathlib import Path
from isolated_demo import demo_server
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');parser.add_argument('--browser',action='store_true');args=parser.parse_args();checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
class Visitor:
    def __init__(self,base):
        self.url=base+'?module=leases';self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.csrf=''
    def call(self,action=None,token=None):
        body=None if action is None else urllib.parse.urlencode(dict(action=action,_csrf=self.csrf if token is None else token)).encode()
        try:response=self.client.open(urllib.request.Request(self.url,data=body,headers={'Accept':'application/json'}),timeout=10)
        except urllib.error.HTTPError as error:response=error
        with response:
            check('no-store',response.headers['Cache-Control']);data=json.load(response);self.csrf=data.get('controls_token',self.csrf);check(False,'l1.' in json.dumps(data));return response.status,data
def acceptance(base):
    v=Visitor(base);check(False,v.call()[1]['state']['initialized']);check(403,v.call('prepare',token='bad')[0]);check(503,v.call('acquire')[0]);check(False,v.call()[1]['state']['initialized'])
    check(200,v.call('prepare')[0]);check(200,v.call('acquire')[0]);check(409,v.call('acquire')[0]);check(1,v.call('step')[1]['state']['steps'])
    check(200,v.call('renew')[0]);v.call('switch_owner');check(False,v.call()[1]['state']['current_valid']);check(200,v.call('acquire')[0]);check(2,v.call()[1]['state']['active']);check(409,v.call('remove')[0])
    v.call('switch_owner');check(200,v.call('release')[0]);check(409,v.call('step')[0]);check(200,v.call('acquire')[0]);check(409,v.call('stale_release')[0]);check(True,v.call()[1]['state']['current_valid'])
    check(3,v.call('prepare')[1]['state']['sequence']);v.call('advance');check(0,v.call()[1]['state']['active']);check(409,v.call('renew')[0]);check(200,v.call('acquire')[0]);check(4,v.call()[1]['state']['sequence'])
    v.call('absolute');check(409,v.call('renew')[0]);check(409,v.call('step')[0]);check(1,v.call()[1]['state']['steps']);check(200,v.call('remove')[0]);check(503,v.call('acquire')[0])
    v.call('prepare');check(0,v.call()[1]['state']['sequence']);v.call('acquire')
    other=Visitor(base);check(False,other.call()[1]['state']['initialized']);other.call('prepare');other.call('acquire');other.call('release');other.call('remove');check(True,v.call()[1]['state']['current_valid'])
    check(503,v.call('store_failure')[0]);check(1,v.call()[1]['state']['steps']);check(200,v.call('release')[0]);check(200,v.call('remove')[0])
    print(f'PASS native lease demo HTTP: {checks} assertions; CSRF, explicit provisioning, capacity, holder isolation, renewal/expiry, stale release, missing state, no secret output and fault refusal')
def run(base):
    if args.browser:subprocess.run(['node',str(Path(__file__).with_name('lease-browser.cjs')),base],check=True)
    else:acceptance(base)
if args.url:run(args.url.rstrip('/')+'/')
else:
    with demo_server(args.runtime) as base:run(base)
