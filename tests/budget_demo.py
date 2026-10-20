#!/usr/bin/env python3
"""Native Cookie/CSRF demo requests, weighted denial and visitor-owned work counters."""
import argparse,http.cookiejar,json,subprocess,urllib.error,urllib.parse,urllib.request
from pathlib import Path
from isolated_demo import demo_server
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');parser.add_argument('--browser',action='store_true');args=parser.parse_args();checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
class Visitor:
    def __init__(self,base):
        self.url=base+'?module=budgets';self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.csrf='';self.algorithm='fixed_window';self.mode='single'
    def call(self,action=None,token=None,extra=None):
        fields=dict(action=action,_csrf=self.csrf if token is None else token,budget_algorithm=self.algorithm,budget_mode=self.mode);fields.update(extra or {})
        data=None if action is None else urllib.parse.urlencode(fields).encode()
        try:response=self.client.open(urllib.request.Request(self.url,data=data,headers={'Accept':'application/json'}),timeout=10)
        except urllib.error.HTTPError as error:response=error
        with response:
            check('no-store',response.headers['Cache-Control']);result=json.load(response);self.csrf=result.get('controls_token',self.csrf);return response.status,result,dict(response.headers)
def acceptance(base):
    v=Visitor(base);check(0,v.call()[1]['state']['executed']);check(403,v.call('light',token='wrong')[0]);check(0,v.call()[1]['state']['executed'])
    for algorithm in ['token_bucket','fixed_window','sliding_window']:
        v.algorithm=algorithm;v.mode='single';v.call('reset')
        status,data,_=v.call('batch',extra={'cost':0});check(200,status);check(3,data['result']['cost']);check(1,data['state']['executed'])
        status,data,headers=v.call('batch');check(429,status);check(1,data['state']['executed']);check(True,int(headers['Retry-After'])>0)
        check(200,v.call('light')[0]);status,data,headers=v.call('oversize');check(429,status);check(False,'Retry-After' in headers);check(2,data['state']['executed'])
        check(200,v.call('advance')[0]);check(200,v.call('batch')[0]);check(3,v.call('inspect')[1]['state']['executed'])
    v.algorithm='fixed_window';v.mode='atomic';v.call('reset');v.call('batch');status,data,_=v.call('batch');check(429,status);check([],data['result']['charged'])
    check(1,data['state']['balances']['requests']['remaining']);check(2,data['state']['balances']['work']['remaining']);check(1,data['state']['executed'])
    check(200,v.call('light')[0]);check(429,v.call('light')[0])
    v.mode='ordered';v.call('reset');v.call('batch');status,data,_=v.call('batch');check(429,status);check(['ip'],data['result']['charged']);check(18,data['state']['balances']['ip']['remaining']);check(2,data['state']['balances']['account']['remaining'])
    v.call('change_ip');check(429,v.call('batch')[0]);v.call('change_account');check(200,v.call('batch')[0])
    before=v.call()[1]['state']['executed'];check(503,v.call('store_failure')[0]);check(before,v.call()[1]['state']['executed'])
    other=Visitor(base);check(0,other.call()[1]['state']['executed']);other.call('reset');check(before,v.call()[1]['state']['executed'])
    check(400,v.call('light',extra={'budget_algorithm':'unknown'})[0]);v.call('reset')
    print(f'PASS weighted-budget native HTTP: {checks} assertions; CSRF, server-derived costs, three algorithms, atomic/ordered debits, visitor isolation, work denial and store failure')
def run(base):
    if args.browser:subprocess.run(['node',str(Path(__file__).with_name('budget-browser.cjs')),base],check=True)
    else:acceptance(base)
if args.url:run(args.url.rstrip('/')+'/')
else:
    with demo_server(args.runtime) as base:run(base)
