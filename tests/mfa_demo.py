#!/usr/bin/env python3
"""Real form/AJAX-compatible HTTP flows with independent Python TOTP calculation."""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from isolated_demo import demo_server

parser = argparse.ArgumentParser(); parser.add_argument('runtime', nargs='?', default='php'); parser.add_argument('--url')
args = parser.parse_args(); checks = 0

def check(expected, actual):
    global checks
    checks += 1
    assert expected == actual, (expected, actual)

def otp(uri, future=False):
    config = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
    secret = config['secret'][0]; key = base64.b32decode(secret + '=' * ((-len(secret)) % 8))
    period = int(config['period'][0]); counter = int(time.time()) // period + int(future)
    mac = hmac.new(key, struct.pack('!Q', counter), config['algorithm'][0].lower()).digest(); offset = mac[-1] & 15
    return str((struct.unpack('!I', mac[offset:offset+4])[0] & 0x7fffffff) % 10**int(config['digits'][0])).zfill(int(config['digits'][0]))

class Visitor:
    def __init__(self, base):
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.url = base + '?module=mfa'; self.controls = None
    def call(self, action=None, code='', csrf=None):
        data = None if action is None else urllib.parse.urlencode({'action': action, 'mfa_code': code, '_csrf': self.controls if csrf is None else csrf}).encode()
        request = urllib.request.Request(self.url, data=data, headers={'Accept': 'application/json'})
        try:
            response = self.client.open(request, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            check('no-store', response.headers['Cache-Control'])
            result = json.load(response); self.controls = result.get('controls_token', self.controls)
            return response.status, result

def acceptance(base):
    visitor = Visitor(base); code, initial = visitor.call(); check(200, code)
    if not initial['state']['available']:
        check(503, visitor.call('begin')[0])
        print(f'PASS missing sodium demo: {checks} assertions; explicit unavailable state/refusal'); return
    check(403, visitor.call('begin', csrf='invalid')[0])
    check(False, visitor.call()[1]['state']['factor']['pending'])
    status, result = visitor.call('begin'); check(200, status); uri = result['result']['provisioning_uri']
    check(False, 'secret' in json.dumps(result['state'])); check(False, 'provisioning_uri' in result['state'])
    other = Visitor(base); other.call(); check(403, other.call('confirm', otp(uri))[0])
    check(403, visitor.call('confirm', 'bad')[0])
    proof = otp(uri); status, result = visitor.call('confirm', proof); check(200, status)
    codes = result['result']['recovery_codes']; check(10, len(codes)); check(True, result['state']['factor']['enabled'])
    check(403, visitor.call('confirm', proof)[0]); check(403, visitor.call('verify', proof)[0])
    check(200, visitor.call('recovery', codes[0])[0]); check(403, visitor.call('recovery', codes[0])[0])
    check(200, visitor.call('rotate')[0]); check(200, visitor.call('recovery', codes[1])[0])
    status, result = visitor.call('regenerate', otp(uri, future=True)); check(200, status); replacements = result['result']['recovery_codes']
    check(403, visitor.call('recovery', codes[2])[0]); check(200, visitor.call('recovery', replacements[0])[0])
    status, result = visitor.call('store_failure'); check(503, status); check('storage.unavailable', result['result']['reason'])
    status, result = visitor.call('begin'); check(200, status); new_uri = result['result']['provisioning_uri']
    check(True, result['state']['factor']['enabled']); status, result = visitor.call('confirm', otp(new_uri)); check(200, status)
    new_codes = result['result']['recovery_codes']; check(403, visitor.call('recovery', replacements[1])[0])
    check(200, visitor.call('verify', otp(new_uri, future=True))[0]); check(200, visitor.call('clear')[0])
    check(403, visitor.call('recovery', new_codes[0])[0]); check(False, visitor.call()[1]['state']['factor']['enabled'])
    print(f'PASS MFA demo HTTP: {checks} assertions; CSRF, visitor isolation, independent TOTP, confirmation/replay, recovery, key rotation, replacement, clear and storage failure')

if args.url:
    acceptance(args.url.rstrip('/') + '/')
else:
    with demo_server(args.runtime) as url:
        acceptance(url)
