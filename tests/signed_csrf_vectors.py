#!/usr/bin/env python3
"""Independent signed-CSRF profile check (our bounded format, not a new cryptographic algorithm)."""
import argparse, base64, hashlib, hmac, json, subprocess
parser=argparse.ArgumentParser();parser.add_argument('--php',default='php72');args=parser.parse_args()
def token_mac(case,prefix):
    audience=case['audience'].encode();scope=case['scope'].encode();binding=base64.b64decode(case['binding_b64'])
    message=b'SoSecurity.CSRF.v1\n'+str(len(audience)).encode()+b':'+audience+b'\n'+str(len(scope)).encode()+b':'+scope+b'\n'+str(len(binding)).encode()+b':'+binding+b'\n'+prefix.encode('ascii')
    return hmac.new(bytes.fromhex(case['secret_hex']),message,hashlib.sha256).hexdigest()
cases=[]
for index,(audience,scope,binding,ttl,key_size) in enumerate([
    ('site-a','orders:update',b'verified-current-login-binding',30,32),
    ('中文站点','表单/保存',b'\x00\xff\n:binding',86400,64),
    ('site-a','a:b',b'a\nb:c',7200,128),
]):
    case={'audience':audience,'scope':scope,'binding_b64':base64.b64encode(binding).decode(),'ttl':ttl,'created':100000,'id':'python'+str(index),'secret_hex':bytes(range(key_size)).hex()}
    prefix='socs1.{}.{}.{}.{}'.format(case['id'],case['created'],case['created']+ttl,format(index+1,'064x'))
    case['token']=prefix+'.'+token_mac(case,prefix);cases.append(case)
result=subprocess.run([args.php,'tests/signed-csrf-vectors.php'],input=json.dumps(cases).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
if result.returncode or result.stderr:raise RuntimeError(result.stderr.decode())
for case,token in zip(cases,json.loads(result.stdout)):
    prefix,mac=token.rsplit('.',1);assert hmac.compare_digest(mac,token_mac(case,prefix))
print('PASS {}: 3 independent Python/PHP signed-CSRF vectors; UTF-8 and binary length-prefix binding'.format(args.php))
