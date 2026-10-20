#!/usr/bin/env python3
"""Independent HMAC/framing interoperability, Unicode length and strict canonical token parsing."""
import hashlib, hmac, json, subprocess, sys
from pathlib import Path
runtime = sys.argv[1] if len(sys.argv)>1 else 'php'
entry = str(Path(__file__).with_name('remember-vectors.php')); checks = 0
def call(data):
    result = subprocess.run([runtime,entry],input=json.dumps(data),capture_output=True,text=True,check=True)
    assert not result.stderr, result.stderr
    return json.loads(result.stdout)
for scope,kid,generation in [('tenant','test',0),('租户:主站','Current_2026',19),('x'*256,'K'*32,2147483647)]:
    key = bytes(range(32)); selector='0123456789abcdef'*2; secret='fedcba9876543210'*4; counter=f'{generation:08x}'
    message=(f'SoSecurity.Remember.1.{len(scope.encode())}:{scope}{len(kid)}:{kid}:{selector}:{counter}:{secret}').encode()
    mac=hmac.new(key,message,hashlib.sha256).hexdigest(); token=f'sorp1.{kid}.{selector}.{counter}.{secret}.{mac}'
    data={'scope':scope,'kid':kid,'key':key.hex(),'selector':selector,'secret':secret,'generation':generation,'operation':'issue'}
    assert call(data)==token; checks+=1
    data.update(operation='parse',token=token)
    assert call(data)=={'id':selector,'generation':generation,'digest':hashlib.sha256(token.encode()).hexdigest()}; checks+=1
    for bad in [token+'x',token+'\n',token.replace('sorp1.','sorp2.'),token.replace(selector,selector.upper()),token.replace(counter,'ffffffff',1),token[:-1]+'Z']:
        data['token']=bad; assert call(data) is None; checks+=1
    data.update(token=token,scope='other'); assert call(data) is None; checks+=1
print(f'PASS independent Python/PHP persistent-token framing: {checks} assertions; HMAC, byte lengths, counters, bounds and canonical rejection')
