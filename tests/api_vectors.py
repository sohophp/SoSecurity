#!/usr/bin/env python3
"""Independent RFC 9421 bounded-profile implementation using Python standard libraries."""
import argparse, base64, hashlib, hmac, json, subprocess

def signed_headers(method, url, body, content_type, created, lifetime, nonce, key_id, secret):
    digest='sha-256=:'+base64.b64encode(hashlib.sha256(body).digest()).decode()+':'
    parameters='("@method" "@target-uri" "content-digest" "content-type");created={};expires={};nonce="{}";keyid="{}";alg="hmac-sha256";tag="sosecurity-v1"'.format(created,created+lifetime,nonce,key_id)
    base='"@method": {}\n"@target-uri": {}\n"content-digest": {}\n"content-type": {}\n"@signature-params": {}'.format(method,url,digest,content_type,parameters).encode('ascii')
    signature=base64.b64encode(hmac.new(secret,base,hashlib.sha256).digest()).decode()
    return {'Content-Type':content_type,'Content-Digest':digest,'Signature-Input':'sig1='+parameters,'Signature':'sig1=:'+signature+':'}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--php',default='php72'); args=parser.parse_args()
    cases=[]
    for index,(method,body,url,content_type,key_length) in enumerate([
        ('GET',b'','https://api.example.com/','application/octet-stream',32),
        ('POST',b'{"message":"'+ '中文'.encode('utf-8') +b'"}','https://api.example.com/orders?q=a%20b&x=1&x=2','application/json; charset=utf-8',64),
        ('PUT',bytes(range(256)),'https://api.example.com:8443/a%2Fb?q=%FF','application/octet-stream',128),
        ('DELETE',b'\x00\xff\r\n','https://[2606:4700:4700::1111]/v1/a?name=a+b','text/plain',32),
    ]):
        origin=url.split('/',3)[0]+'//'+url.split('/',3)[2]
        secret=bytes(range(key_length)); nonce='independent_nonce_{:02}'.format(index)
        case={'method':method,'url':url,'origin':origin,'body_base64':base64.b64encode(body).decode(),'type':content_type,'created':1791840000,'lifetime':60,'nonce':nonce,'id':'python-key-'+str(index),'secret_hex':secret.hex()}
        case['headers']=signed_headers(method,url,body,content_type,case['created'],case['lifetime'],nonce,case['id'],secret)
        cases.append(case)
    result=subprocess.run([args.php,'tests/api-vectors.php'],input=json.dumps(cases).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode: raise RuntimeError(result.stderr.decode())
    if result.stderr: raise RuntimeError(result.stderr.decode())
    assert json.loads(result.stdout)==[case['headers'] for case in cases]
    print('PASS {}: 4 independent Python -> PHP verify and PHP -> Python byte-identical RFC profile vectors (binary/UTF-8/query/IPv6)'.format(args.php))
if __name__=='__main__': main()
