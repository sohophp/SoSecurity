#!/usr/bin/env python3
"""Independent canonical target/JSON/HMAC/URL framing; fixed public test material, no protocol interop claim."""
import base64,copy,hashlib,hmac,json,subprocess,sys,urllib.parse
from pathlib import Path
runtime=sys.argv[1] if len(sys.argv)>1 else 'php';entry=str(Path(__file__).with_name('link-vectors.php'));checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
def call(data):
    result=subprocess.run([runtime,entry],input=json.dumps(data),capture_output=True,text=True,check=True)
    check('',result.stderr);return json.loads(result.stdout)
def php_json(data):return json.dumps(data,ensure_ascii=True,separators=(',',':')).replace('/','\\/')
def digest(data):return hashlib.sha256(php_json(data).encode()).hexdigest()
def target(data):
    r=data['resource'];attributes=dict(sorted(r['attributes'].items())) if r['attributes'] else []
    resource=digest([r['scope'],r['type'],r['id'],r['version'],attributes])
    query=urllib.parse.urlencode(sorted(data['parameters'].items()),quote_via=urllib.parse.quote,safe='~')
    relative=data['path']+('?' + query if query else '')
    return resource,digest([data['purpose'],resource,data['method'],relative]),relative
def signed(data,identifier):
    _,fp,relative=target(data);issued=data['now'];expires=issued+data['ttl'];mode='o' if data['once'] else 'r'
    binding=hashlib.sha256(('bound' if data['binding'] else 'bearer').encode()+b'\0'+data['binding'].encode()).hexdigest()
    message=php_json(['signed-link-v1',data['site'],data['origin'],fp,data['kid'],identifier,issued,expires,mode,binding]).encode()
    mac=base64.urlsafe_b64encode(hmac.new(bytes.fromhex(data['key']),message,hashlib.sha256).digest()).decode().rstrip('=')
    token=f'sl1.{data["kid"]}.{identifier}.{issued}.{expires}.{mode}.{mac}'
    return data['origin']+relative+('&' if data['parameters'] else '?')+'_ss='+token
base={'now':100000,'operation':'issue','resource':{'scope':'tenant','type':'document','id':'a','version':'1','attributes':{}},'purpose':'document.read','path':'/document','parameters':{},'method':'GET','origin':'https://files.example','kid':'test','key':bytes(range(32)).hex(),'site':'vectors','once':False,'ttl':300,'binding':''}
cases=[base,dict(base,resource={'scope':'租户:一','type':'document','id':'文档/一','version':'17','attributes':{'z':None,'owner':'张三','enabled':True,'n':7}},path='/%E4%B8%AD%E6%96%87',parameters={'name':'中文 / + &','id':'一','empty':''},site='站点/😀',binding='session:中文\0bound',once=True,method='POST',ttl=1),dict(base,site='s'*128,kid='K'*32,ttl=86400,once=True,parameters={'z':'','a':'/a?x=%25'}),dict(base,origin='https://[2001:db8::1]:8443',path='/',parameters={'id':'a'})]
for original in cases:
    data=copy.deepcopy(original);actual=call(data);resource,fp,_=target(data)
    check(resource,actual['resource']);check(fp,actual['target']);check(signed(data,actual['id']),actual['url'])
    identifier='0123456789abcdef'*2;url=signed(data,identifier);record={'id':identifier,'issued':data['now'],'expires':data['now']+data['ttl'],'once':data['once'],'url':url}
    data.update(operation='verify',record=record,url=url,request_method=data['method'])
    check([True,not data['once']],call(data))
    alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';noncanonical=url[:-1]+alphabet[alphabet.index(url[-1])+1]
    changed_mode=url.replace('.o.','.r.') if data['once'] else url.replace('.r.','.o.')
    for bad in [url+'&extra=1',url+'&_ss=duplicate',url+'#fragment',url+'\n',url.replace('sl1.','sl2.'),changed_mode,url.replace(f'.{data["now"]}.',f'.0{data["now"]}.',1),noncanonical]:
        test=dict(data,url=bad);check([False,False],call(test))
    check([False,False],call(dict(data,request_method='HEAD')))
    check([False,False],call(dict(data,binding='wrong-context')))
print(f'PASS independent signed-link vectors: {checks} assertions; resource/target hashes, Unicode/query canonicalization, HMAC, TTL, binding, modes, method and strict envelope rejection')
