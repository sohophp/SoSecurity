#!/usr/bin/env python3
"""Independent Node/OpenSSL Ed25519 and Python binding checks, using private local test databases only."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root=Path(__file__).resolve().parent.parent
domain=b'SoSecurity.OutboxExample.TerminalReceipt.1.'
script=r'''
require 'tests/bootstrap.php';require 'tests/outbox-resolution-support.php';
$e=new NativeResolutionEnvironment();try{$request=$e->request();$proof=$e->proof();$keys=SoSecurity\Examples\Outbox\keyData($e->config['resolution_keys']);echo json_encode(['request'=>$request,'proof'=>$proof,'public'=>base64_encode($keys['keys']['old']),'root'=>SoSecurity\Examples\Outbox\receiverRead($e->receiver->pdo(),'root')]);}finally{$e->close();}
'''
verify=r'''
require 'vendor/autoload.php';require 'examples/outbox-business.php';$value=json_decode(stream_get_contents(STDIN,8193),true);$proof=SoSecurity\Examples\Outbox\resolutionReceipt($value['proof'],base64_decode($value['public'],true));echo json_encode($proof);
'''
def canonical(value):return json.dumps(value,separators=(',',':'),ensure_ascii=True).replace('/','\\/').encode()
for runtime in sys.argv[1:] or ['php']:
    checks=0
    def same(expected,actual):
        global checks
        checks+=1
        assert expected==actual,(expected,actual)
    run=subprocess.run([runtime,'-r',script],cwd=root,capture_output=True,text=True,check=True,timeout=30)
    value=json.loads(run.stdout);request=json.loads(value['request']);envelope=json.loads(value['proof']);payload=base64.b64decode(envelope['payload'],validate=True);proof=json.loads(payload)
    body=base64.b64decode(request['body'],validate=True);event=json.loads(body)
    event_id='o1.'+str(event['created_at'])+'.'+hashlib.sha256(b'SoSecurity.Outbox.BusinessEvent.1.'+event['order_id'].encode()).hexdigest()
    same(event_id,event['event_id']);same(event_id,proof['event_id']);same(request['challenge'],proof['challenge']);same('cancelled',proof['outcome']);same(hashlib.sha256(body).hexdigest(),proof['body_digest'])
    namespace=hashlib.sha256(canonical(['outbox-v1','outbox-native-example','outbox-example','orders'])).hexdigest()
    delivery=hashlib.sha256(('SoSecurity.Outbox.Delivery.1.'+namespace+'.'+event_id).encode()).hexdigest()
    same(delivery,proof['delivery_id']);same(delivery,request['delivery_id'])
    fingerprint=hashlib.sha256(b'SoSecurity.Outbox.Message.1.'+canonical(['outbox-example','orders',event_id,'receiver','order.created',event['order_id'],len(body),hashlib.sha256(body).hexdigest()])).hexdigest()
    same(fingerprint,proof['fingerprint']);same(hashlib.sha256(b'https://receiver.example.com/outbox-receiver.php').hexdigest(),proof['destination_hash']);same(300,proof['expires_at']-proof['issued_at']);same(1,proof['sequence'])
    business_root=value['root'];same(hashlib.sha256((business_root['payload']+'\0'+business_root['seal_key']+'\0'+business_root['seal']).encode()).hexdigest(),proof['root_hash'])
    same(2,json.loads(business_root['payload'])['format'])
    # Node uses its own OpenSSL implementation, independently of PHP/libsodium.
    independent=r'''
const crypto=require('crypto'), fs=require('fs'), v=JSON.parse(fs.readFileSync(0,'utf8'));
const pub=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(v.public,'base64')]),format:'der',type:'spki'});
const secret=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,'q')]),format:'der',type:'pkcs8'});
const payload=Buffer.from(v.payload,'base64'), message=Buffer.concat([Buffer.from('SoSecurity.OutboxExample.TerminalReceipt.1.'),payload]), signature=Buffer.from(v.signature,'base64');
console.log(JSON.stringify({valid:crypto.verify(null,message,pub,signature),wrongDomain:crypto.verify(null,Buffer.concat([Buffer.from('wrong-domain.'),payload]),pub,signature),signature:crypto.sign(null,message,secret).toString('base64')}));
'''
    incoming=canonical({'payload':envelope['payload'],'signature':envelope['signature'],'public':value['public']})
    independent_result=json.loads(subprocess.run(['node','-e',independent],input=incoming,capture_output=True,check=True,timeout=15).stdout)
    same(True,independent_result['valid']);same(False,independent_result['wrongDomain']);same(envelope['signature'],independent_result['signature'])
    envelope['signature']=independent_result['signature'];incoming=canonical({'proof':canonical(envelope).decode(),'public':value['public']})
    accepted=subprocess.run([runtime,'-r',verify],cwd=root,input=incoming,capture_output=True,check=True,timeout=15)
    same('cancelled',json.loads(accepted.stdout)['outcome'])
    print('PASS native Outbox independent Ed25519: '+str(checks)+' checks on '+runtime,flush=True)
