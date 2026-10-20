<?php
declare(strict_types=1);
// Cross-process contract: Ed25519 reception needs sodium, historical sealed processing does not.
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/examples/webhook-business.php';
$input=json_decode(stream_get_contents(STDIN),true);$mode=$argv[1] ?? '';
$pdo=new PDO('sqlite:'.$input['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$stored=json_decode(file_get_contents($input['seals']),true);$secrets=[];foreach($stored['keys'] as $id=>$key){$secrets[$id]=base64_decode($key,true);}
$keys=new SoSecurity\Support\HmacKeys($stored['current'],$secrets);$clock=new TestClock();
$definition=['scope'=>'webhook-example','account'=>'publisher-example','url'=>$input['url'].'?receive=1','protocol'=>'standard-ed25519','policy'=>['allow_http'=>strpos($input['url'],'http://')===0]];
if($mode==='receive'){
    $endpoint=new SoSecurity\Webhook\Endpoint('events',$definition['scope'],$definition['account'],$definition['url'],$definition['protocol'],$definition['policy']);
    $pair=sodium_crypto_sign_keypair();$public=sodium_crypto_sign_publickey($pair);$private=sodium_crypto_sign_secretkey($pair);
    $verifier=new SoSecurity\Webhook\Verifier($endpoint,static function()use($endpoint,$public){return new SoSecurity\Webhook\KeySet($endpoint,['temporary'=>$public]);},static function(){return true;},$clock);
    $inbox=new SoSecurity\Webhook\SqlInbox($pdo,'webhook-example',$verifier,$keys,static function($endpoint,$message)use($pdo){return SoSecurity\Examples\WebhookBusiness\associated($pdo,$endpoint,$message);},$clock);
    $body=json_encode(['id'=>'ed-history','type'=>'document.changed','resource'=>'a','version'=>'1','tenant'=>'webhook-example','account'=>'publisher-example']);
    $signature=sodium_crypto_sign_detached('ed-history.'.$clock->time.'.'.$body,$private);
    $request=new SoSecurity\Webhook\Request('POST',$definition['url'],$body,['Webhook-Id'=>'ed-history','Webhook-Timestamp'=>(string)$clock->time,'Webhook-Signature'=>'v1a,'.base64_encode($signature)]);
    $receipt=$inbox->accept($request,static function($proof){return SoSecurity\Examples\WebhookBusiness\map($proof->body(),$proof->endpoint(),$proof->messageId());});
    Check::same(true,$receipt!==null);echo json_encode(['receipt_id'=>$receipt->id()])."\n";
}elseif($mode==='process'){
    $clock->time+=3600;$definition['processing']=['connection'=>'db','integrity_keys'=>'seals','mapper'=>'mapper','association_guard'=>'association','worker_guard'=>'worker'];
    $security=SoSecurity\Security::fromArray(['site'=>'webhook-example','webhooks'=>['events'=>$definition]],['db'=>$pdo,'seals'=>$keys,
        'mapper'=>static function(string $body,$endpoint,string $receipt,array $metadata){return SoSecurity\Examples\WebhookBusiness\map($body,$endpoint,$metadata['message_id']);},
        'association'=>static function($endpoint,$message)use($pdo){return SoSecurity\Examples\WebhookBusiness\associated($pdo,$endpoint,$message);},'worker'=>static function(){return true;},
    ],$clock);
    $processor=$security->webhookProcessor('events');$claim=$processor->claim($input['receipt'],'historical-worker');Check::same(true,$claim!==null);
    Check::same('succeeded',$processor->execute('historical-worker',$claim->token(),'SoSecurity\\Examples\\WebhookBusiness\\apply')->status());
    Check::same(null,$processor->execute('historical-worker',$claim->token(),'SoSecurity\\Examples\\WebhookBusiness\\apply'));
    echo json_encode(['sodium'=>extension_loaded('sodium'),'receipt_id'=>$input['receipt'],'assertions'=>Check::$assertions])."\n";
}else{throw new RuntimeException('Invalid test mode.');}
