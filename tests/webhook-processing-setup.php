<?php
declare(strict_types=1);
// Isolated HTTP test preparation: produce a genuine sealed dead state through the public processing API.
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/examples/webhook-business.php';
$input=json_decode(stream_get_contents(STDIN),true);
$pdo=new PDO('sqlite:'.$input['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
$keys=json_decode(file_get_contents($input['seals']),true);$decoded=[];foreach($keys['keys'] as $id=>$value){$decoded[$id]=base64_decode($value,true);}
$security=SoSecurity\Security::fromArray(['site'=>'webhook-example','webhooks'=>['events'=>[
    'scope'=>'webhook-example','account'=>'publisher-example','url'=>$input['url'].'?receive=1','protocol'=>'standard-hmac','policy'=>['allow_http'=>strpos($input['url'],'http://')===0],
    'processing'=>['connection'=>'db','integrity_keys'=>'seals','mapper'=>'map','association_guard'=>'association','worker_guard'=>'worker'],
]]],['db'=>$pdo,'seals'=>new SoSecurity\Support\HmacKeys($keys['current'],$decoded),
    'map'=>static function(string $body,$endpoint,string $receipt,array $metadata){return SoSecurity\Examples\WebhookBusiness\map($body,$endpoint,$metadata['message_id']);},
    'association'=>static function($endpoint,$message)use($pdo):bool{return SoSecurity\Examples\WebhookBusiness\associated($pdo,$endpoint,$message);},
    'worker'=>static function(string $operation,$endpoint,string $receipt,string $worker):bool{return $worker==='fixture-worker';},
]);
$processor=$security->webhookProcessor('events');$claim=$processor->claim($input['receipt'],'fixture-worker');
if($claim===null){throw new RuntimeException('Fixture receipt could not be claimed.');}
$state=$processor->fail('fixture-worker',$claim->token(),'example.test_failure',false);
if($state===null||$state->status()!=='dead'){throw new RuntimeException('Fixture did not reach its dead state.');}
echo json_encode($state->toArray())."\n";
