<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Idempotency\Request as IdempotentRequest;
use SoSecurity\Idempotency\Response as IdempotentResponse;
use SoSecurity\Download\Request as DownloadRequest;
use SoSecurity\Download\LinkAccess as SignedDownloadAccess;
use SoSecurity\Http\Outbound\Response as OutboundResponse;
use SoSecurity\Link\Links;
use SoSecurity\Link\Policy as LinkPolicy;
use SoSecurity\Link\IssuedLink;
use SoSecurity\Link\Target;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Webhook\Request as WebhookRequest;

$secret='PRIVATE_EXPORT_SENTINEL_12345';
$resource=new Resource('tenant','doc','1','v1');
$target=new Target('doc.read',$resource,'/r',['note'=>$secret]);
$url='https://example.test/r?token='.$secret;
$link=new IssuedLink($url,str_repeat('a',32),$target,100,200,false);
$webhookBody="webhook\0".$secret;
$webhook=new WebhookRequest('POST','https://example.test/hook',$webhookBody,['Webhook-Signature'=>$secret]);
$requestBody="request\0".$secret;
$idempotent=new IdempotentRequest('tenant','actor','create',$secret,'POST','/create?token='.$secret,$requestBody,['note'=>$secret]);
$response=new IdempotentResponse(200,"response\0".$secret);
$downloadRequest=new DownloadRequest('GET',['If-Range'=>$secret]);
$outboundResponse=new OutboundResponse(200,['Set-Cookie'=>[$secret]],"external\0".$secret,'8.8.8.8');
$links=new Links(new MemoryStore(),new HmacKeys('test',['test'=>str_repeat('x',32)]),'test',new LinkPolicy('https://example.test'),static function():bool{return true;});
$downloadAccess=new SignedDownloadAccess($links,static function(){return null;},$url,$secret);

Check::same($url,$link->url());Check::same($target,$link->target());
Check::same($webhookBody,$webhook->body());Check::same($secret,$webhook->header('webhook-signature'));
Check::same($secret,$idempotent->key());Check::same($requestBody,$idempotent->body());
Check::same($secret,$idempotent->bindings()['note']);Check::same('/create?token='.$secret,$idempotent->target());
Check::same("response\0".$secret,$response->body());
Check::same($secret,$downloadRequest->header('if-range'));
Check::same($secret,$outboundResponse->values('set-cookie')[0]);Check::same("external\0".$secret,$outboundResponse->body());
foreach([$link,$webhook,$idempotent,$response,$downloadRequest,$outboundResponse,$downloadAccess] as $object){
    foreach([print_r($object,true),var_export($object,true)] as $rendered){Check::same(false,strpos($rendered,$secret)!==false);}
    ob_start();var_dump($object);$dumped=ob_get_clean();
    Check::same(false,strpos($dumped,$secret)!==false);
    Check::same('{}',json_encode($object));
    Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});
    $class=get_class($object);$serialized='O:'.strlen($class).':"'.$class.'":0:{}';
    Check::throws(ConfigurationException::class,static function()use($serialized):void{unserialize($serialized);});
}

echo 'PASS transport value exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; credential URL, signed request, download context, external HTTP response and application bytes absent from common exports\n";
