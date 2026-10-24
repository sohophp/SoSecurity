<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Exception\ConfigurationException;

// Entire accepted option maps still fit the preflight. No storage or delivery is constructed.
$policies=[
    new \SoSecurity\Account\Policy(),new \SoSecurity\Outbox\Policy(),new \SoSecurity\Idempotency\Policy(),
    new \SoSecurity\Download\Policy(),new \SoSecurity\Api\CredentialPolicy(),
    new \SoSecurity\Api\SignaturePolicy(['origin'=>'https://example.test']),
    new \SoSecurity\Http\Outbound\Policy(['hosts'=>['example.test']]),
    new \SoSecurity\Upload\Policy(),new \SoSecurity\Output\HtmlPolicy(),
    new \SoSecurity\Webhook\ProcessingPolicy(),
];
foreach($policies as $policy){
    $class=get_class($policy);$options=$policy->options();
    Check::same($options,(new $class($options))->options());
    $unknown=$options;$unknown['unknown']=true;
    Check::throws(ConfigurationException::class,static function()use($class,$unknown):void{new $class($unknown);});
    $first=key($options);$sameSize=$options;unset($sameSize[$first]);$sameSize['unknown']=true;
    Check::throws(ConfigurationException::class,static function()use($class,$sameSize):void{new $class($sameSize);});
}
$step=1;$backoff=[&$step,2];$p=new \SoSecurity\Webhook\ProcessingPolicy(['backoff'=>&$backoff]);
$before=$p->options();$step=90000;$backoff=[];Check::same($before,$p->options());
$p=new \SoSecurity\Webhook\ProcessingPolicy(['backoff'=>array_fill(0,20,1)]);Check::same(20,count($p->options()['backoff']));
Check::throws(ConfigurationException::class,static function():void{new \SoSecurity\Webhook\ProcessingPolicy(['backoff'=>array_fill(0,21,1)]);});
Check::throws(ConfigurationException::class,static function():void{new \SoSecurity\Webhook\ProcessingPolicy(['backoff'=>[1=>1]]);});
Check::throws(ConfigurationException::class,static function():void{new \SoSecurity\Webhook\ProcessingPolicy(['backoff'=>null]);});
$quarantine=\SoSecurity\Upload\QuarantineState::options([]);
Check::same($quarantine,\SoSecurity\Upload\QuarantineState::options($quarantine));
$endpoint=new \SoSecurity\Webhook\Endpoint('hook','tenant','account','https://example.test/hook','standard-hmac');
Check::same($endpoint->options(),(new \SoSecurity\Webhook\Endpoint('hook','tenant','account','https://example.test/hook','standard-hmac',$endpoint->options()))->options());
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
echo 'PASS policy option boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; full maps, unknown keys, nested limits and reference detachment\n";
