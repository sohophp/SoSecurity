<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\KeySet;

$secret=str_repeat('K',32).'PRIVATE_WEBHOOK_KEY_SENTINEL';
$endpoint=new Endpoint('endpoint','tenant','provider-account','https://hooks.example/events','standard-hmac',[]);
$keys=new KeySet($endpoint,['current'=>$secret]);
$message="payload\0after-nul";
$signature=hash_hmac('sha256',$message,$secret,true);
Check::same('current',$keys->verify($message,[$signature]));
Check::same(null,$keys->verify($message,[str_repeat("\0",32)]));
Check::same(true,$keys->matches($endpoint));
foreach([print_r($keys,true),var_export($keys,true)] as $rendered){Check::same(false,strpos($rendered,$secret)!==false);}
ob_start();var_dump($keys);$dumped=ob_get_clean();
Check::same(false,strpos($dumped,$secret)!==false);
Check::same('{}',json_encode($keys));
Check::throws(ConfigurationException::class,static function()use($keys):void{serialize($keys);});

$class=KeySet::class;$serialized='O:'.strlen($class).':"'.$class.'":0:{}';
Check::throws(ConfigurationException::class,static function()use($serialized):void{unserialize($serialized);});
$old=(new ReflectionClass($class))->newInstanceWithoutConstructor();
$reflection=new ReflectionClass($class);
foreach(['endpoint'=>$endpoint->fingerprint(),'protocol'=>'standard-hmac','keys'=>['current'=>$secret]] as $name=>$value){
    $property=$reflection->getProperty($name);
    if(PHP_VERSION_ID<80100){$property->setAccessible(true);}
    $property->setValue($old,$value);
}
Check::throws(ConfigurationException::class,static function()use($old,$message,$signature):void{$old->verify($message,[$signature]);});

echo 'PASS webhook key exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; verification retained and raw keys absent from common exports\n";
