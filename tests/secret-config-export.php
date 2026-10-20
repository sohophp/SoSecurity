<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Api\HmacSigner;
use SoSecurity\Api\KeyRing;
use SoSecurity\Api\SignaturePolicy;
use SoSecurity\Api\SigningKey;
use SoSecurity\Captcha\HCaptcha;
use SoSecurity\Captcha\Recaptcha;
use SoSecurity\Captcha\Turnstile;
use SoSecurity\Exception\ConfigurationException;

$signingSecret=str_repeat('K',32).'PRIVATE_API_SENTINEL';
$turnstileSecret=str_repeat('T',32).'PRIVATE_TURNSTILE_SENTINEL';
$recaptchaSecret=str_repeat('R',32).'PRIVATE_RECAPTCHA_SENTINEL';
$hcaptchaSecret=str_repeat('H',32).'PRIVATE_HCAPTCHA_SENTINEL';
$signing=new SigningKey('key-id',$signingSecret,'actor',['read']);
$ring=new KeyRing([$signing]);
$signer=new HmacSigner(new SignaturePolicy(['origin'=>'https://example.test']),$signing);
Check::same($signingSecret,$signing->secret());
Check::same($signingSecret,$ring->find('key-id')->secret());
Check::same(true,isset($signer->sign('GET','https://example.test/resource')['Signature']));

$seen=[];
$turnstile=new Turnstile($turnstileSecret,'example.test','login',static function(array $payload)use(&$seen):string{$seen['turnstile']=$payload['secret'];return '{"success":true,"hostname":"example.test","action":"login"}';});
$recaptcha=new Recaptcha($recaptchaSecret,'example.test',null,0.5,static function(array $payload)use(&$seen):string{$seen['recaptcha']=$payload['secret'];return '{"success":true,"hostname":"example.test"}';});
$hcaptcha=new HCaptcha($hcaptchaSecret,'site-key',static function(array $payload)use(&$seen):string{$seen['hcaptcha']=$payload['secret'];return '{"success":true}';});
Check::same(true,$turnstile->verify('synthetic-token'));
Check::same(true,$recaptcha->verify('synthetic-token'));
Check::same(true,$hcaptcha->verify('synthetic-token'));
Check::same(['turnstile'=>$turnstileSecret,'recaptcha'=>$recaptchaSecret,'hcaptcha'=>$hcaptchaSecret],$seen);

$secrets=[$signingSecret,$turnstileSecret,$recaptchaSecret,$hcaptchaSecret];
foreach([$signing,$ring,$signer,$turnstile,$recaptcha,$hcaptcha] as $object){
    $printed=print_r($object,true);$exported=var_export($object,true);
    ob_start();var_dump($object);$dumped=ob_get_clean();
    foreach($secrets as $secret){
        Check::same(false,strpos($printed,$secret)!==false);
        Check::same(false,strpos($exported,$secret)!==false);
        Check::same(false,strpos($dumped,$secret)!==false);
    }
    Check::same('{}',json_encode($object));
    Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});
}

// Old serialized objects and reconstructed plain-string fields must not revive credential handling.
foreach([SigningKey::class,Turnstile::class,Recaptcha::class,HCaptcha::class] as $class){
    $serialized='O:'.strlen($class).':"'.$class.'":0:{}';
    Check::throws(ConfigurationException::class,static function()use($serialized):void{unserialize($serialized);});
    $reflection=new ReflectionClass($class);$object=$reflection->newInstanceWithoutConstructor();
    $property=$reflection->getProperty('secret');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}$property->setValue($object,'secret_object_trap');
    if($class===SigningKey::class){Check::throws(ConfigurationException::class,static function()use($object):void{$object->secret();});}
    else{Check::throws(ConfigurationException::class,static function()use($object):void{$object->verify('synthetic-token');});}
}

echo 'PASS private provider/signing object exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; synthetic secrets absent from common exports, old serialized/plain-string state refused\n";
