<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\LoginResult;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Exception\ConfigurationException;

$account=new Account('tenant','actor','v1');
$hash=password_hash('synthetic-only',PASSWORD_BCRYPT,['cost'=>4]);
$record=new PasswordRecord($account,$hash);
$challenge=str_repeat('c',64);
$result=new LoginResult('mfa_required',$challenge,200);
Check::same($hash,$record->hash());
Check::same(hash('sha256',json_encode([$account->version(),$hash])),$record->identity()->version());
Check::same($challenge,$result->challenge());
Check::same(null,(new LoginResult('denied'))->challenge());
foreach([[$record,$hash],[$result,$challenge]] as $case){
    list($object,$secret)=$case;
    foreach([print_r($object,true),var_export($object,true)] as $rendered){Check::same(false,strpos($rendered,$secret)!==false);}
    ob_start();var_dump($object);$dumped=ob_get_clean();
    Check::same(false,strpos($dumped,$secret)!==false);
    Check::same('{}',json_encode($object));
    Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});
    $class=get_class($object);$serialized='O:'.strlen($class).':"'.$class.'":0:{}';
    Check::throws(ConfigurationException::class,static function()use($serialized):void{unserialize($serialized);});
}
foreach([[PasswordRecord::class,'hash',$hash,'hash'],[LoginResult::class,'challenge',$challenge,'challenge']] as $case){
    list($class,$name,$secret,$getter)=$case;
    $reflection=new ReflectionClass($class);$object=$reflection->newInstanceWithoutConstructor();
    $property=$reflection->getProperty($name);if(PHP_VERSION_ID<80100){$property->setAccessible(true);}$property->setValue($object,$secret);
    Check::throws(ConfigurationException::class,static function()use($object,$getter):void{$object->$getter();});
}

echo 'PASS authentication object exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; password hashes and MFA challenges absent from common exports\n";
