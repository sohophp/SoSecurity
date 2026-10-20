<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;

$simple='SYNTHETIC-PRIVATE-BEARER-OBJECT';
$identity=new SoSecurity\Api\Identity('key-id','actor',['read']);
$credential=new SoSecurity\Api\Credential($simple,$identity,200);
$session=new SoSecurity\Auth\SessionCredential($simple,'session-id',200);
$remember=new SoSecurity\Auth\RememberCredential($simple,'remember-id',200);
$leaseToken='l1.'.str_repeat('a',32).'.'.str_repeat('b',32).'.'.str_repeat('c',64);
$lease=new SoSecurity\Concurrency\Lease($leaseToken,1,200,300);
$confirmationToken='oc1.'.str_repeat('d',32).'.'.str_repeat('e',64);
$grantToken='og1.'.str_repeat('f',32).'.'.str_repeat('a',64);
$resource=new SoSecurity\Authorization\Resource('tenant','document','item','v1');
$intent=new SoSecurity\Operation\Intent('document.approve',$resource);
$confirmation=new SoSecurity\Operation\Confirmation($confirmationToken,$intent,200);
$grant=new SoSecurity\Operation\Grant($grantToken,200);
$claimToken='wc1.'.str_repeat('b',32).'.1.'.str_repeat('c',64);
$claimStatus=new SoSecurity\Webhook\ProcessingStatus(str_repeat('b',32),'leased',1,1,0,1,0,200,100);
$claim=new SoSecurity\Webhook\ProcessingClaim($claimToken,$claimStatus);
$issuedToken='ac1.test.'.str_repeat('a',64).'.'.str_repeat('b',32).'.'.str_repeat('c',32).'.1.100.200.'.str_repeat('d',64).'.'.str_repeat('e',64).'.'.str_repeat('A',43);
$metadata=new SoSecurity\Api\CredentialInfo(str_repeat('c',32),'synthetic',['read'],0,100,200,1,'test');
$issued=new SoSecurity\Api\IssuedCredential($issuedToken,$metadata);
$registry=(new ReflectionClass(SoSecurity\Auth\SessionRegistry::class))->newInstanceWithoutConstructor();
$authorizer=(new ReflectionClass(SoSecurity\Authorization\Authorizer::class))->newInstanceWithoutConstructor();
$access=new SoSecurity\Download\SessionAccess($registry,$authorizer,'tenant','actor',$simple,static function():bool{return true;});

foreach([[$credential,$simple],[$session,$simple],[$remember,$simple],[$lease,$leaseToken],[$confirmation,$confirmationToken],[$grant,$grantToken],[$claim,$claimToken],[$issued,$issuedToken],[$access,$simple]] as $case){
    list($object,$secret)=$case;
    if(method_exists($object,'token')){Check::same($secret,$object->token());}
    $printed=print_r($object,true);$exported=var_export($object,true);ob_start();var_dump($object);$dumped=ob_get_clean();
    Check::same(false,strpos($printed,$secret)!==false);
    Check::same(false,strpos($exported,$secret)!==false);
    Check::same(false,strpos($dumped,$secret)!==false);
    Check::same('{}',json_encode($object));
    Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});
    $class=get_class($object);$serialized='O:'.strlen($class).':"'.$class.'":0:{}';
    Check::throws(ConfigurationException::class,static function()use($serialized):void{unserialize($serialized);});
}

echo 'PASS private bearer object exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; public token getters retain bytes, common exports omit tokens, old objects refused\n";
