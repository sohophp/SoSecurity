<?php
declare(strict_types=1);
// Test-only private host bootstrap. Copied outside the web root by the controller.
$root=getenv('SOSECURITY_MANAGED_AUTH_TEST_ROOT');$fixture=getenv('SOSECURITY_MANAGED_AUTH_TEST_FIXTURE');
if(!is_string($root)||!is_string($fixture)||!is_dir($fixture)){throw new RuntimeException('Owned managed-auth test fixture required.');}
require_once $root.'/examples/SqlAccounts.php';
require_once $root.'/tests/account-factor/fence-support.php';
$pdo=new PDO('sqlite:'.$fixture.'/managed.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>2]);
$accounts=new SoSecurity\Account\Example\SqlAccounts($pdo);
$keys=new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('s',32)]);
$raw=new SoSecurity\Mfa\TotpFactors(new SoSecurity\Storage\FileStore($fixture.'/factors','managed-factor-test'),new SoSecurity\Crypto\Cipher('test',['test'=>str_repeat('t',32)],'managed-test'),'Managed test');
$fence=new SoSecurity\Account\LocalEpochFence($fixture.'/authority','managed-test','tenant',str_repeat('e',64),$keys,'fencePersist',100);
$hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);
$provider=new SoSecurity\Auth\PasswordIdentityProvider(
    static function(string $scope,string $address)use($accounts){$record=$accounts->findAddress($scope,new SoSecurity\Account\Address($address));return $record===null?null:$accounts->passwordRecord($record);},
    static function(string $scope,string $subject)use($accounts){$record=$accounts->find($scope,$subject);return $record===null?null:$accounts->passwordRecord($record);},
    $hasher,$hasher->hash('Owned managed HTTP dummy password 49!'));
return SoSecurity\Security::fromArray([
    'site'=>'managed-test','storage'=>['driver'=>'file','directory'=>$fixture.'/factors'],
    'authentication'=>['identity_provider'=>'identity','request_guard'=>'request','managed_factors'=>true],
    'account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'worker','read_guard'=>'read','management_guard'=>'manage'],
],['db'=>$pdo,'accounts'=>$accounts,'keys'=>$keys,'raw'=>$raw,'fence'=>$fence,'identity'=>$provider,'request'=>$requestGuard,
    'worker'=>static function():bool{return true;},'read'=>static function():bool{return true;},'manage'=>static function():bool{return true;}]);
