<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__).'/vendor/autoload.php';
use SoSecurity\WebAuthn\DeviceAuthority;
use SoSecurity\WebAuthn\DeviceManager;
use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;
final class DeviceBoundaryPdo extends PDO {
    public $hook;
    public function prepare(string $query,array $options=[]):PDOStatement|false {$result=parent::prepare($query,$options);if($this->hook!==null&&strpos($query,'SELECT')===0){($this->hook)();}return $result;}
}
$mode=$argv[2]??'permission';$backend=$argv[3]??'sqlite';
if($backend==='mysql'){
    $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET')?:'';if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned MySQL required');}
    $pdo=new DeviceBoundaryPdo('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $pdo->exec('DROP TABLE IF EXISTS sosecurity_webauthn_credential');$pdo->exec('DROP TABLE IF EXISTS sosecurity_webauthn_user');
    foreach(explode(';',file_get_contents(dirname(__DIR__).'/schema.mysql.sql')) as $sql){if(trim($sql)!==''){$pdo->exec($sql);}}
}else{$pdo=new DeviceBoundaryPdo('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$pdo->exec(file_get_contents(dirname(__DIR__).'/schema.sqlite.sql'));}
$repository=new SqlCredentialRepository($pdo,'device-boundary');
foreach(['one','two'] as $id){$repository->register(CredentialRecord::create($id,'public-key',[],'none',EmptyTrustPath::create(),Uuid::v4(),'not-a-real-key','alice',0),100,0);}
$clock=new class implements SoSecurity\Support\Clock {
    public $calls=0;public $failAt=0;
    public function now():int {if(++$this->calls===$this->failAt){throw new RuntimeException('SYNTHETIC-DEVICE-PRIVATE-CLOCK');}return 200;}
};
$authority=new class implements DeviceAuthority {
    public $denied=false;public $fail='';public $phases=[];
    public function allow(string $phase,string $scope,string $userHandle,string $credentialId,$proof,int $now):bool {$this->phases[]=$phase;if($phase===$this->fail){throw new RuntimeException('SYNTHETIC-DEVICE-PRIVATE-AUTHORITY');}return !$this->denied;}
};
if($mode==='permission'){$pdo->hook=static function()use($authority):void{$authority->denied=true;};}
if(in_array($mode,['before','current','return'],true)){$authority->fail=$mode;}
if($mode==='clock-before'){$clock->failAt=1;}
if($mode==='clock-return'){$clock->failAt=4;}
$notices=0;$manager=new DeviceManager($repository,$authority,static function()use(&$notices,$mode):void{++$notices;if($mode==='notice'){throw new RuntimeException('SYNTHETIC-DEVICE-PRIVATE-NOTICE');}},$clock);
$checks=0;$check=static function(bool $ok)use(&$checks):void{if(!$ok){throw new RuntimeException('Device boundary invariant failed');}++$checks;};
if($mode==='permission'){try{$check($manager->remove('alice','one','owned-proof')===false);}catch(RuntimeException $error){$pdo->hook=null;fwrite(STDERR,'Remaining devices after revoked authority: '.count($repository->forUser('alice')).PHP_EOL);throw $error;}}
else{
    try{$manager->remove('alice','one','owned-proof');throw new LogicException('Expected failure');}
    catch(RuntimeException $error){$check(get_class($error)===RuntimeException::class);$check($error->getPrevious()===null);$check(strpos($error->getMessage(),'SYNTHETIC')===false);}
}
$pdo->hook=null;$changed=in_array($mode,['return','notice','clock-return'],true);$check(count($repository->forUser('alice'))===($changed?1:2));$check($notices===($mode==='notice'?1:0));$check(!$pdo->inTransaction());
echo 'PASS WebAuthn device boundary '.$mode.': '.$checks.' assertions '.$backend.' PHP '.PHP_VERSION.PHP_EOL;
