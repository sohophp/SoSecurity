<?php
declare(strict_types=1);
// Explicit negative control: a fresh process using the SDK with witness protection omitted.
require dirname(__DIR__).'/bootstrap.php';
require dirname(__DIR__,2).'/examples/SqlAccounts.php';
try{
    $input=$argv[1]??'';$directory=dirname($input);
    if(!preg_match('~\A/tmp/sosecurity-test-[a-f0-9]{16}\z~D',$directory)||realpath($directory)!==$directory||!is_file($directory.'/owned-state-backup-test')||is_link($input)){
        throw new RuntimeException('Owned negative-control data required.');
    }
    $raw=file_get_contents($input,false,null,0,4097);$v=json_decode($raw,true,4);
    if(!is_string($raw)||strlen($raw)>4096||!is_array($v)||array_keys($v)!==['mysql','time','session','remember','mode','recovery','factor']){throw new RuntimeException('Invalid negative-control input.');}
    $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if($v['mysql']&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Owned no-TCP database required.');}
    $dsn=$v['mysql']?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/managed.sqlite';
    $pdo=new PDO($dsn,$v['mysql']?'sosecurity_test':null,$v['mysql']?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $clock=new TestClock();$clock->time=$v['time'];$keys=new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('s',32)]);
    $fence=new SoSecurity\Account\LocalEpochFence($directory.'/authority','managed-test','tenant',str_repeat('e',64),$keys,new SoSecurity\Account\LocalStatePersistence($directory.'/authority',5000),5000);
    $authority=new SoSecurity\Account\FactorWorkerAuthority($pdo,'managed-test','tenant',str_repeat('e',64),$keys,$fence,static function():bool{return true;},new SoSecurity\Account\Policy(),$clock);
    $factorStore=new SoSecurity\Storage\FileStore($directory.'/factors','managed-factor-test',$clock,5000);
    $factors=(new SoSecurity\Mfa\TotpFactors($factorStore,new SoSecurity\Crypto\Cipher('test',['test'=>str_repeat('t',32)],'managed-test'),'Managed test',$clock))->managedRegistered('managed-test','tenant',str_repeat('e',64),$keys,$fence,$authority);
    $accounts=new SoSecurity\Account\Example\SqlAccounts($pdo);
    $registry=new SoSecurity\Account\FactorRegistry($pdo,'managed-test','tenant',str_repeat('e',64),$keys,$accounts,$factors,static function():bool{return true;},static function():bool{return true;},null,$clock,$fence);
    $hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);
    $provider=new SoSecurity\Auth\PasswordIdentityProvider(static function(string $scope,string $address)use($accounts){$r=$accounts->findAddress($scope,new SoSecurity\Account\Address($address));return $r===null?null:$accounts->passwordRecord($r);},static function(string $scope,string $subject)use($accounts){$r=$accounts->find($scope,$subject);return $r===null?null:$accounts->passwordRecord($r);},$hasher,$hasher->hash('Owned negative-control dummy password 49!'));
    $store=new SoSecurity\Storage\FileStore($directory.'/factors','entry-sessions',$clock,5000);$adapter=$registry->secondFactor();
    $sessions=new SoSecurity\Auth\SessionRegistry($store,$provider,$adapter,$clock);
    $remember=new SoSecurity\Auth\RememberedLogin($store,$provider,$sessions,$keys,static function():bool{return true;},$adapter,$clock);
    $sessionAccepted=$sessions->verify('tenant','user',$v['session'],2)!==null;
    $rememberAccepted=$remember->resume('tenant',$v['remember'])->status()==='authenticated';
    $recoveryAccepted=null;
    if($v['mode']==='recovery'){$slot=$registry->current('user');$recoveryAccepted=$factors->verifyBound($slot->slotScope(),$slot->slotSubject(),$slot->factorId(),$v['recovery'],true);}
    echo json_encode(['session'=>$sessionAccepted,'remember'=>$rememberAccepted,'recovery'=>$recoveryAccepted]),PHP_EOL;
}catch(Throwable $error){fwrite(STDERR,$error instanceof SoSecurity\Exception\SecurityException?$error->reason():get_class($error));exit(2);}
