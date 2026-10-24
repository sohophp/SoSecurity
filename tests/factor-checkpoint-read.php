<?php
declare(strict_types=1);
require __DIR__.'/account-factor/support.php';
$mode=$argv[2]??'normal';
managedCase(static function(ManagedEnvironment $e)use($mode):void{
 Check::same(true,$e->registry->initialize('user'));$phases=[];$roots=0;
 $digest=static function()use($e):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM account_example ORDER BY subject')->fetchAll(PDO::FETCH_ASSOC),$e->pdo->query('SELECT * FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$e->pdo->query('SELECT * FROM sosecurity_account_records ORDER BY namespace,record_id')->fetchAll(PDO::FETCH_ASSOC)]));};$before=$digest();
 $e->pdo->beforeStatement=static function(string $sql)use(&$roots):void{if(strpos($sql,'AS history_digest')!==false){++$roots;}};
 $e->onRead=static function(string $action,string $phase)use($mode,$e,&$phases):bool{$phases[]=$phase;if($phase==='return'){
  if($mode==='return-denial'){return false;}
  if($mode==='return-account-change'){$e->pdo->exec("UPDATE account_example SET credential_version='changed' WHERE subject='user'");}
  if($mode==='return-body-change'){$q=$e->pdo->prepare('UPDATE sosecurity_account_records SET payload=?');$q->bindValue(1,'changed',PDO::PARAM_LOB);$q->execute();}
 }return true;};
 if($mode==='normal'){Check::same(true,$e->registry->current('user')->enabled());Check::same(2,$roots);Check::same(['before','current','return'],$phases);}
 elseif($mode==='binding'){Check::same(true,is_string($e->registry->binding('tenant','user')));Check::same(4,$roots);Check::same(['before','current','return','before','current','return'],$phases);}
 else{Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($e):void{$e->registry->current('user');});}
 Check::same(false,$e->pdo->inTransaction());Check::same($before,$digest());
});
echo 'PASS factor checkpoint read '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
