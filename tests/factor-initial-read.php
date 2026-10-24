<?php
declare(strict_types=1);
require __DIR__.'/account-factor/support.php';
$mode=$argv[2]??'normal';
managedCase(static function(ManagedEnvironment $e)use($mode):void{
 Check::same(true,$e->registry->initialize('user'));$phases=[];$roots=0;$bodies=0;$injected=false;$temporary=false;
 if($mode==='initial-root-corrupt'){$e->pdo->exec("UPDATE sosecurity_account_roots SET seal='invalid'");}
 if($mode==='initial-body-corrupt'){$e->pdo->exec("UPDATE sosecurity_account_records SET payload='invalid'");}
 $digest=static function()use($e):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM account_example ORDER BY subject')->fetchAll(PDO::FETCH_ASSOC),$e->pdo->query('SELECT * FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$e->pdo->query('SELECT * FROM sosecurity_account_records ORDER BY namespace,record_id')->fetchAll(PDO::FETCH_ASSOC)]));};$before=$digest();
 $e->pdo->beforeStatement=static function(string $sql)use($e,$mode,&$roots,&$bodies,&$injected,&$temporary):void{
  if(strpos($sql,'SELECT payload,')===0){++$bodies;}
  if(strpos($sql,'AS history_digest')!==false){++$roots;}
  if(!$injected&&strpos($sql,' FROM account_example WHERE ')!==false&&strpos($mode,'account-')===0){
   $injected=true;
   if($mode==='account-temporary'){$e->pdo->exec('CREATE TEMPORARY TABLE sosecurity_account_records(namespace VARCHAR(64),record_id VARCHAR(64),payload LONGBLOB) ENGINE=InnoDB');$temporary=true;}
   elseif($mode==='account-disabled'){$e->pdo->exec("UPDATE account_example SET status='disabled' WHERE subject='user'");}
   elseif($mode==='account-unverified'){$e->pdo->exec("UPDATE account_example SET verified=0 WHERE subject='user'");}
   elseif($mode==='account-delete'){$e->pdo->exec('DELETE FROM sosecurity_account_records');}
   elseif($mode==='account-body'){$e->pdo->exec("UPDATE sosecurity_account_records SET payload='invalid'");}
   elseif($mode==='account-root'){$e->pdo->exec("UPDATE sosecurity_account_roots SET seal='invalid'");}
   elseif($mode==='account-valid-write'){
    $row=$e->pdo->query('SELECT * FROM sosecurity_account_records')->fetch(PDO::FETCH_ASSOC);
    $unit=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);
    $ledger=new SoSecurity\Account\Ledger($unit,'account-factor-directory:'.hash('sha256',json_encode(['managed-test','user'])),'tenant',str_repeat('e',64),$e->keys,new SoSecurity\Account\Policy());
    $unit->enlist(static function()use($ledger,$row):void{$ledger->put($row['record_id'],$row['owner'],$row['kind'],$row['payload'],(int)$row['retire_at'],(int)$row['revision']);});
   }
  }
 };
 $e->onRead=static function(string $action,string $phase)use($mode,$e,&$phases):bool{$phases[]=$phase;if(($mode==='before-denial'&&$phase==='before')||($mode==='current-denial'&&$phase==='current')){return false;}if($phase==='return'){
  if($mode==='return-denial'){return false;}
  if($mode==='return-account-change'){$e->pdo->exec("UPDATE account_example SET credential_version='changed' WHERE subject='user'");}
  if($mode==='return-body-change'){$q=$e->pdo->prepare('UPDATE sosecurity_account_records SET payload=?');$q->bindValue(1,'changed',PDO::PARAM_LOB);$q->execute();}
 }return true;};
 if($mode==='normal'){Check::same(true,$e->registry->current('user')->enabled());Check::same(2,$roots);Check::same(['before','current','return'],$phases);}
 elseif($mode==='binding'){Check::same(true,is_string($e->registry->binding('tenant','user')));Check::same(4,$roots);Check::same(['before','current','return','before','current','return'],$phases);}
 else{Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($e):void{$e->registry->current('user');});}
 if($mode==='account-temporary'){Check::same(true,$temporary);$e->pdo->exec('DROP TEMPORARY TABLE sosecurity_account_records');Check::same(0,$bodies);Check::same(['before'],$phases);}
 if($mode==='account-disabled'||$mode==='account-unverified'){Check::same(0,$bodies);Check::same(['before'],$phases);}
 if($mode==='account-valid-write'){Check::same(['before','current','return'],$phases);}
 if(strpos($mode,'account-')===0){Check::same(true,$injected);}
 Check::same(false,$e->pdo->inTransaction());Check::same($before,$digest());
 // These three tables were created by this case in the controller-owned disposable server.
 if(($GLOBALS['argv'][1]??'')==='mysql'){foreach(['account_example','sosecurity_account_records','sosecurity_account_roots'] as $table){$e->pdo->exec('DROP TABLE '.$table);}}
});
echo 'PASS factor initial read '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
