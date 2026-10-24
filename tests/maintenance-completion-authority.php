<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/address-change-support.php';
if(($argv[1]??'')==='mysql'){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\SecurityException;
foreach(['registration','address'] as $family){foreach(['maintain','rotate'] as $action){foreach(['commit','cleanup','before','allow','throw'] as $stage){
 $change=$family==='address'?new ChangeEnvironment():null;$e=$change===null?new RegistrationEnvironment():$change->e;
 try{
  if($change===null){$s=$e->service();$s->initialize();$s->request('owner@example.com','setup');}else{$s=$change->service;$change->request();}
  $e->clock->time+=172800;$before=$e->count('sosecurity_account_records');$account=$e->account();$queue=$e->observer->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,order_no')->fetchAll(PDO::FETCH_ASSOC);
  $allowed=true;$completed=false;$phases=[];
  $guard=static function(string $a,string $phase)use($action,$stage,&$allowed,&$phases):bool{if($a!==$action){return true;}$phases[]=$phase;if($stage==='before'&&$phase==='commit'){return false;}if($stage==='throw'&&$phase==='complete'){throw new RuntimeException('private-maintenance-authority');}return $allowed;};
  if($change===null){$e->onManagement=$guard;}else{$change->onManager=$guard;}
  $e->pdo->afterCommit=static function()use(&$allowed,&$completed,$stage):void{$completed=true;if($stage==='commit'){$allowed=false;}};
  $e->pdo->afterExec=static function(string $sql)use(&$allowed,&$completed,$stage):void{if($stage==='cleanup'&&$completed&&(strpos($sql,'PRAGMA busy_timeout=')===0||strpos($sql,'SET SESSION innodb_lock_wait_timeout=')===0)){$allowed=false;}};
  if($stage==='allow'){$r=$s->$action();Check::same(true,is_array($r));Check::same(true,in_array('complete',$phases,true));}
  elseif($stage==='before'){Check::throws(SecurityException::class,static function()use($s,$action):void{$s->$action();});Check::same(false,$completed);}
  else{try{$s->$action();throw new RuntimeException('Maintenance returned success after authority loss: '.$family.'/'.$action.'/'.$stage);}catch(StorageException $error){Check::same('account.completion_unknown',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-maintenance-authority')!==false);}Check::same(true,$completed);}
  $e->pdo->afterCommit=null;$e->pdo->afterExec=null;
  Check::same($account,$e->account());Check::same($queue,$e->observer->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,order_no')->fetchAll(PDO::FETCH_ASSOC));
  if($action==='maintain'&&$stage!=='before'){Check::same(true,$e->count('sosecurity_account_records')<$before);}else{Check::same($before,$e->count('sosecurity_account_records'));}
 }finally{if($change!==null){$change->close();}else{$e->close();}}
}}}
echo 'PASS maintenance completion authority: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.(($argv[1]??'')==='mysql'?'mysql':'sqlite').PHP_EOL;
