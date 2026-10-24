<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';
if(($argv[1]??'')==='mysql'){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
use SoSecurity\Account as A;
use SoSecurity\Storage\StorageException;
foreach(['maintain','rotate','notification'] as $action){foreach(array_merge(['commit','cleanup','throw','allow'],$action==='notification'?['account','expiry']:[]) as $stage){
 $e=new RegistrationEnvironment();
 try{
  $allowed=true;$committed=false;$phases=[];
  $guard=static function(string &$a,string &$phase,string &$scope)use($action,$stage,&$allowed,&$phases):bool{$result=true;if($a===$action){$phases[]=$phase;if($stage==='throw'&&$phase==='complete'){throw new RuntimeException('private-factor-notice-authority');}$result=$allowed;}$a='mutated';$phase='mutated';$scope='mutated';return $result;};
  $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);
  $s=new A\FactorNotices($e->pdo,'owned-notice','tenant',str_repeat('e',64),$keys,$keys,$e->accounts,new A\Notifications('owned',['owned'=>str_repeat('n',32)],$e->clock),$guard,static function():bool{return true;},$guard,null,$e->clock);$s->initialize();
  $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$pending=$e->accounts->createPending('tenant','fresh',new A\Address('owned@example.test'));$e->accounts->activate($pending,$e->hasher->hash('Owned new account password 48!'));$id=$s->publish('factor_management_completed','fresh',str_repeat('1',64));$e->pdo->exec('COMMIT');
  if($action==='maintain'){$e->clock->time+=172800;}
  $accounts=$e->observer->query('SELECT * FROM account_example')->fetchAll(PDO::FETCH_ASSOC);$queue=$e->observer->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC);
  $e->pdo->afterCommit=static function()use(&$allowed,&$committed,$stage,$e):void{$committed=true;if($stage==='account'){$e->observer->exec('UPDATE account_example SET roles=\'["changed"]\'');}if($stage==='expiry'){$e->clock->time+=172800;}if($stage==='commit'){$allowed=false;}};
  $e->pdo->afterExec=static function(string $sql)use(&$allowed,&$committed,$stage):void{if($stage==='cleanup'&&$committed&&(strpos($sql,'PRAGMA busy_timeout=')===0||strpos($sql,'SET SESSION innodb_lock_wait_timeout=')===0)){$allowed=false;}};
  $call=static function()use($s,$action,$id){return $action==='notification'?$s->notificationForDispatch($id):$s->$action();};
  if($stage==='allow'){Check::same(true,$call()!==null);Check::same(true,in_array('complete',$phases,true));}
  else{try{$call();throw new RuntimeException('Committed notification operation returned after authority loss: '.$action.'/'.$stage);}catch(StorageException $error){Check::same('account.completion_unknown',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}}
  Check::same(true,$committed);$e->pdo->afterCommit=null;$e->pdo->afterExec=null;
  if($stage==='account'){$accounts[0]['roles']='["changed"]';}Check::same($accounts,$e->observer->query('SELECT * FROM account_example')->fetchAll(PDO::FETCH_ASSOC));Check::same($queue,$e->observer->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC));
  Check::same($action==='maintain'?0:1,$e->count('sosecurity_account_records'));
 }finally{
  if($e->mysql){foreach(['sosecurity_outbox_records','sosecurity_outbox_roots','sosecurity_account_records','sosecurity_account_roots','account_example'] as $table){$e->observer->exec('DROP TABLE '.$table);}}
  $e->close();
 }
}}
echo 'PASS factor notice completion: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
