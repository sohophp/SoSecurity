<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$backend=$argv[1]??'sqlite';$mysql=$backend==='mysql';if(!in_array($backend,['mysql','sqlite'],true)){throw new RuntimeException('Owned backend required');}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
foreach(['inbox','processor'] as $component){foreach(['normal','locked','short-policy','policy-change','entry-throw','restore-throw','zero'] as $mode){
 if($mysql&&$mode==='zero'){continue;}if($component==='inbox'&&$mode==='restore-throw'){continue;} // No unknown receipt continuation or post-commit receipt failure experiment.
 $e=new InboxEnvironment($mysql,'standard-hmac',['io_milliseconds'=>1000]);$other=null;$locked=false;$processing=false;$entry=null;$sets=0;$injected=false;$changed=false;$reason=null;$result=null;
 try{
  $change=static function()use($e,$mysql,$mode,&$changed,&$entry):void{if($mode==='policy-change'&&!$changed&&$entry!==null){$changed=true;$e->pdo->exec($mysql?'SET SESSION lock_wait_timeout=9':'PRAGMA busy_timeout=7');}};
  $e->onAssociation=static function()use($change):void{$change();};
  if($component==='processor'){$schema=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql');foreach(explode(';',$schema) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}$processing=true;
   $processor=new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(){throw new RuntimeException('No receipt mapping allowed');},static function(){return true;},static function()use($change):bool{$change();return true;},new SoSecurity\Webhook\ProcessingPolicy(['io_milliseconds'=>1000]),$e->clock);
  }
  $original=$mode==='zero'?0:($mode==='short-policy'?($mysql?1:5):($mysql?23:19000));$e->pdo->exec($mysql?'SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout='.$original:'PRAGMA busy_timeout='.$original);
  $e->pdo->afterExec=static function(string $sql)use($mysql,$mode,&$entry,&$sets,&$injected):void{
   if(!preg_match($mysql?'/\ASET SESSION lock_wait_timeout=(\d+)\z/':'/\APRAGMA busy_timeout=(\d+)\z/',$sql,$m)){return;}
   ++$sets;if($entry===null){$entry=(int)$m[1];}
   if(!$injected&&(($mode==='entry-throw'&&$sets===1)||($mode==='restore-throw'&&$sets===2))){$injected=true;throw new RuntimeException('PRIVATE-WEBHOOK-SET');}
  };
  if($mode==='locked'){
   $other=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$e->database,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
   $other->exec($mysql?'LOCK TABLES sosecurity_webhook_'.($component==='inbox'?'inbox':'processing').' WRITE':'BEGIN IMMEDIATE');$locked=true;
  }
  $start=microtime(true);
  try{$result=$component==='inbox'?$e->receive():$processor->pending('worker');}catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();$chain=$error;$depth=0;while($chain!==null){Check::same(false,strpos($chain->getMessage(),'PRIVATE-')!==false);Check::same(true,++$depth<=4);$chain=$chain->getPrevious();}}
  $seconds=microtime(true)-$start;$e->pdo->afterExec=null;if($locked){$other->exec($mysql?'UNLOCK TABLES':'ROLLBACK');$locked=false;}
  Check::same(true,is_int($entry));Check::same(true,$entry<=($mysql?1:1000));if($mode==='zero'){Check::same(0,$entry);}
  if(in_array($mode,['locked','entry-throw','restore-throw'],true)){Check::same(true,is_string($reason));}
  else{Check::same(null,$reason);Check::same(true,$component==='inbox'?$result instanceof SoSecurity\Webhook\Receipt:is_array($result));}
  if($mode==='locked'){Check::same(true,$seconds>=0.8&&$seconds<2.5);}
  if($mode==='policy-change'){Check::same(true,$changed);}
  Check::same(false,$e->pdo->inTransaction());
  $q=$e->pdo->query($mysql?'SELECT @@SESSION.lock_wait_timeout':'PRAGMA busy_timeout');$restored=(int)$q->fetchColumn();$q->closeCursor();Check::same($original,$restored);
  if($mysql){$q=$e->pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout');$row=(int)$q->fetchColumn();$q->closeCursor();if($mode!=='restore-throw'){Check::same(19,$row);}}
  Check::same($component==='inbox'&&!in_array($mode,['locked','entry-throw'],true)?1:0,$e->count());
  if($mode==='restore-throw'){Check::throws(SoSecurity\Storage\StorageException::class,static function()use($processor):void{$processor->pending('worker');});}
  echo 'PASS Webhook SQL lock policy '.json_encode(['backend'=>$backend,'component'=>$component,'mode'=>$mode,'entry'=>$entry,'seconds'=>$seconds,'reason'=>$reason,'php'=>PHP_VERSION]).PHP_EOL;
 }finally{$e->pdo->afterExec=null;if($locked){$other->exec($mysql?'UNLOCK TABLES':'ROLLBACK');}if($e->pdo->inTransaction()){$e->pdo->rollBack();}if($processing&&$mysql){$e->pdo->exec('DROP TABLE sosecurity_webhook_processing');}$other=null;$e->close();}
}}
