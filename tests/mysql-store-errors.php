<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$pdo=new InboxTestConnection('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);$mode=$argv[1];$called=false;$injected=false;$clock=new TestClock();
try{
 $pdo->exec(SoSecurity\Storage\MySqlStore::schema());$store=new SoSecurity\Storage\MySqlStore($pdo,'owned-errors',$clock);
 if($mode==='construct'){$pdo->beforeStatement=static function():void{throw new PDOException('PRIVATE-STORE-DETAIL');};}
 elseif($mode==='install'){$pdo->afterExec=static function(string $sql):void{if(strpos($sql,'CREATE TABLE')===0){throw new PDOException('PRIVATE-STORE-DETAIL');}};}
 else{
  if($mode==='prune'){$store->transact('owned-key',static function(){return new SoSecurity\Storage\Change(['owned'=>true],100001,null);});$clock->time=100002;}
  // Trigger-bearing schemas are rejected before data I/O. Inject a real server error at
  // the target data statement without invalidating the schema under test.
  $pdo->beforeStatement=static function(string $sql)use($pdo,$mode,&$injected):void{
   $prefix=$mode==='prune'?'DELETE FROM sosecurity_state':'INSERT INTO sosecurity_state';
   if(strpos($sql,$prefix)===0){$injected=true;$pdo->exec("SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='PRIVATE-STORE-DETAIL'");}
  };
 }
 $caught=null;
 try{
  if($mode==='construct'){new SoSecurity\Storage\MySqlStore($pdo,'owned-errors',$clock);}
  elseif($mode==='install'){SoSecurity\Storage\MySqlStore::install($pdo);}
  elseif($mode==='prune'){$store->prune(1);}
  else{$store->transact('owned-key',static function()use(&$called){$called=true;return new SoSecurity\Storage\Change(['owned'=>true],200000,null);});}
 }catch(SoSecurity\Storage\StorageException $error){$caught=$error;}
 $pdo->beforeStatement=null;$pdo->afterExec=null;Check::same(!in_array($mode,['construct','install'],true),$injected);Check::same(true,$caught!==null);Check::same(in_array($mode,['construct','install'],true)?'storage.schema':'storage.database',$caught->reason());
 Check::same(null,$caught->getPrevious());Check::same(false,strpos($caught->getMessage(),'PRIVATE-')!==false);Check::same(false,$called);Check::same(false,$pdo->inTransaction());Check::same($mode==='prune'?1:0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_state')->fetchColumn());
 echo 'PASS private store error '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{$pdo->beforeStatement=null;$pdo->afterExec=null;$pdo->exec('DROP TABLE IF EXISTS sosecurity_state');}
