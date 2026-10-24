<?php
declare(strict_types=1);
if(getenv('SOSECURITY_TEST_LOCKED_BASELINE')==='1'){require dirname(__DIR__).'/docs/locked-schema-evidence-2026-10-23/src__Support__SqlTransaction.php.before';}
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function lockedControl(string $sql):string{
 $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg($socket).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
 if(!is_resource($p)){throw new RuntimeException('Owned controller unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($p);if($code!==0){throw new RuntimeException('Owned control SQL failed');}return trim($out);
}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$otherCreated=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)===''){continue;}$pdo->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}
 $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$policy=new SoSecurity\Account\Policy();$clock=new SoSecurity\Support\SystemClock();
 $u=new SoSecurity\Support\SqlTransaction($pdo,$clock,10000);$l=new SoSecurity\Account\Ledger($u,'owned','tenant',str_repeat('e',64),$keys,$policy);$u->run(static function()use($l):void{$l->initialize();});
 foreach($created as $table){$pdo->exec('CREATE TABLE sosecurity_fk_other.'.$table.' LIKE sosecurity_test.'.$table);$otherCreated[]=$table;$pdo->exec('INSERT INTO sosecurity_fk_other.'.$table.' SELECT * FROM sosecurity_test.'.$table);}
 $pdo->exec('ALTER TABLE sosecurity_fk_other.sosecurity_account_roots ADD UNIQUE owned_extra_unique(revision)');
 $modes=getenv('SOSECURITY_TEST_LOCKED_BASELINE')==='1'?['normal']:['normal','permission','permission-roots','permission-records','temporary','temporary-records','database','database-clone','global-revokes','data','write','ended','borrow','borrow-failure'];
 if(getenv('SOSECURITY_TEST_LOCKED_BORROW_ONLY')==='1'){$modes=['borrow','borrow-failure'];}
 foreach($modes as $mode){
  lockedControl("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sosecurity_reader'@'localhost'; GRANT SELECT,INSERT,UPDATE,DELETE,TRIGGER,CREATE TEMPORARY TABLES ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'; GRANT SELECT,INSERT,UPDATE,DELETE,TRIGGER,CREATE TEMPORARY TABLES ON sosecurity_fk_other.* TO 'sosecurity_reader'@'localhost'; SET GLOBAL partial_revokes=OFF");
  if($mode==='global-revokes'){lockedControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'; GRANT TRIGGER ON *.* TO 'sosecurity_reader'@'localhost'");}
  $reader=new PDO($dsn,'sosecurity_reader','integration-read-only',$options);$unit=new SoSecurity\Support\SqlTransaction($reader,$clock,10000);$ledger=new SoSecurity\Account\Ledger($unit,'owned','tenant',str_repeat('e',64),$keys,$policy);$error=null;$calls=0;$temporary=false;$lostReason=null;
  if(in_array($mode,['normal','write','borrow','borrow-failure'],true)){lockedControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");$id=(int)$reader->query('SELECT CONNECTION_ID()')->fetchColumn();}
  try{$unit->run(static function()use($reader,$unit,$ledger,$mode,&$calls,&$temporary,&$lostReason):void{
   $first=$ledger->checkpoint();
   if($mode==='borrow'||$mode==='borrow-failure'){
    $child=new SoSecurity\Support\SqlTransaction($reader,new SoSecurity\Support\SystemClock(),10000);
    $childLedger=new SoSecurity\Account\Ledger($child,'owned','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]),new SoSecurity\Account\Policy());
    $read=static function()use($child,$unit,$childLedger):array{return $child->readIn($unit,static function()use($childLedger):array{return $childLedger->checkpoint();});};
    Check::same($first,$read());
    if($mode==='borrow-failure'){
     $unit->invoke(static function():void{lockedControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");},[],'test.revoke');
     $failure=null;try{$read();}catch(SoSecurity\Exception\ConfigurationException $caught){$failure=$caught;}Check::same(true,$failure!==null);Check::same('configuration.sql_schema',$failure->reason());
     $unit->invoke(static function():void{lockedControl("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");},[],'test.restore');
    }
    Check::same($first,$ledger->checkpoint());Check::same($first,$read());++$calls;return;
   }
   try{$unit->invoke(static function()use($reader,$ledger,$mode,&$temporary):void{
    if($mode==='permission'){lockedControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");}
    if($mode==='permission-roots'||$mode==='permission-records'){lockedControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'; GRANT TRIGGER ON sosecurity_test.sosecurity_account_".($mode==='permission-roots'?'roots':'records')." TO 'sosecurity_reader'@'localhost'");}
    if($mode==='global-revokes'){lockedControl('SET GLOBAL partial_revokes=ON');}
    if($mode==='data'){$ledger->put(hash('sha256','owned-entry'),hash('sha256','owned-owner'),'budget','{}',time()+60);}
    if($mode==='temporary'||$mode==='temporary-records'){$reader->exec('CREATE TEMPORARY TABLE sosecurity_account_'.($mode==='temporary'?'roots':'records').'(x INT) ENGINE=InnoDB');$temporary=true;}
    if($mode==='database'||$mode==='database-clone'){$reader->exec('USE sosecurity_fk_other');if($mode==='database'){$reader->exec('CREATE TEMPORARY TABLE sosecurity_account_roots(x INT) ENGINE=InnoDB');$temporary=true;}}
    if($mode==='ended'){$reader->exec('COMMIT');}
   },[],'test.callback');}catch(SoSecurity\Exception\ConfigurationException $caught){if($mode==='ended'){$lostReason=$caught->reason();}throw $caught;}
   if($mode==='write'){$unit->query('UPDATE sosecurity_account_roots SET revision=revision WHERE namespace=:namespace',['namespace'=>$first['namespace']])->closeCursor();}
   $second=$ledger->checkpoint();if($mode==='data'){Check::same(1,$second['entries']);Check::same(true,$second['revision']>$first['revision']);}else{Check::same($first,$second);}$unit->invoke(static function():bool{return true;},[],'test.callback');Check::same($second,$ledger->checkpoint());++$calls;
  });}catch(SoSecurity\Exception\ConfigurationException|SoSecurity\Exception\SecurityException $caught){$error=$caught;}
  Check::same(in_array($mode,['normal','write','data','borrow','borrow-failure'],true),$error===null);Check::same(in_array($mode,['normal','write','data','borrow','borrow-failure'],true)?1:0,$calls);
  if(in_array($mode,['permission','permission-roots','permission-records','global-revokes','database-clone'],true)){Check::same('configuration.sql_schema',$error->reason());}
  if($mode==='temporary'||$mode==='temporary-records'||$mode==='database'){Check::same('sql.unavailable',$error->reason());}
  if($mode==='temporary'||$mode==='temporary-records'){Check::same(true,$temporary);}
  if($mode==='ended'){Check::same('configuration.sql_transaction_lost',$lostReason);Check::same('sql.cleanup',$error->reason());}
  if(in_array($mode,['normal','write','borrow','borrow-failure'],true)){
   $reads=(int)lockedControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND argument LIKE '%information_schema.COLUMNS%'");lockedControl('SET GLOBAL general_log=OFF');
   echo 'FULL_SCHEMA_READS '.$mode.' '.$reads.PHP_EOL;Check::same(getenv('SOSECURITY_TEST_LOCKED_BASELINE')==='1'?3:(in_array($mode,['write','borrow-failure'],true)?2:1),$reads);
  }
  try{$reader->exec('ROLLBACK');}catch(Throwable $e){}if($temporary){$reader->exec('DROP TEMPORARY TABLE sosecurity_account_'.($mode==='temporary-records'?'records':'roots'));}$reader=null;
  echo 'PASS locked ledger schema '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{
 lockedControl('SET GLOBAL general_log=OFF; SET GLOBAL partial_revokes=OFF');foreach(array_reverse($otherCreated) as $table){$pdo->exec('DROP TABLE sosecurity_fk_other.'.$table);}foreach(array_reverse($created) as $table){$pdo->exec('DROP TABLE '.$table);}
}
