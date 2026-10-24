<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Storage\StorageException;
$backend=$argv[1]??'sqlite';if(!in_array($backend,['sqlite','mysql'],true)){throw new RuntimeException('Use an owned supported backend');}$mysql=$backend==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
foreach(['busy','failed','admission-change'] as $state){foreach(['run','enlist','inContext'] as $method){
 $directory=privateDirectory();$pdo=null;$observer=null;$created=false;$armed=false;$guardEffects=0;$attempted=false;$bodyCalls=0;$innerReason=null;$outerReason=null;$guardCommitted=false;$poison=false;$poisoned=false;$unit=null;
 try{
  $dsn=$mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/owned.sqlite';$opts=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
  $pdo=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$opts);$observer=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$opts);
  if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
  $pdo->exec('CREATE TABLE sosecurity_unit_precheck(id '.($mysql?'BIGINT UNSIGNED':'INTEGER').' NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
  SqlStateAccess::bind($pdo,hash('sha256','owned-precheck:'.$state.':'.$method),hash('sha256','owned-precheck-binding:'.$state.':'.$method),static function()use($pdo,&$unit,&$poison,&$poisoned,&$armed,&$guardEffects,&$guardCommitted):void{if($poison){$poison=false;try{$unit->run(static function()use($unit,$pdo):void{$unit->invoke(static function()use($pdo):void{$pdo->exec('COMMIT');},[],'test.poison');});}catch(StorageException $error){Check::same('sql.cleanup',$error->reason());$poisoned=true;}}if($armed){++$guardEffects;$pdo->exec('COMMIT');$guardCommitted=true;}});
  $unit=new SqlTransaction($pdo,new TestClock(),10000);
  $invalid=static function()use($unit,$method,&$armed,&$attempted,&$bodyCalls,&$innerReason):void{
   $attempted=true;$armed=true;
   try{$unit->$method(static function()use(&$bodyCalls):void{++$bodyCalls;});}catch(StorageException $error){$innerReason=$error->reason();}finally{$armed=false;}
  };
  if($state==='admission-change'){
   $attempted=true;$poison=true;
   try{$unit->$method(static function()use($unit,&$bodyCalls):void{++$bodyCalls;$unit->query('INSERT INTO sosecurity_unit_precheck VALUES(1)')->closeCursor();});}catch(StorageException|SoSecurity\Exception\ConfigurationException $error){$innerReason=$error->reason();}
   Check::same(true,$poisoned);
  }elseif($state==='busy'){
   try{$unit->run(static function()use($unit,$pdo,$observer,$invalid):void{$unit->query('INSERT INTO sosecurity_unit_precheck VALUES(1)')->closeCursor();Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_unit_precheck')->fetchColumn());Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_unit_precheck')->fetchColumn());$invalid();throw new StorageException('Owned parent abort.','test.parent_abort');});}catch(StorageException $error){$outerReason=$error->reason();}
  }else{
   $failedReason=null;try{$unit->run(static function()use($unit,$pdo):void{$unit->invoke(static function()use($pdo):void{$pdo->exec('COMMIT');},[],'test.end');});}catch(StorageException $error){$failedReason=$error->reason();}Check::same('sql.cleanup',$failedReason);
   $pdo->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');Check::same(1,$pdo->exec('INSERT INTO sosecurity_unit_precheck VALUES(1)'));Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_unit_precheck')->fetchColumn());$invalid();
   if(!$guardCommitted){$pdo->exec('ROLLBACK');}
  }
  $visible=(int)$observer->query('SELECT COUNT(*) FROM sosecurity_unit_precheck')->fetchColumn();
  echo 'OBSERVATION unit precheck '.json_encode(['state'=>$state,'method'=>$method,'attempted'=>$attempted,'guard_effects'=>$guardEffects,'body_calls'=>$bodyCalls,'committed_rows'=>$visible,'inner_reason'=>$innerReason,'outer_reason'=>$outerReason]).PHP_EOL;
  Check::same(true,$attempted);Check::same('sql.cleanup',$innerReason);Check::same(0,$bodyCalls);Check::same(0,$guardEffects);Check::same(0,$visible);Check::same(false,$unit->committed());
  if($state==='admission-change'){
   $attempted=true;$poison=true;
   try{$unit->$method(static function()use($unit,&$bodyCalls):void{++$bodyCalls;$unit->query('INSERT INTO sosecurity_unit_precheck VALUES(1)')->closeCursor();});}catch(StorageException|SoSecurity\Exception\ConfigurationException $error){$innerReason=$error->reason();}
   Check::same(true,$poisoned);
  }elseif($state==='busy'){Check::same('test.parent_abort',$outerReason);}
  echo 'PASS SQL unit precheck '.$state.' '.$method.' '.$backend.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{
  $armed=false;if($pdo instanceof PDO){try{$pdo->exec('ROLLBACK');}catch(Throwable $cleanup){}}
  if($mysql&&$created){$observer->exec('DROP TABLE sosecurity_unit_precheck');}$observer=null;$pdo=null;gc_collect_cycles();cleanDirectory($directory);
 }
}}
