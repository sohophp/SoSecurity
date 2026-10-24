<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$other=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=false;
try{
 $pdo->exec('CREATE TABLE sosecurity_mdl_probe(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;
 $other->exec('SET SESSION lock_wait_timeout=1');echo 'ENV MySQL '. $pdo->query('SELECT VERSION()')->fetchColumn().PHP_EOL;
 $phases=['closed-cursor','after-callback','after-savepoint-rollback','certificate-rollback','locked-certificate-rollback'];$selected=getenv('SOSECURITY_TEST_MDL_PHASE')?:'all';if($selected!=='all'&&!in_array($selected,$phases,true)){throw new RuntimeException('Unknown owned phase');}
 foreach($selected==='all'?$phases:[$selected] as $phase){
  $unit=new SoSecurity\Support\SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);
  if(in_array($phase,['certificate-rollback','locked-certificate-rollback'],true)){
   $reason=null;$afterReuse=0;$lost=false;$contextReads=0;
   $pdo->beginTransaction();$pdo->exec('SAVEPOINT owned_before_certificate');
   try{$unit->inContext(static function()use($unit,$phase,&$afterReuse,&$lost,&$contextReads):void{
    $verify=static function()use($unit):void{$unit->query(SoSecurity\Support\SqlSchema::tableResolution('sosecurity_mdl_probe'))->closeCursor();};
    $context=$phase==='locked-certificate-rollback'?static function()use($unit,&$contextReads):array{++$contextReads;return ['database'=>$unit->query('SELECT DATABASE()')->fetchColumn()];}:null;
    $unit->verifySchema('owned-mdl-certificate',$verify,$context);
    $unit->connection()->exec('ROLLBACK TO SAVEPOINT owned_before_certificate');
    try{$unit->verifySchema('owned-mdl-certificate',$verify,$context);}catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.sql_transaction_lost',$error->reason());$lost=true;throw $error;}++$afterReuse;
   });}catch(SoSecurity\Storage\StorageException $error){$reason=$error->reason();}
   Check::same('sql.cleanup',$reason);Check::same(true,$lost);Check::same(0,$afterReuse);Check::same(false,$unit->committed());Check::same($phase==='locked-certificate-rollback'?1:0,$contextReads);
   // This connection and its empty transaction belong exclusively to this test.
   $pdo->rollBack();
  }else{
  $unit->run(static function()use($unit,$other,$phase):void{
   if($phase==='after-savepoint-rollback'){$unit->connection()->exec('SAVEPOINT owned_mdl_before_read');}
   $unit->query(SoSecurity\Support\SqlSchema::tableResolution('sosecurity_mdl_probe'))->closeCursor();
   if($phase==='after-callback'){$unit->invoke(static function():bool{return true;},[],'test.callback');}
   if($phase==='after-savepoint-rollback'){
    foreach(['ROLLBACK TO SAVEPOINT owned_mdl_before_read','RELEASE SAVEPOINT owned_mdl_before_read'] as $command){try{$unit->connection()->exec($command);}catch(PDOException $error){echo 'DIAGNOSTIC owned savepoint '.substr($command,0,8).' state '.($error->errorInfo[0]??'none').' code '.($error->errorInfo[1]??0).PHP_EOL;throw $error;}}
   }
   $code=null;
   try{$other->exec('ALTER TABLE sosecurity_mdl_probe ADD COLUMN changed BIGINT UNSIGNED NOT NULL DEFAULT 0');}
   catch(PDOException $error){$code=isset($error->errorInfo[1])?(int)$error->errorInfo[1]:null;}
   echo 'OBSERVATION metadata lock '.$phase.' ddl_code '.($code===null?'accepted':$code).PHP_EOL;
   Check::same($phase==='after-savepoint-rollback'?null:1205,$code);
  });
  Check::same(true,$unit->committed());
  }
  if($phase!=='after-savepoint-rollback'){$other->exec('ALTER TABLE sosecurity_mdl_probe ADD COLUMN changed BIGINT UNSIGNED NOT NULL DEFAULT 0');}
  $other->exec('ALTER TABLE sosecurity_mdl_probe DROP COLUMN changed');
  echo 'PASS schema metadata lock '.$phase.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{
 try{$pdo->exec('ROLLBACK');}catch(Throwable $e){}
 if($created){$pdo->exec('DROP TABLE sosecurity_mdl_probe');}
}
