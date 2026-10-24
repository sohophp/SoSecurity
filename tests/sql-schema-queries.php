<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\ConfigurationException;
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$directory=privateDirectory();$pdo=null;
try{
 $pdo=new InboxTestConnection($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/schema.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);if($mysql){$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
 $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);$triggerReads=0;$count=0;$guards=0;$metadata=0;$pdo->beforeStatement=static function(string $sql)use(&$count,&$guards,&$metadata,&$triggerReads):void{$triggerReads+=substr_count($sql,'information_schema.TRIGGERS');if(strpos($sql,'information_schema.COLUMNS')!==false||strpos($sql,'information_schema.STATISTICS')!==false){++$metadata;}if(strpos($sql,'information_schema.KEY_COLUMN_USAGE')!==false||strpos($sql,'information_schema.TRIGGERS')!==false){++$guards;}if(strpos($sql,'information_schema.TABLES')!==false||strpos($sql,'information_schema.COLUMNS')!==false){++$count;}};
 foreach(['valid','extra-column','wrong-type','nullable','wrong-engine','many-columns','long-type','missing'] as $mode){
  if(!$mysql&&in_array($mode,['wrong-engine','long-type'],true)){continue;}
  $pdo->exec('DROP TABLE IF EXISTS sosecurity_query_probe');
  if($mode!=='missing'){$type=$mysql?'BIGINT UNSIGNED':'INTEGER';if($mode==='long-type'){$type="ENUM('".str_repeat('x',200)."')";}if($mode==='wrong-type'){$type=$mysql?'INT UNSIGNED':'TEXT';}$pdo->exec('CREATE TABLE sosecurity_query_probe(id '.($mysql?'BIGINT UNSIGNED':'INTEGER').' NOT NULL PRIMARY KEY,value '.$type.($mode==='nullable'?'':' NOT NULL').($mode==='extra-column'?',extra INTEGER NOT NULL':'').')'.($mysql?' ENGINE='.($mode==='wrong-engine'?'MyISAM':'InnoDB'):''));}
  if($mode==='many-columns'){for($i=0;$i<63;++$i){$pdo->exec('ALTER TABLE sosecurity_query_probe ADD COLUMN extra_'.$i.' INTEGER NOT NULL DEFAULT 0');}}
  $unit=SqlTransaction::forObservation($pdo,new TestClock(),10000);$count=0;$guards=0;$metadata=0;$triggerReads=0;
  $run=static function()use($unit):void{$unit->run(static function()use($unit):void{SqlSchema::table($unit,'sosecurity_query_probe',['id'=>'int','value'=>'int'],['id']);});};
  if($mode==='valid'){$run();if($mysql){echo 'STRUCTURE_QUERIES '.$count.PHP_EOL;Check::same(1,$count);echo 'GUARD_QUERIES '.$guards.PHP_EOL;Check::same(1,$guards);Check::same(1,$metadata);Check::same(1,$triggerReads);}}
  else{Check::throws($mode==='missing'?SoSecurity\Exception\SecurityException::class:ConfigurationException::class,$run);}
 }
}finally{if($pdo!==null&&$mysql){$pdo->exec('DROP TABLE IF EXISTS sosecurity_query_probe');}$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS bounded ledger structure queries '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
