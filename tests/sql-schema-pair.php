<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Support\SqlSchema;use SoSecurity\Support\SqlTransaction;use SoSecurity\Exception\ConfigurationException;
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required');}
$directory=privateDirectory();$pdo=null;$reader=null;
$control=static function(string $sql)use($socket):void{
 $p=proc_open('mysql --no-defaults --protocol=SOCKET --socket='.escapeshellarg($socket).' --user=root --database=sosecurity_test --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned controller unavailable');}
 $input=$sql.';'.PHP_EOL;$n=fwrite($pipes[0],$input);fclose($pipes[0]);stream_get_contents($pipes[1],8192);fclose($pipes[1]);stream_get_contents($pipes[2],8192);fclose($pipes[2]);$exit=proc_close($p);if($n!==strlen($input)||$exit!==0){throw new RuntimeException('Owned controller failed');}
};
try{
 $dsn=$mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/pair.sqlite';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
 $pdo=new InboxTestConnection($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);
 $modes=['valid','reverse','multi-index','extra-index'];
 foreach(['first','second'] as $side){foreach(['missing','type','nullable','extra','primary','trigger','unique','foreign-out','foreign-in','foreign-disabled','many-columns'] as $kind){$modes[]=$side.':'.$kind;}if($mysql){$modes[]=$side.':engine';$modes[]=$side.':shadow';}}
 if($mysql){$modes=array_merge($modes,['scope-first','scope-second','scope-both','scope-hidden-first','scope-hidden-second']);}
 foreach($modes as $mode){$shadowTable=null;
  $parts=explode(':',$mode);$target=count($parts)===2?$parts[0]:'';$kind=count($parts)===2?$parts[1]:'';$metadata=0;$resolutions=0;$pdo->beforeStatement=static function(string $sql)use(&$metadata,&$resolutions):void{if(strpos($sql,'_sosecurity_left')!==false){++$resolutions;}if(strpos($sql,'information_schema.COLUMNS')!==false||strpos($sql,'information_schema.STATISTICS')!==false){++$metadata;}};
  $spec=[];$int=$mysql?'BIGINT UNSIGNED':'INTEGER';$suffix=$mysql?' ENGINE=InnoDB':'';
  try{
   $pdo->exec('CREATE TABLE pair_effects(value INTEGER NOT NULL)'.$suffix);$pdo->exec('CREATE TABLE pair_parent(id '.$int.' NOT NULL PRIMARY KEY)'.$suffix);
   foreach(['first','second'] as $side){
    $table='sosecurity_pair_'.$side;$bad=$side===$target;$indexes=['pair_'.$side.'_value'=>['unique'=>false,'columns'=>['value','id']]];
    if($mode==='multi-index'&&$side==='second'){for($i=0;$i<5;++$i){$indexes['pair_second_more_'.$i]=['unique'=>false,'columns'=>['id','value']];}}
    $spec[$table]=['types'=>['id'=>'int','value'=>'int'],'primary'=>['id'],'indexes'=>$indexes];
    if($bad&&$kind==='missing'){continue;}
    $columns='id '.$int.' NOT NULL'.($bad&&$kind==='primary'?'':' PRIMARY KEY').',value '.($bad&&$kind==='type'?($mysql?'INT UNSIGNED':'TEXT'):$int).($bad&&$kind==='nullable'?'':' NOT NULL');
    if($bad&&$kind==='extra'){$columns.=',extra INTEGER NOT NULL';}
    if($bad&&$kind==='many-columns'){for($i=0;$i<63;++$i){$columns.=',extra_'.$i.' INTEGER NOT NULL DEFAULT 0';}}
    if($bad&&in_array($kind,['foreign-out','foreign-disabled'],true)){$columns.=',FOREIGN KEY(id) REFERENCES pair_parent(id)';}
    $pdo->exec('CREATE TABLE '.$table.'('.$columns.')'.($mysql?' ENGINE='.($bad&&$kind==='engine'?'MyISAM':'InnoDB'):''));
    foreach($indexes as $name=>$definition){$pdo->exec('CREATE INDEX '.$name.' ON '.$table.'('.implode(',',$definition['columns']).')');}
    if($mode==='extra-index'){$pdo->exec('CREATE INDEX pair_'.$side.'_extra ON '.$table.'(value)');}
    if($bad&&$kind==='unique'){$pdo->exec('CREATE UNIQUE INDEX pair_'.$side.'_unexpected ON '.$table.'(value)');}
    if(($bad&&$kind==='trigger')||$mode==='scope-hidden-'.$side){$pdo->exec('CREATE TRIGGER pair_trigger_'.$side.' AFTER INSERT ON '.$table.($mysql?' FOR EACH ROW INSERT INTO pair_effects VALUES(9)':' BEGIN INSERT INTO pair_effects VALUES(9); END'));}
    if($bad&&$kind==='shadow'){$pdo->exec('CREATE TEMPORARY TABLE '.$table.'(id '.$int.' NOT NULL PRIMARY KEY,value '.$int.' NOT NULL) ENGINE=InnoDB');$shadowTable=$table;}
    if($bad&&$kind==='foreign-in'){$pdo->exec('CREATE TABLE pair_child(id '.$int.' NOT NULL,FOREIGN KEY(id) REFERENCES '.$table.'(id))'.$suffix);}
   }
   if($mode==='reverse'){$spec=array_reverse($spec,true);}
   if($kind==='foreign-disabled'&&$mysql){$pdo->exec('SET FOREIGN_KEY_CHECKS=0');}
   $connection=$pdo;
   if(strpos($mode,'scope-')===0){
    $control("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sosecurity_reader'@'localhost'");$control("GRANT SELECT,INSERT,UPDATE,DELETE ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");
    foreach(['first','second'] as $side){if($mode==='scope-both'||$mode==='scope-'.$side||$mode==='scope-hidden-'.($side==='first'?'second':'first')){$control("GRANT TRIGGER ON sosecurity_test.sosecurity_pair_".$side." TO 'sosecurity_reader'@'localhost'");}}
    $reader=new InboxTestConnection($dsn,'sosecurity_reader','integration-read-only',$options);$reader->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$reader]]);$reader->beforeStatement=$pdo->beforeStatement;$connection=$reader;
   }
   $unit=new SqlTransaction($connection,new TestClock(),10000);$calls=0;$error=null;$metadata=0;
   try{$unit->run(static function()use($unit,$spec,&$calls):void{SqlSchema::tables($unit,$spec);++$calls;$unit->query('INSERT INTO sosecurity_pair_first VALUES(1,7)')->closeCursor();$unit->query('INSERT INTO sosecurity_pair_second VALUES(1,7)')->closeCursor();$unit->query('INSERT INTO pair_effects VALUES(1)')->closeCursor();});}catch(ConfigurationException|SoSecurity\Exception\SecurityException $caught){$error=$caught;}
   $valid=in_array($mode,['valid','reverse','multi-index','extra-index','scope-both'],true);
   Check::same(!$valid,$error!==null);Check::same($valid?1:0,$calls);Check::same($valid?'1':'0',(string)$pdo->query('SELECT COUNT(*) FROM pair_effects')->fetchColumn());Check::same(false,$connection->inTransaction());Check::same($valid,$unit->committed());
   if(!$valid&&$kind!=='missing'){Check::same($kind==='shadow'?'sql.unavailable':'configuration.sql_schema',$error->reason());}
   if($valid&&$mysql){Check::same($mode==='multi-index'?2:1,$metadata);}
   if($mode==='valid'&&$mysql){echo 'TABLE_RESOLUTION_READS '.$resolutions.PHP_EOL;Check::same(1,$resolutions);}
   echo 'CASE SQL pair '.$mode.' PASS'.PHP_EOL;
  }finally{
   $reader=null;$pdo->beforeStatement=null;if($shadowTable!==null){$pdo->exec('DROP TEMPORARY TABLE '.$shadowTable);}
   foreach(['pair_child','sosecurity_pair_first','sosecurity_pair_second','pair_parent','pair_effects'] as $table){$pdo->exec('DROP TABLE IF EXISTS '.$table);}
   if($mysql){$pdo->exec('SET FOREIGN_KEY_CHECKS=1');}
  }
 }
 $unit=SqlTransaction::forObservation($pdo,new TestClock(),10000);$good=['types'=>['id'=>'int'],'primary'=>['id'],'indexes'=>[]];$badShapes=[[],['sosecurity_pair_first'=>$good,'sosecurity_pair_second'=>$good,'sosecurity_pair_third'=>$good],['bad name'=>$good],['sosecurity_pair_first'=>['types'=>[],'primary'=>['id'],'indexes'=>[]]],['sosecurity_pair_first'=>['types'=>['id'=>'int'],'primary'=>[],'indexes'=>[]]],['sosecurity_pair_first'=>['types'=>['id'=>'int'],'primary'=>['id'],'indexes'=>array_fill(0,17,[])]]];
 foreach($badShapes as $shape){$unit->run(static function()use($unit,$pdo,$shape):void{$before=$pdo->queries;Check::throws(ConfigurationException::class,static function()use($unit,$shape):void{SqlSchema::tables($unit,$shape);});Check::same($before,$pdo->queries);});}
}finally{$reader=null;$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS bounded private table pair '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
