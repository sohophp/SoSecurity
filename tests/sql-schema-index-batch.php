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
 $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);$count=0;$pdo->beforeStatement=static function(string $sql)use(&$count):void{if(strpos($sql,'information_schema.STATISTICS')!==false){++$count;}};
 $definitions=['query_a'=>['unique'=>false,'columns'=>['a','id']],'query_b'=>['unique'=>true,'columns'=>['b']],'query_c'=>['unique'=>false,'columns'=>['id','a']],'query_d'=>['unique'=>false,'columns'=>['c','b']],'query_e'=>['unique'=>false,'columns'=>['a','c']]];
 foreach(['valid','uppercase','missing','wrong-order','wrong-unique','prefix','missing-primary','extra-index'] as $mode){
  if(!$mysql&&in_array($mode,['prefix','missing-primary','uppercase'],true)){continue;}
  $pdo->exec('DROP TABLE IF EXISTS sosecurity_index_probe');$integer=$mysql?'BIGINT UNSIGNED':'INTEGER';
  $pdo->exec('CREATE TABLE sosecurity_index_probe(id '.$integer.' NOT NULL PRIMARY KEY,a '.$integer.' NOT NULL,b '.($mysql?'VARBINARY(32)':'TEXT').' NOT NULL,c '.$integer.' NOT NULL)'.($mysql?' ENGINE=InnoDB':''));
  foreach($definitions as $name=>$definition){
   if($mode==='missing'&&$name==='query_e'){continue;}$columns=$definition['columns'];$unique=$definition['unique'];
   if($name==='query_b'){if($mode==='wrong-unique'){$unique=false;}if($mode==='prefix'){$columns=['b(8)'];}}
   if($mode==='wrong-order'&&$name==='query_d'){$columns=array_reverse($columns);}
   $pdo->exec('CREATE '.($unique?'UNIQUE ':'').'INDEX '.($mode==='uppercase'?strtoupper($name):$name).' ON sosecurity_index_probe('.implode(',',$columns).')');
  }
  if($mode==='missing-primary'){$pdo->exec('ALTER TABLE sosecurity_index_probe DROP PRIMARY KEY');}
  if($mode==='extra-index'){$pdo->exec('CREATE INDEX owned_extra ON sosecurity_index_probe(c)');}
  $unit=SqlTransaction::forObservation($pdo,new TestClock(),10000);$count=0;$run=static function()use($unit,$definitions):void{$unit->run(static function()use($unit,$definitions):void{SqlSchema::table($unit,'sosecurity_index_probe',['id'=>'int','a'=>'int','b'=>'bytes:32','c'=>'int'],['id'],$definitions);});};
  if(in_array($mode,['valid','uppercase','extra-index'],true)){$run();if($mysql){echo 'INDEX_QUERIES '.$mode.' '.$count.PHP_EOL;Check::same(2,$count);}}
  else{Check::throws(ConfigurationException::class,$run);}
 }
}finally{if($pdo!==null&&$mysql){$pdo->exec('DROP TABLE IF EXISTS sosecurity_index_probe');}$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS bounded ledger index batches '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
