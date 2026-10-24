<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\ConfigurationException;
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required');}
$directory=privateDirectory();$pdo=null;$created=[];
try{
 $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/schema.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
 $definitions=['query_a'=>['unique'=>false,'columns'=>['a','id']],'query_b'=>['unique'=>true,'columns'=>['b']],'query_c'=>['unique'=>false,'columns'=>['id','a']],'query_d'=>['unique'=>false,'columns'=>['a','b']],'query_e'=>['unique'=>true,'columns'=>['a']],'query_f'=>['unique'=>false,'columns'=>['b','a']]];
 $modes=($argv[2]??'')==='ledger-only'?[]:['extra-unique','valid','extra-nonunique','many-nonunique','many-and-unique','missing-and-extra','implicit-unique','redundant-primary','expression-unique','partial-unique'];
 foreach($modes as $mode){
  if($mysql&&$mode==='partial-unique'){continue;}
  $integer=$mysql?'BIGINT UNSIGNED':'INTEGER';
  $pdo->exec('CREATE TABLE sosecurity_unique_probe(id '.$integer.' NOT NULL PRIMARY KEY,a '.$integer.' NOT NULL,b '.($mysql?'VARBINARY(32)':'TEXT').' NOT NULL'.($mode==='implicit-unique'?',UNIQUE(id,a)':'').')'.($mysql?' ENGINE=InnoDB':''));$created[]='sosecurity_unique_probe';
  foreach($definitions as $name=>$definition){if($mode==='missing-and-extra'&&$name==='query_e'){continue;}$pdo->exec('CREATE '.($definition['unique']?'UNIQUE ':'').'INDEX '.$name.' ON sosecurity_unique_probe('.implode(',',$definition['columns']).')');}
  if(in_array($mode,['extra-unique','many-and-unique','missing-and-extra'],true)){$pdo->exec('CREATE UNIQUE INDEX zz_owned_unexpected ON sosecurity_unique_probe(a,b)');}
  if($mode==='expression-unique'){$pdo->exec('CREATE UNIQUE INDEX zz_owned_expression ON sosecurity_unique_probe((a+id))');}
  if($mode==='partial-unique'){$pdo->exec('CREATE UNIQUE INDEX zz_owned_partial ON sosecurity_unique_probe(id,a) WHERE a>0');}
  if($mode==='redundant-primary'){$pdo->exec('CREATE UNIQUE INDEX zz_owned_redundant ON sosecurity_unique_probe(id)');}
  if(in_array($mode,['many-nonunique','many-and-unique','extra-nonunique'],true)){$count=$mode==='extra-nonunique'?1:30;for($i=0;$i<$count;++$i){$pdo->exec('CREATE INDEX owned_extra_'.$i.' ON sosecurity_unique_probe(b)');}}
  $unit=SqlTransaction::forObservation($pdo,new TestClock(),10000);$effectCalls=0;
  $run=static function()use($unit,$definitions,&$effectCalls):void{$unit->run(static function()use($unit,$definitions,&$effectCalls):void{SqlSchema::table($unit,'sosecurity_unique_probe',['id'=>'int','a'=>'int','b'=>'bytes:32'],['id'],$definitions);++$effectCalls;});};
  if(in_array($mode,['valid','extra-nonunique','many-nonunique'],true)){$run();Check::same(1,$effectCalls);}
  else{$error=null;try{$run();}catch(ConfigurationException $caught){$error=$caught;}echo 'UNIQUE_CONTRACT '.json_encode(['mode'=>$mode,'rejected'=>$error!==null,'effect_calls'=>$effectCalls]).PHP_EOL;Check::same(true,$error instanceof ConfigurationException);Check::same('configuration.sql_schema',$error->reason());Check::same(0,$effectCalls);}
  $pdo->exec('DROP TABLE sosecurity_unique_probe');array_pop($created);
 }
 // A reused real ledger must also reject a newly added cross-namespace uniqueness restriction.
 $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-'.($mysql?'mysql':'sqlite').'.sql'));
 foreach(explode(';',$ddl) as $statement){if(trim($statement)===''){continue;}$pdo->exec($statement);if(preg_match('/CREATE TABLE\s+(\w+)/i',$statement,$match)){$created[]=$match[1];}}
 if($mysql){SoSecurity\Support\SqlStateAccess::bind($pdo,hash('sha256','owned-unique-context'),hash('sha256','owned-unique-binding'),static function():void{});}
 $unit=new SqlTransaction($pdo,new TestClock(),10000);$ledger=new SoSecurity\Account\Ledger($unit,'owned-unique-ledger','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('k',32)]),new SoSecurity\Account\Policy());
 $unit->run(static function()use($ledger):void{Check::same(true,$ledger->initialize());});
 $before=$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn();
 $pdo->exec('CREATE UNIQUE INDEX owned_epoch_restriction ON sosecurity_account_roots(epoch)');
 Check::throws(ConfigurationException::class,static function()use($unit,$ledger):void{$unit->run(static function()use($ledger):void{$ledger->checkpoint();});});Check::same($before,$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn());
 if(!$mysql){
  $pdo->exec('DROP INDEX owned_epoch_restriction');
  Check::throws(ConfigurationException::class,static function()use($unit,$ledger,$pdo):void{$unit->run(static function()use($unit,$ledger,$pdo):void{$ledger->checkpoint();$unit->invoke(static function()use($pdo):bool{$pdo->exec('CREATE UNIQUE INDEX owned_callback_unique ON sosecurity_account_records(owner)');return true;},[],'owned.callback');$ledger->checkpoint();});});
  Check::same('0',(string)$pdo->query("SELECT COUNT(*) FROM main.pragma_index_list('sosecurity_account_records') WHERE name='owned_callback_unique'")->fetchColumn());
 }
}finally{if($mysql&&$pdo!==null){foreach(array_reverse($created) as $table){$pdo->exec('DROP TABLE '.$table);}}$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS private unexpected unique restrictions '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
