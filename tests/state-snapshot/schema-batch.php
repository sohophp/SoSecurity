<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$mysql=($argv[1]??'sqlite')==='mysql';$observe=($argv[2]??'')==='observe';$backend=$mysql?'mysql':'sqlite';$results=[];
snapshotCase($mysql,static function(InboxTestConnection $pdo)use($mysql,$observe,$backend,&$results):void{
 $owned=[];$definition=snapshotSpec()['snapshot_test'];$definitions=['snapshot_test'=>$definition];
 try{
  foreach(['snapshot_b','snapshot_c','snapshot_d','snapshot_e'] as $table){
   $pdo->exec($mysql?'CREATE TABLE '.$table.' LIKE snapshot_test':'CREATE TABLE '.$table.'(scope TEXT NOT NULL,id INTEGER NOT NULL,body BLOB NOT NULL,password TEXT NULL,tag TEXT NOT NULL,PRIMARY KEY(scope,id))');$owned[]=$table;$definitions[$table]=$definition;
  }
  $s=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-schema-group',$definitions,30000);
  $capture=static function(string $name)use($pdo,$s,&$results):void{$start=$pdo->queries;$digest=$s->digest();$results[$name]=['digest'=>$digest,'calls'=>$pdo->queries-$start];};
  $capture('empty');snapshotInsert($pdo,'tenant',1,'owned');$capture('first');
  $pdo->exec("INSERT INTO snapshot_e(scope,id,body,password,tag) VALUES('tenant',1,".($mysql?"_binary 'last'":"CAST('last' AS BLOB)").",NULL,'last')");$capture('last');
  if(!$observe){
   $baseline=json_decode(file_get_contents(__DIR__.'/schema-batch-baseline.json'),true)[$backend];
   foreach($results as $name=>$result){Check::same($baseline[$name]['digest'],$result['digest']);Check::same(true,$mysql?$result['calls']<$baseline[$name]['calls']:$result['calls']===$baseline[$name]['calls']);}
   Check::same(false,$results['empty']['digest']===$results['first']['digest']);Check::same(false,$results['first']['digest']===$results['last']['digest']);
   $pdo->exec('ALTER TABLE snapshot_e ADD COLUMN unexpected '.($mysql?'BIGINT':'INTEGER').' NULL');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});
  }
 }finally{foreach(array_reverse($owned) as $table){$pdo->exec('DROP TABLE '.$table);}}
});
echo 'BATCH_OBSERVATION '.json_encode([$backend=>$results]).PHP_EOL;echo 'PASS bounded schema groups '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
