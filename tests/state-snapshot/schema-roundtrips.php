<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$mysql=($argv[1]??'sqlite')==='mysql';$observe=($argv[2]??'')==='observe';$backend=$mysql?'mysql':'sqlite';$observed=[];
snapshotCase($mysql,static function(InboxTestConnection $pdo)use($mysql,$observe,$backend,&$observed):void{
 $s=snapshotSource($pdo);$capture=static function(string $name)use($pdo,$s,&$observed):void{$before=$pdo->queries;$digest=$s->digest();$observed[$name]=['digest'=>$digest,'statements'=>$pdo->queries-$before];};
 $capture('empty');snapshotInsert($pdo,'tenant',1,"a\0b",null,'owned');snapshotInsert($pdo,'tenant',2,'second','private-test-value','tag');$capture('records');
 if(!$mysql){
  $pdo->exec('CREATE INDEX owned_snapshot_index ON snapshot_test(tag)');$capture('index');
  $pdo->exec('CREATE TRIGGER owned_snapshot_trigger AFTER UPDATE ON snapshot_test BEGIN SELECT 1; END');$capture('trigger');
  $pdo->exec('CREATE TEMP TRIGGER owned_snapshot_temp_trigger AFTER UPDATE ON main.snapshot_test BEGIN SELECT 2; END');$capture('temp_trigger');
 }
 if(!$observe){
  $baseline=json_decode(file_get_contents(__DIR__.'/schema-roundtrips-baseline.json'),true)[$backend];
  foreach($observed as $name=>$result){Check::same($baseline[$name]['digest'],$result['digest']);Check::same(true,$result['statements']<$baseline[$name]['statements']);}
  if(!$mysql){
   foreach(['main','temp'] as $scope){$pdo->exec('CREATE TABLE '.$scope.'.pragma_table_info(v TEXT)');try{snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});}finally{$pdo->exec('DROP TABLE '.$scope.'.pragma_table_info');}}
  }
  if(!$mysql){
   $changed=false;$pdo->afterStatement=static function(string $sql)use($pdo,&$changed):void{if(!$changed&&strpos($sql,'__sw_valid')!==false){$changed=true;$pdo->exec('CREATE INDEX owned_mid_read_index ON snapshot_test(id)');}};
   try{snapshotReason('account.snapshot_changed',static function()use($s):void{$s->digest();});}finally{$pdo->afterStatement=null;}
   Check::same(true,$changed);
   $pdo->exec('DROP INDEX IF EXISTS owned_mid_read_index');
   for($i=0;$i<123;++$i){$pdo->exec('CREATE '.($i%2?'TEMP ':'').'TRIGGER owned_limit_'.$i.' AFTER UPDATE ON '.($i%2?'main.':'').'snapshot_test BEGIN SELECT 1; END');}
   Check::same(64,strlen($s->digest()));
   $pdo->exec('CREATE TEMP TRIGGER owned_limit_extra AFTER UPDATE ON main.snapshot_test BEGIN SELECT 1; END');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});
  }else{
   $pdo->exec('ALTER TABLE snapshot_test ENGINE=MyISAM');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});
  }
  $pdo->exec('DROP TABLE snapshot_test');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});
  $pdo->exec('CREATE VIEW snapshot_test AS SELECT 1 AS id');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});$pdo->exec('DROP VIEW snapshot_test');
 }
});
echo 'SCHEMA_OBSERVATION '.json_encode([$backend=>$observed]).PHP_EOL;
echo 'PASS bounded schema queries '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
