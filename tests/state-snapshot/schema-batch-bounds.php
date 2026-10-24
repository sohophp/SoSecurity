<?php
declare(strict_types=1);
require __DIR__.'/support.php';$mysql=($argv[1]??'sqlite')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo)use($mysql):void{
 $owned=[];$columns=['id'=>'int'];for($i=0;$i<63;++$i){$columns['c'.$i]='int';}$spec=['columns'=>$columns,'primary'=>['id'],'where'=>[],'maximum_rows'=>2];$definitions=[];
 try{
  foreach(range(0,3) as $i){$table='owned_wide_'.$i;$parts=[];foreach($columns as $name=>$type){$parts[]=$name.($mysql?' BIGINT UNSIGNED NOT NULL':' INTEGER NOT NULL');}$parts[]='PRIMARY KEY(id)';$pdo->exec('CREATE TABLE '.$table.'('.implode(',',$parts).')'.($mysql?' ENGINE=InnoDB':''));$owned[]=$table;$definitions[$table]=$spec;}
  $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-wide-schema',$definitions,30000);Check::same(64,strlen($source->digest()));Check::same('8M',ini_get('memory_limit'));Check::same(true,memory_get_peak_usage(true)<=8388608);
  $tooMany=[];for($i=0;$i<33;++$i){$tooMany['owned_extra_'.$i]=$spec;}$before=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$tooMany):void{new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-invalid-schema',$tooMany);});Check::same($before,$pdo->queries);
  $changed=false;$pdo->afterStatement=static function(string $sql)use($pdo,&$changed,$mysql):void{if(!$changed&&strpos($sql,'__sw_valid')!==false){$changed=true;$pdo->exec('ALTER TABLE owned_wide_3 ADD COLUMN unexpected '.($mysql?'BIGINT':'INTEGER').' NULL');}};
  try{snapshotReason($mysql?'sql.cleanup':'account.snapshot_corrupt',static function()use($source):void{$source->digest();});}finally{$pdo->afterStatement=null;}
  Check::same(true,$changed);
 }finally{foreach(array_reverse($owned) as $table){$pdo->exec('DROP TABLE '.$table);}}
});
echo 'PASS bounded schema batch memory and mutation '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
