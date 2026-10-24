<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$pdo=null;$base=[];$temporary=[];$cases=0;
$deny=static function(callable $run):void{
 $caught=null;try{$run();}catch(SoSecurity\Exception\SecurityException $error){$caught=$error;}
 Check::same(true,$caught instanceof SoSecurity\Exception\SecurityException);Check::same(null,$caught->getPrevious());
 Check::same(true,in_array($caught->reason(),['storage.schema','storage.database','sql.unavailable'],true));
};
try{
 foreach([false,true] as $emulated){
  $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>$emulated]);
  foreach(['InnoDB','MyISAM'] as $engine){
   foreach(['construct','transact','prune'] as $entry){
    $ddl=str_replace('CREATE TABLE IF NOT EXISTS sosecurity_state','CREATE TABLE sosecurity_state',SoSecurity\Storage\MySqlStore::schema());Check::same(1,substr_count($ddl,'CREATE TABLE sosecurity_state'));$pdo->exec($ddl);$base[]='sosecurity_state';
    $store=new SoSecurity\Storage\MySqlStore($pdo,'owned-resolved',new TestClock());$store->transact('owned-base',static function(){return new SoSecurity\Storage\Change(['base'=>true],0,null);});
    $pdo->exec(str_replace(['CREATE TABLE sosecurity_state','ENGINE=InnoDB'],['CREATE TEMPORARY TABLE sosecurity_state','ENGINE='.$engine],$ddl));$temporary[]='sosecurity_state';$called=0;
    $deny(static function()use($entry,$pdo,$store,&$called):void{
     if($entry==='construct'){new SoSecurity\Storage\MySqlStore($pdo,'owned-resolved',new TestClock());}
     elseif($entry==='prune'){$store->prune();}
     else{$store->transact('owned-marker',static function()use(&$called){++$called;return new SoSecurity\Storage\Change(['owned_marker'=>true],0,null);});}
    });
    Check::same(0,$called);Check::same(false,$pdo->inTransaction());Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_state')->fetchColumn());
    $pdo->exec('DROP TEMPORARY TABLE sosecurity_state');array_pop($temporary);Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_state')->fetchColumn());
    Check::same(['base'=>true],$store->transact('owned-base',static function($value){return new SoSecurity\Storage\Change($value,0,$value);}));
    $pdo->exec('DROP TABLE sosecurity_state');array_pop($base);++$cases;
   }
   if($emulated){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo):void{SoSecurity\Support\SqlTransaction::forObservation($pdo,new TestClock(),10000);});continue;}
   foreach(['single','pair-first','pair-second','snapshot'] as $entry){
    $definitions=[];
    foreach(['first','second'] as $side){$table='sosecurity_resolved_'.$side;$pdo->exec('CREATE TABLE '.$table.'(id BIGINT UNSIGNED NOT NULL PRIMARY KEY,value VARBINARY(32) NOT NULL) ENGINE=InnoDB');$base[]=$table;$pdo->exec("INSERT INTO ".$table." VALUES(1,'base')");$definitions[$table]=['types'=>['id'=>'int','value'=>'bytes:32'],'primary'=>['id'],'indexes'=>[]];}
    $target=$entry==='pair-second'?'sosecurity_resolved_second':'sosecurity_resolved_first';$pdo->exec('CREATE TEMPORARY TABLE '.$target.'(id BIGINT UNSIGNED NOT NULL PRIMARY KEY,value VARBINARY(32) NOT NULL) ENGINE='.$engine);$temporary[]=$target;$pdo->exec("INSERT INTO ".$target." VALUES(1,'temporary')");$called=0;
    if($entry==='snapshot'){
     $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-resolved-source',[$target=>['columns'=>['id'=>'int','value'=>'bytes:32'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);
     $deny(static function()use($source,&$called):void{$source->capture(['owned'=>['table'=>'sosecurity_resolved_first','key'=>['id'=>1],'columns'=>['value']]]);++$called;});
    }else{
     $unit=SoSecurity\Support\SqlTransaction::forObservation($pdo,new TestClock(),10000);
     $deny(static function()use($unit,$entry,$definitions,&$called):void{$unit->run(static function()use($unit,$entry,$definitions,&$called):void{if($entry==='single'){SoSecurity\Support\SqlSchema::table($unit,'sosecurity_resolved_first',['id'=>'int','value'=>'bytes:32'],['id']);}else{SoSecurity\Support\SqlSchema::tables($unit,$definitions);}++$called;});});
    }
    Check::same(0,$called);Check::same(false,$pdo->inTransaction());Check::same('temporary',$pdo->query('SELECT value FROM '.$target)->fetchColumn());
    $pdo->exec('DROP TEMPORARY TABLE '.$target);array_pop($temporary);Check::same('base',$pdo->query('SELECT value FROM '.$target)->fetchColumn());
    if($entry==='snapshot'){Check::same(64,strlen($source->digest()));}
    foreach(['second','first'] as $side){$pdo->exec('DROP TABLE sosecurity_resolved_'.$side);array_pop($base);}++$cases;
   }
  }
  $pdo=null;
 }
 $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
 $pdo->exec('CREATE TABLE `order`(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$base[]='order';
 $reserved=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-reserved-source',['order'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>1]],10000);Check::same(64,strlen($reserved->digest()));
 $pdo->exec('DROP TABLE `order`');array_pop($base);
 foreach(['','owned.name','UPPER','owned`table',str_repeat('x',65)] as $invalid){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($invalid):void{SoSecurity\Support\SqlSchema::tableResolution($invalid);});}
}finally{
 if($pdo instanceof PDO){foreach(array_reverse($temporary) as $table){$pdo->exec('DROP TEMPORARY TABLE '.$table);}foreach(array_reverse($base) as $table){$pdo->exec('DROP TABLE `'.$table.'`');}}$pdo=null;
}
echo 'PASS MySQL resolved tables '.Check::$assertions.' PHP '.PHP_VERSION.'; '.$cases.' cases, native/emulated prepares, InnoDB/MyISAM shadows, no callback or persistent writes'.PHP_EOL;
