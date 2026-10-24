<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$phase=$argv[1];$mode=$argv[2];
if($phase==='prepare'){
 $pdo->exec('DROP TABLE IF EXISTS sosecurity_state');$sql=SoSecurity\Storage\MySqlStore::schema();
 if($mode==='large-extra-defaults'){$extra='';for($i=0;$i<64;++$i){$extra.='extra_'.$i.' MEDIUMTEXT NULL DEFAULT (\''.str_repeat('x',60000).'\'),';}$sql=str_replace('PRIMARY KEY',$extra.'PRIMARY KEY',$sql);}
 elseif($mode==='wrong-type'){$sql=str_replace('MEDIUMTEXT','TEXT',$sql);}
 $pdo->exec($sql);echo 'PREPARED owned metadata '.$mode.PHP_EOL;return;
}
try{
 $rejected=false;try{$store=new SoSecurity\Storage\MySqlStore($pdo,'owned-metadata',new TestClock());}catch(SoSecurity\Exception\ConfigurationException $error){$rejected=true;}
 Check::same($mode!=='canonical',$rejected);
 if(!$rejected){$store->transact('owned-key',static function($value){Check::same(null,$value);return new SoSecurity\Storage\Change(['owned'=>true],200000,null);});$seen=$store->transact('owned-key',static function($value){return new SoSecurity\Storage\Change($value,200000,$value);});Check::same(['owned'=>true],$seen);}
 echo 'PASS bounded store metadata '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{$pdo->exec('DROP TABLE sosecurity_state');}
