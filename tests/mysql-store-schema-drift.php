<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$mode=$argv[1]??'engine';$operation=$argv[2]??'transact';
try{
 $pdo->exec(SoSecurity\Storage\MySqlStore::schema());$store=new SoSecurity\Storage\MySqlStore($pdo,'owned-schema',new TestClock());
 $store->transact('owned-key',static function(){return new SoSecurity\Storage\Change(['owned'=>true],99999,null);});
 if($mode==='engine'){$pdo->exec('ALTER TABLE sosecurity_state ENGINE=MyISAM');}
 elseif($mode==='payload'){$pdo->exec('ALTER TABLE sosecurity_state MODIFY payload TEXT NULL');}
 elseif($mode==='expiry'){$pdo->exec('ALTER TABLE sosecurity_state MODIFY expires_at BIGINT NOT NULL DEFAULT 0');}
 elseif($mode==='extra'){$pdo->exec('ALTER TABLE sosecurity_state ADD unexpected VARCHAR(16) NULL');}
 elseif(in_array($mode,['trigger_insert','trigger_update','trigger_delete'],true)){$event=strtoupper(substr($mode,8));$pdo->exec('CREATE TRIGGER owned_store_trigger BEFORE '.$event.' ON sosecurity_state FOR EACH ROW SET @owned_trigger_ran=1');}
 elseif($mode!=='canonical'){throw new RuntimeException('Unknown test mode');}
 $rows=static function()use($pdo):array{return $pdo->query('SELECT * FROM sosecurity_state ORDER BY namespace_hash,state_key')->fetchAll(PDO::FETCH_ASSOC);};$before=$rows();$called=false;$rejected=false;
 try{if($operation==='construct'){new SoSecurity\Storage\MySqlStore($pdo,'owned-schema',new TestClock());}elseif($operation==='prune'){$store->prune(1);}else{$store->transact('owned-new-key',static function()use(&$called){$called=true;return new SoSecurity\Storage\Change(['new'=>true],200000,null);});}}catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.schema',$error->reason());$rejected=true;}
 echo 'SCHEMA_DRIFT '.json_encode(['mode'=>$mode,'operation'=>$operation,'rejected'=>$rejected,'callback'=>$called,'unchanged'=>$before===$rows()]).PHP_EOL;
 Check::same($mode!=='canonical',$rejected);Check::same(false,$pdo->inTransaction());
 if($mode!=='canonical'){Check::same(false,$called);Check::same($before,$rows());if(strpos($mode,'trigger_')===0){Check::same(null,$pdo->query('SELECT @owned_trigger_ran')->fetchColumn());}}
 echo 'PASS store schema drift '.$mode.' '.$operation.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{if($pdo->inTransaction()){$pdo->rollBack();}$pdo->exec('DROP TABLE IF EXISTS sosecurity_state');}
