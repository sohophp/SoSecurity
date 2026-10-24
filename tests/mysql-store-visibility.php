<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
// Only mysql_check.py's disposable server and synthetic account are modified.
// The controller uses the installed MySQL client; old PHP clients do not support root's
// caching_sha2_password. Product calls below still use each selected PHP's real PDO driver.
$control=static function(string $sql)use($socket):void{
    $process=proc_open('mysql --no-defaults --protocol=SOCKET --socket='.escapeshellarg($socket).' --user=root --database=sosecurity_test --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($process)){throw new RuntimeException('Owned controller unavailable');}
    $input=$sql.';'.PHP_EOL;$written=fwrite($pipes[0],$input);fclose($pipes[0]);
    stream_get_contents($pipes[1],8192);fclose($pipes[1]);stream_get_contents($pipes[2],8192);fclose($pipes[2]);$exit=proc_close($process);
    if($written!==strlen($input)||$exit!==0){throw new RuntimeException('Owned controller command failed');}
};
foreach(['missing','missing-clean','prune-revoked','schema','table','global','revoked','trigger','global-restricted','role-only','schema-race','table-race'] as $mode){
 $control("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sosecurity_reader'@'localhost'");
 $control("GRANT SELECT,INSERT,UPDATE,DELETE ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");
 $admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$reader=null;
 try{
  $admin->exec(SoSecurity\Storage\MySqlStore::schema());
  $admin->exec('CREATE TABLE store_visibility_effects(value INTEGER NOT NULL) ENGINE=InnoDB');
  if(in_array($mode,['schema','revoked','prune-revoked','trigger','schema-race'],true)){$control("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");}
  elseif(in_array($mode,['table','table-race'],true)){$control("GRANT TRIGGER ON sosecurity_test.sosecurity_state TO 'sosecurity_reader'@'localhost'");}
  elseif(in_array($mode,['global','global-restricted'],true)){$control("GRANT TRIGGER ON *.* TO 'sosecurity_reader'@'localhost'");if($mode==='global-restricted'){$control('SET GLOBAL partial_revokes=ON');}}
  elseif($mode==='role-only'){$control("CREATE ROLE 'owned_store_role'");$control("GRANT TRIGGER ON sosecurity_test.* TO 'owned_store_role'");$control("GRANT 'owned_store_role' TO 'sosecurity_reader'@'localhost'");}
  $trigger=static function()use($admin):void{$admin->exec('CREATE TRIGGER owned_store_trigger AFTER INSERT ON sosecurity_state FOR EACH ROW INSERT INTO store_visibility_effects VALUES(1)');};
  if(in_array($mode,['missing','trigger'],true)){$trigger();}
  $reader=new InboxTestConnection($dsn,'sosecurity_reader','integration-read-only',$options);$reader->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$reader]]);
  if($mode==='role-only'){$reader->exec('SET ROLE ALL');}
  $called=0;$rejected=false;$revoked=false;
  try{
   $store=new SoSecurity\Storage\MySqlStore($reader,'visibility-test',new TestClock());
   if(in_array($mode,['revoked','schema-race','table-race'],true)){$trigger();}
   if($mode==='prune-revoked'){$store->transact('expired',static function(){return new SoSecurity\Storage\Change(['retained'=>true],1,null);});$admin->exec('CREATE TRIGGER owned_store_delete AFTER DELETE ON sosecurity_state FOR EACH ROW INSERT INTO store_visibility_effects VALUES(1)');}
   if(in_array($mode,['revoked','prune-revoked'],true)){$control("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");}
   if(in_array($mode,['schema-race','table-race'],true)){$reader->afterStatement=static function(string $sql)use($control,$mode,&$revoked):void{if(!$revoked&&strpos($sql,'information_schema.SCHEMA_PRIVILEGES')!==false){$revoked=true;$control("REVOKE TRIGGER ON sosecurity_test.".($mode==='table-race'?'sosecurity_state':'*')." FROM 'sosecurity_reader'@'localhost'");}};}
   if($mode==='prune-revoked'){$store->prune(1);}else{$store->transact('key',static function()use(&$called){++$called;return new SoSecurity\Storage\Change(['value'=>1],2000000000,true);});}
  }catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.schema',$error->reason());$rejected=true;}
  $blocked=!in_array($mode,['schema','table','global'],true);$effects=(int)$admin->query('SELECT COUNT(*) FROM store_visibility_effects')->fetchColumn();
  if($blocked&&!$rejected){echo 'UNEXPECTED_ACCEPT '.json_encode(['mode'=>$mode,'effects'=>$effects,'callbacks'=>$called]).PHP_EOL;}
  Check::same($blocked,$rejected);Check::same($blocked?0:1,$called);Check::same(0,$effects);
  Check::same($mode==='prune-revoked'?1:($blocked?0:1),(int)$admin->query('SELECT COUNT(*) FROM sosecurity_state')->fetchColumn());Check::same(false,$reader->inTransaction());
  if(in_array($mode,['schema-race','table-race'],true)){Check::same(true,$revoked);}
  echo 'CASE store visibility '.$mode.' PASS'.PHP_EOL;
 }finally{$reader=null;$admin->exec('DROP TABLE IF EXISTS sosecurity_state');$admin->exec('DROP TABLE IF EXISTS store_visibility_effects');$admin=null;if($mode==='global-restricted'){$control('SET GLOBAL partial_revokes=OFF');}if($mode==='role-only'){$control("DROP ROLE 'owned_store_role'");}}
}
echo 'PASS MySqlStore metadata visibility '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
