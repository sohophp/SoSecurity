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
$targets=isset($argv[1])&&in_array($argv[1],['store','webhook'],true)?[$argv[1]]:['store','webhook'];
foreach($targets as $target){
 $control("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sosecurity_reader'@'localhost'");
 $control("GRANT SELECT,INSERT,UPDATE,DELETE ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");
 $control("GRANT TRIGGER ON *.* TO 'sosecurity_reader'@'localhost'");
 $e=new InboxEnvironment(true);$reader=null;
 try{
  $e->pdo->exec(SoSecurity\Storage\MySqlStore::schema());$e->pdo->exec('CREATE TABLE owned_global_effects(value INTEGER NOT NULL) ENGINE=InnoDB');
  $table=$target==='store'?'sosecurity_state':'sosecurity_webhook_inbox';
  $e->pdo->exec('CREATE TRIGGER owned_global_trigger AFTER INSERT ON '.$table.' FOR EACH ROW INSERT INTO owned_global_effects VALUES(1)');
  $reader=new InboxTestConnection($dsn,'sosecurity_reader','integration-read-only',$options);$reader->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$reader]]);$changes=0;
  $reader->beforeStatement=static function(string $sql)use($control):void{if(strpos($sql,'information_schema.SCHEMA_PRIVILEGES')!==false){$control('SET GLOBAL partial_revokes=ON');$control("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");}};
  $reader->afterStatement=static function(string $sql)use($control,&$changes):void{if(strpos($sql,'information_schema.SCHEMA_PRIVILEGES')!==false){++$changes;$control("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");$control('SET GLOBAL partial_revokes=OFF');}};
  $rejected=false;$calls=0;
  try{
   if($target==='store'){$store=new SoSecurity\Storage\MySqlStore($reader,'owned-global',$e->clock);$store->transact('owned',static function()use(&$calls){++$calls;return new SoSecurity\Storage\Change(['owned'=>true],2000000000,true);});}
   else{$service=new SoSecurity\Webhook\SqlInbox($reader,'inbox-test-site',$e->verifier,$e->seals,static function():bool{return true;},$e->clock);$service->accept($e->request(),$e->mapper());}
  }catch(SoSecurity\Exception\ConfigurationException $error){Check::same($target==='store'?'configuration.schema':'configuration.webhook_inbox_schema',$error->reason());$rejected=true;}
  $effects=(int)$e->pdo->query('SELECT COUNT(*) FROM owned_global_effects')->fetchColumn();
  echo 'GLOBAL_RACE '.json_encode(['target'=>$target,'rejected'=>$rejected,'effects'=>$effects,'callbacks'=>$calls,'changes'=>$changes]).PHP_EOL;
  Check::same(true,$rejected);Check::same(0,$effects);Check::same(0,$calls);Check::same(true,$changes>0);Check::same(false,$reader->inTransaction());Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM '.$table)->fetchColumn());
 }finally{$reader=null;$control("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");$control('SET GLOBAL partial_revokes=OFF');$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_state');$e->pdo->exec('DROP TABLE IF EXISTS owned_global_effects');$e->close();}
}
echo 'PASS global visibility observation '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
