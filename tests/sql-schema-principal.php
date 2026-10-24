<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required');}
$paired=($argv[1]??'')==='pair';
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
if(PHP_VERSION_ID>=70400){ini_set('zend.exception_ignore_args','0');}
foreach(['owned.schema-7','owned+principal','owned@principal',str_repeat('u',32)] as $user){
 $account="'".$user."'@'localhost'";$control('CREATE USER '.$account." IDENTIFIED WITH mysql_native_password BY 'integration-principal-only'");
 $control('GRANT SELECT,INSERT,UPDATE,DELETE,TRIGGER ON sosecurity_test.* TO '.$account);
 $admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$reader=null;
 try{
  $admin->exec('CREATE TABLE sosecurity_principal_probe(id BIGINT UNSIGNED NOT NULL PRIMARY KEY,value BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB');if($paired){$admin->exec('CREATE TABLE sosecurity_principal_other(id BIGINT UNSIGNED NOT NULL PRIMARY KEY,value BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB');}
  $reader=new PDO($dsn,$user,'integration-principal-only',$options);$unit=new SoSecurity\Support\SqlTransaction($reader,new TestClock(),10000);$called=0;$rejected=false;
  try{$unit->run(static function()use($unit,&$called,$paired):void{if($paired){$spec=['types'=>['id'=>'int','value'=>'int'],'primary'=>['id'],'indexes'=>[]];SoSecurity\Support\SqlSchema::tables($unit,['sosecurity_principal_probe'=>$spec,'sosecurity_principal_other'=>$spec]);}else{SoSecurity\Support\SqlSchema::table($unit,'sosecurity_principal_probe',['id'=>'int','value'=>'int'],['id']);}++$called;$unit->query('INSERT INTO sosecurity_principal_probe VALUES(1,2)')->closeCursor();});}
  catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.sql_schema',$error->reason());Check::same(false,strpos(json_encode($error->getTrace()),$user.'@')!==false);$rejected=true;}
  $blocked=strpos($user,'+')!==false||strpos($user,'@')!==false;
  Check::same($blocked,$rejected);Check::same($blocked?0:1,$called);Check::same($blocked?0:1,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_principal_probe')->fetchColumn());Check::same(false,$reader->inTransaction());
 }finally{$reader=null;$admin->exec('DROP TABLE IF EXISTS sosecurity_principal_probe');if($paired){$admin->exec('DROP TABLE IF EXISTS sosecurity_principal_other');}$admin=null;$control('DROP USER '.$account);}
}
echo 'PASS SQL schema principal '.($paired?'pair':'format').' '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
