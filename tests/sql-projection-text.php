<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
$baseline=json_decode(file_get_contents(__DIR__.'/state-snapshot/projection-text-baseline.json'),true);
foreach($baseline['rows'] as $case){Check::same($case['expected'],SqlSchema::boundedProjection($case['driver'],$case['types'],$case['alias'],$case['prefix']));}
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function():void{SqlSchema::boundedProjection('sqlite',['counter'=>'int'],null,'',true);});
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function():void{SqlSchema::boundedProjection('mysql',['payload'=>'blob'],null,'',true);});
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function():void{SqlSchema::boundedProjection('mysql',['counter'=>'int'],'r;drop','',true);});
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function():void{SqlSchema::boundedProjection('mysql',['counter'=>'int'],'r','bad.prefix',true);});
echo 'PASS bounded text projection defaults and rejection '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
if(($argv[1]??'')==='mysql'){
 $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
 $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
 $sql='SELECT '.SqlSchema::boundedProjection('mysql',['counter'=>'int','label'=>'bytes:16'],'r','out_',true).' FROM (SELECT CAST(:value AS DECIMAL(21,0)) AS counter,:label AS label) r';
 foreach([false,true] as $stringify){$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,$stringify);foreach([['0','x','0','x'],['1',str_repeat('l',16),'1',str_repeat('l',16)],['9223372036854775807','max','9223372036854775807','max'],['9223372036854775808',str_repeat('l',17),null,null],['-1','negative',null,'negative']] as $case){$q=$pdo->prepare($sql);$q->execute(['value'=>$case[0],'label'=>$case[1]]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();Check::same($case[2],$row['out_counter']);Check::same($case[3],$row['out_label']);}}
 echo 'PASS bounded MySQL text integer range and string budgets '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}
