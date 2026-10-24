<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_schema_clock','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$created=[];$other=false;
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $sql){if(trim($sql)===''){continue;}$pdo->exec($sql);if(preg_match('/CREATE TABLE\s+(\w+)/i',$sql,$m)){$created[]=$m[1];}}
 $clock=new class($pdo) implements SoSecurity\Support\Clock{private $pdo;public $armed=false;public function __construct(PDO $pdo){$this->pdo=$pdo;}public function now():int{if($this->armed){$this->armed=false;$this->pdo->exec('USE sosecurity_clock_other');}return 1000000;}};
 $unit=new SoSecurity\Support\SqlTransaction($pdo,$clock,10000);$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);
 $ledger=new SoSecurity\Account\Ledger($unit,'owned','tenant',str_repeat('e',64),$keys,new SoSecurity\Account\Policy());
 $unit->run(static function()use($ledger):void{$ledger->initialize();});
 $pdo->exec('CREATE DATABASE sosecurity_clock_other');$other=true;
 foreach($created as $table){$pdo->exec('CREATE TABLE sosecurity_clock_other.'.$table.' LIKE sosecurity_test.'.$table);$pdo->exec('INSERT INTO sosecurity_clock_other.'.$table.' SELECT * FROM sosecurity_test.'.$table);}
 $pdo->exec('ALTER TABLE sosecurity_clock_other.sosecurity_account_roots ADD UNIQUE owned_extra_unique(revision)');
 $rejected=false;
 try{$unit->run(static function()use($ledger,$clock):void{$ledger->checkpoint();$clock->armed=true;$ledger->checkpoint();});}
 catch(SoSecurity\Exception\ConfigurationException $e){Check::same('configuration.sql_schema',$e->reason());$rejected=true;}
 Check::same(true,$rejected);
 $pdo->exec('USE sosecurity_test');
 $native=new SoSecurity\Support\SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);
 $nativeLedger=new SoSecurity\Account\Ledger($native,'owned','tenant',str_repeat('e',64),$keys,new SoSecurity\Account\Policy());
 $rejected=false;
 try{$native->run(static function()use($native,$nativeLedger,$pdo):void{
  $nativeLedger->checkpoint();$native->invoke(static function()use($pdo):void{$pdo->exec('USE sosecurity_clock_other');},[],'test.callback');$nativeLedger->checkpoint();
 });}catch(SoSecurity\Exception\ConfigurationException $e){Check::same('configuration.sql_schema',$e->reason());$rejected=true;}
 Check::same(true,$rejected);
 echo 'PASS schema clock database context '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{
 try{$pdo->exec('ROLLBACK');}catch(Throwable $e){}
 $pdo->exec('USE sosecurity_test');if($other){$pdo->exec('DROP DATABASE sosecurity_clock_other');}
 foreach(array_reverse($created) as $table){$pdo->exec('DROP TABLE '.$table);}
}
