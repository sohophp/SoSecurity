<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use the owned disposable SQL test server.');}
$directory=privateDirectory();$pdo=null;
try{
 $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/ledger.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
 if($mysql){$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}else{$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
 $pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/account-'.($mysql?'mysql':'sqlite').'.sql'));
 $unit=new SoSecurity\Support\SqlTransaction($pdo,new TestClock(),10000);
 $ledger=new SoSecurity\Account\Ledger($unit,'site','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('one',['one'=>str_repeat('k',32)]),new SoSecurity\Account\Policy());
 $id=str_repeat('a',64);$missing=str_repeat('c',64);$owner=str_repeat('b',64);
 $unit->run(static function()use($ledger,$id,$missing,$owner):void{
  Check::same(null,$ledger->checkpointIfInitialized());$ledger->capacity(1,true);Check::same(true,$ledger->initialize());
  $row=$ledger->put($id,$owner,'notice','owned-body',100900);$root=$ledger->checkpoint();
  Check::same($root,$ledger->verifyBodies());Check::same([$row],$ledger->bodyPage(3));
  Check::same([$id=>$row,$missing=>null],$ledger->readMany([$id,$missing]));
  Check::same($row,$ledger->latest($owner,'notice'));Check::same(null,$ledger->latest(str_repeat('d',64),'notice'));
  Check::same($root,$ledger->checkpointIfInitialized());Check::same([],$ledger->page(3,$id));
  $ledger->capacity(1);Check::same($root,$ledger->checkpoint());
  echo 'VALUE '.hash('sha256',json_encode([$root,$row])).PHP_EOL;
 });
 Check::same(false,$pdo->inTransaction());echo 'PASS ledger read values '.Check::$assertions.' assertions'.PHP_EOL;
}finally{if($pdo instanceof PDO&&$pdo->inTransaction()){$pdo->rollBack();}if($mysql&&$pdo instanceof PDO){$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_records');$pdo->exec('DROP TABLE IF EXISTS sosecurity_account_roots');}$pdo=null;cleanDirectory($directory);}
