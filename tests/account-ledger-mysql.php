<?php
declare(strict_types=1);

require __DIR__.'/bootstrap.php';

use SoSecurity\Account\Ledger;
use SoSecurity\Account\Policy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;

// Only the explicit disposable no-TCP instance created by run_ledger_mysql.py is accepted.
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));
if(!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable local MySQL instance.');}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';
$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$observer=new PDO($dsn,'sosecurity_test','integration-only',$options);
$clock=new TestClock();$unit=new SqlTransaction($pdo,$clock,10000);$policy=new Policy(['maximum_entries'=>3]);
$keys=new HmacKeys('one',['one'=>str_repeat('k',32)]);$ledger=new Ledger($unit,'site','tenant',str_repeat('e',64),$keys,$policy);
$id=str_repeat('a',64);$second=str_repeat('c',64);$owner=str_repeat('b',64);
$reset=static function()use($pdo,$ledger,$unit):void{
    foreach(['business_reference','business','sosecurity_account_records','sosecurity_account_roots'] as $table){$pdo->exec('DROP TABLE IF EXISTS '.$table);}
    $pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'));
    Check::same(true,$unit->run(static function()use($ledger):bool{return $ledger->initialize();}));
};
$reset();Check::same(false,$unit->run(static function()use($ledger):bool{return $ledger->initialize();}));
Check::throws(ConfigurationException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'notice',str_repeat('x',16385),100900);});});
Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
foreach(['',"\0start\xff\0end",str_repeat('x',16384)] as $number=>$payload){
    $recordId=hash('sha256','binary-'.$number);$row=$unit->run(static function()use($ledger,$recordId,$owner,$payload):array{return $ledger->put($recordId,$owner,'notice',$payload,100900);});
    Check::same($payload,$row['payload']);Check::same($row,$unit->run(static function()use($ledger,$recordId):array{return $ledger->read($recordId);}));
}
Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','{}',100900);});});
Check::same(3,(int)$pdo->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());
$reset();$row=$unit->run(static function()use($ledger,$id,$owner):array{return $ledger->put($id,$owner,'register','{}',100900);});
Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','changed',100900);});});
$changed=$unit->run(static function()use($ledger,$id,$owner):array{return $ledger->put($id,$owner,'register','changed',100900,1);});Check::same(2,$changed['revision']);Check::same('changed',$changed['payload']);
Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','stale',100900,1);});});
Check::same($changed,$unit->run(static function()use($ledger,$id):array{return $ledger->read($id);}));
$pdo->exec('CREATE TABLE business(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');
Check::throws(StorageException::class,static function()use($ledger,$unit,$second,$owner):void{$unit->run(static function()use($ledger,$unit,$second,$owner):void{$unit->query('INSERT INTO business VALUES(1)');$ledger->put($second,$owner,'notice','{}',100900);throw new RuntimeException('synthetic failure');});});
Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM business')->fetchColumn());Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
$pdo->beginTransaction();try{$pdo->exec('INSERT INTO business VALUES(2)');$unit->enlist(static function()use($ledger,$second,$owner):void{$ledger->put($second,$owner,'notice','{}',100900);});Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());$pdo->rollBack();}catch(Throwable $error){$pdo->rollBack();throw $error;}
Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM business')->fetchColumn());Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
$pdo->beginTransaction();try{$pdo->exec('INSERT INTO business VALUES(3)');Check::throws(StorageException::class,static function()use($ledger,$unit,$second,$owner):void{$unit->enlist(static function()use($ledger,$second,$owner):void{$ledger->put($second,$owner,'notice','{}',100900);throw new RuntimeException('synthetic failure');});});Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM business')->fetchColumn());$pdo->commit();}catch(Throwable $error){$pdo->rollBack();throw $error;}
Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM business')->fetchColumn());Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
foreach(["UPDATE sosecurity_account_records SET payload=REPEAT(0x00,16777214)","UPDATE sosecurity_account_records SET payload=0x7b7b","UPDATE sosecurity_account_records SET kind=0x726567697374657200","UPDATE sosecurity_account_records SET seal=REPEAT('f',64)",'DELETE FROM sosecurity_account_records'] as $sql){
    $reset();$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','{}',100900);});$pdo->exec($sql);
    Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->read($id);});});
    Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','repair',100900,1);});});
    Check::same(1,(int)$pdo->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());
}
$reset();$pdo->exec('CREATE TABLE business_reference(namespace CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,FOREIGN KEY(namespace) REFERENCES sosecurity_account_roots(namespace) ON DELETE CASCADE) ENGINE=InnoDB');
Check::throws(ConfigurationException::class,static function()use($ledger,$unit):void{$unit->run(static function()use($ledger):void{$ledger->initialize();});});
Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn());
$reset();$pdo->exec("ALTER TABLE sosecurity_account_records MODIFY kind VARBINARY(32) NOT NULL");
Check::throws(ConfigurationException::class,static function()use($ledger,$unit):void{$unit->run(static function()use($ledger):void{$ledger->initialize();});});
$reset();$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'budget','cursor',100900);});$clock->time+=15*86400;
$next=$unit->run(static function()use($ledger,$clock,$id,$owner):array{return $ledger->put($id,$owner,'budget','next-cursor',$clock->time+900,1);});Check::same(100000,$next['created_at']);Check::same($clock->time,$next['updated_at']);Check::same('next-cursor',$next['payload']);
Check::throws(ConfigurationException::class,static function()use($ledger,$clock,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$clock,$id,$owner):void{$ledger->put($id,$owner,'budget','too-far',$clock->time+1209601,2);});});Check::same($next,$unit->run(static function()use($ledger,$id):array{return $ledger->read($id);}));
echo 'PASS isolated account ledger MySQL: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; owned no-TCP local database, binary bounds, CAS, integrity and transaction ownership; not complete account lifecycle\n";
