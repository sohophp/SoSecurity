<?php
declare(strict_types=1);

require __DIR__.'/bootstrap.php';

use SoSecurity\Account\Ledger;
use SoSecurity\Account\Policy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;

/** Private on-disk database only; never reads host database configuration. */
function ledgerCase(callable $body,array $options=[]):void
{
    $directory=privateDirectory();$pdo=null;$observer=null;
    try{
        $pdo=new PDO('sqlite:'.$directory.'/ledger.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');
        $pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/account-sqlite.sql'));
        $observer=new PDO('sqlite:'.$directory.'/ledger.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $clock=new TestClock();$unit=new SqlTransaction($pdo,$clock,10000);$keys=new HmacKeys('one',['one'=>str_repeat('k',32)]);$policy=new Policy($options);
        $ledger=new Ledger($unit,'site','tenant',str_repeat('e',64),$keys,$policy);
        $body($pdo,$observer,$clock,$unit,$ledger,$keys,$policy);
    }finally{$pdo=null;$observer=null;cleanDirectory($directory);}
}

$id=str_repeat('a',64);$owner=str_repeat('b',64);
ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$owner):void{
    $unit->run(static function()use($ledger,$id,$owner):void{$ledger->initialize();$ledger->put($id,$owner,'budget','cursor',100900);});$clock->time+=15*86400;
    $next=$unit->run(static function()use($ledger,$clock,$id,$owner):array{return $ledger->put($id,$owner,'budget','next-cursor',$clock->time+900,1);});Check::same(100000,$next['created_at']);Check::same($clock->time,$next['updated_at']);Check::same('next-cursor',$next['payload']);
    Check::throws(ConfigurationException::class,static function()use($ledger,$clock,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$clock,$id,$owner):void{$ledger->put($id,$owner,'budget','too-far',$clock->time+1209601,2);});});Check::same($next,$unit->run(static function()use($ledger,$id):array{return $ledger->read($id);}));
});
ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$owner):void{
    Check::throws(ConfigurationException::class,static function()use($ledger):void{$ledger->initialize();});
    Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->read($id);});});
    Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn());
    Check::same(true,$unit->run(static function()use($ledger):bool{return $ledger->initialize();}));
    Check::same(false,$unit->run(static function()use($ledger):bool{return $ledger->initialize();}));
    $payload="\0binary\xff\0suffix";
    $row=$unit->run(static function()use($ledger,$id,$owner,$payload):array{return $ledger->put($id,$owner,'notice',$payload,100900);});
    Check::same($payload,$row['payload']);Check::same(1,$row['revision']);
    Check::same($row,$unit->run(static function()use($ledger,$id):array{return $ledger->read($id);}));
    Check::same($row,$unit->run(static function()use($ledger,$owner):array{return $ledger->latest($owner,'notice');}));
    Check::same(null,$unit->run(static function()use($ledger):?array{return $ledger->read(str_repeat('d',64));}));
    foreach([null,0,2] as $revision){Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner,$revision):void{$unit->run(static function()use($ledger,$id,$owner,$revision):void{$ledger->put($id,$owner,'notice','replace',100900,$revision);});});}
    Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->put($id,str_repeat('d',64),'notice','replace',100900,1);});});
    Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','replace',100900,1);});});
    ++$clock->time;$new=$unit->run(static function()use($ledger,$id,$owner):array{return $ledger->put($id,$owner,'notice','',100900,1);});
    Check::same('', $new['payload']);Check::same(2,$new['revision']);Check::same(100000,$new['created_at']);Check::same(100001,$new['updated_at']);
    Check::same($new,$unit->run(static function()use($ledger,$id):array{return $ledger->read($id);}));
    $before=$pdo->query('SELECT revision,history_digest FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    Check::throws(ConfigurationException::class,static function()use($ledger,$unit,$owner):void{$unit->run(static function()use($ledger,$owner):void{$ledger->put(str_repeat('c',64),$owner,'notice',str_repeat('x',16385),100900);});});
    Check::same($before,$pdo->query('SELECT revision,history_digest FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));
    Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
    // The owning unit commits exactly once; a thrown business operation retains neither ledger nor business writes.
    $pdo->exec('CREATE TABLE business(id INTEGER PRIMARY KEY)');
    Check::throws(StorageException::class,static function()use($ledger,$unit,$owner):void{$unit->run(static function()use($ledger,$unit,$owner):void{$unit->query('INSERT INTO business VALUES(1)');$ledger->put(str_repeat('c',64),$owner,'register','{}',100900);throw new RuntimeException('synthetic failure');});});
    Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM business')->fetchColumn());
    Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
    $pdo->exec('BEGIN IMMEDIATE');
    try{
        $pdo->exec('INSERT INTO business VALUES(2)');
        $unit->enlist(static function()use($ledger,$owner):void{$ledger->put(str_repeat('c',64),$owner,'register','{}',100900);});
        Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
        $pdo->exec('ROLLBACK');
    }catch(Throwable $error){$pdo->exec('ROLLBACK');throw $error;}
    Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM business')->fetchColumn());Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
    $pdo->exec('BEGIN IMMEDIATE');
    try{
        $pdo->exec('INSERT INTO business VALUES(3)');
        Check::throws(StorageException::class,static function()use($ledger,$unit,$owner):void{$unit->enlist(static function()use($ledger,$owner):void{$ledger->put(str_repeat('c',64),$owner,'register','{}',100900);throw new RuntimeException('synthetic failure');});});
        Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM business')->fetchColumn());Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
        $pdo->exec('COMMIT');
    }catch(Throwable $error){$pdo->exec('ROLLBACK');throw $error;}
    Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM business')->fetchColumn());
    foreach([var_export($ledger,true),print_r($ledger,true),json_encode($ledger)] as $dump){Check::same(false,strpos($dump,str_repeat('k',32))!==false);}
    Check::throws(ConfigurationException::class,static function()use($ledger):void{serialize($ledger);});
    $clock->time=99999;Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->read($id);});});
});

// Read bounding happens in SQL. A multi-megabyte TEXT/NUL field is never materialized in PHP.
foreach(['record_id','owner','kind','seal_key','seal','payload_digest'] as $field){
    ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$owner,$field):void{
        $unit->run(static function()use($ledger,$id,$owner):void{$ledger->initialize();$ledger->put($id,$owner,'register','{}',100900);});
        $pdo->exec('UPDATE sosecurity_account_records SET '.$field."=CAST(x'6100' || zeroblob(16777216) AS TEXT)");
        Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->read($id);});});
        Check::same(1,(int)$pdo->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());
    });
}
foreach(['policy','seal_key','seal','history_digest'] as $field){
    ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$field):void{
        $unit->run(static function()use($ledger):void{$ledger->initialize();});$pdo->exec('UPDATE sosecurity_account_roots SET '.$field."=CAST(x'6100' || zeroblob(16777216) AS TEXT)");
        Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->read($id);});});
    });
}
foreach(['DELETE FROM sosecurity_account_records',"UPDATE sosecurity_account_records SET payload=zeroblob(16777216)","UPDATE sosecurity_account_records SET payload=CAST(x'7b007d' AS TEXT)","UPDATE sosecurity_account_records SET payload=x'7b7b'","UPDATE sosecurity_account_records SET revision=-1","UPDATE sosecurity_account_records SET kind=CAST(x'726567697374657200' AS TEXT)"] as $sql){
    ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$owner,$sql):void{
        $unit->run(static function()use($ledger,$id,$owner):void{$ledger->initialize();$ledger->put($id,$owner,'register','{}',100900);});$pdo->exec($sql);
        Check::throws(StorageException::class,static function()use($ledger,$unit,$id):void{$unit->run(static function()use($ledger,$id):void{$ledger->read($id);});});
        Check::throws(StorageException::class,static function()use($ledger,$unit,$id,$owner):void{$unit->run(static function()use($ledger,$id,$owner):void{$ledger->put($id,$owner,'register','fixed',100900,1);});});
    });
}
ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$owner):void{
    $unit->run(static function()use($ledger,$id,$owner):void{$ledger->initialize();$ledger->put($id,$owner,'register',str_repeat('x',16384),100900);});
    Check::same(16384,strlen($unit->run(static function()use($ledger,$id):array{return $ledger->read($id);})['payload']));
    Check::throws(StorageException::class,static function()use($ledger,$unit,$owner):void{$unit->run(static function()use($ledger,$owner):void{$ledger->put(str_repeat('c',64),$owner,'notice','{}',100900);});});
    Check::throws(StorageException::class,static function()use($ledger,$unit):void{$unit->run(static function()use($ledger):void{$ledger->capacity(1);});});
    Check::same(1,(int)$pdo->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());
},['maximum_entries'=>1]);
ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($id,$owner):void{
    $unit->run(static function()use($ledger,$id,$owner):void{$ledger->initialize();$ledger->put($id,$owner,'register','{}',100900);});$pdo->exec('DELETE FROM sosecurity_account_roots');
    Check::throws(StorageException::class,static function()use($ledger,$unit):void{$unit->run(static function()use($ledger):void{$ledger->initialize();});});
    Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn());
});
foreach(['sosecurity_account_roots'=>'namespace','sosecurity_account_records'=>'namespace,record_id'] as $table=>$columns){
    ledgerCase(static function(PDO $pdo,PDO $observer,TestClock $clock,SqlTransaction $unit,Ledger $ledger)use($table,$columns):void{
        $unit->run(static function()use($ledger):void{$ledger->initialize();});
        $definitions=$columns==='namespace'?'namespace TEXT NOT NULL':'namespace TEXT NOT NULL,record_id TEXT NOT NULL';
        $pdo->exec('CREATE TABLE business_reference('.$definitions.',FOREIGN KEY('.$columns.') REFERENCES '.$table.'('.$columns.') ON DELETE CASCADE)');
        Check::same(0,(int)$pdo->query('PRAGMA foreign_keys')->fetchColumn());
        Check::throws(ConfigurationException::class,static function()use($ledger,$unit):void{$unit->run(static function()use($ledger):void{$ledger->initialize();});});
    });
}
echo 'PASS isolated account ledger: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; private SQLite, bounded metadata/binary payloads, integrity, CAS, capacity and transaction ownership; not complete account lifecycle\n";
