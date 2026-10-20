<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable local test database.');}$GLOBALS['registrationMySQLSocket']=$socket;}
use SoSecurity\Account\Ledger;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
function revisions(RegistrationEnvironment $e):array {$rows=$e->pdo->query('SELECT record_id,revision FROM sosecurity_account_records')->fetchAll(PDO::FETCH_KEY_PAIR);$result=[];foreach($rows as $id=>$revision){$result[$id]=SoSecurity\Support\SqlSchema::integer($revision);}return $result;}
function participant(RegistrationEnvironment $e):array {$unit=new SqlTransaction($e->pdo,$e->clock,10000);return [$unit,new Ledger($unit,'account-test','tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),$e->policy)];}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();list($unit,$ledger)=participant($e);$ids=[];
    $unit->run(static function()use($ledger,&$ids):void{for($n=0;$n<66;++$n){$id=hash('sha256','page-'.$n);$ledger->put($id,str_repeat('a',64),'budget','{}',100900);$ids[]=$id;}});sort($ids);
    $first=$unit->run(static function()use($ledger):array{return $ledger->page(50);});$second=$unit->run(static function()use($ledger,$first):array{return $ledger->page(50,$first[49]['record_id']);});Check::same(50,count($first));Check::same(16,count($second));Check::same($ids,array_merge(array_column($first,'record_id'),array_column($second,'record_id')));
    $last=$unit->run(static function()use($ledger,$second):array{return $ledger->page(50,$second[15]['record_id']);});Check::same([],$last);$expected=array_fill_keys($ids,1);Check::same(66,$unit->run(static function()use($ledger,$expected):int{return $ledger->remove($expected);}));Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,(int)$e->observer->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');list($unit,$ledger)=participant($e);$ids=revisions($e);$before=$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    $queries=$e->pdo->queries;foreach([[],array_fill_keys(array_map(static function(int $n):string{return hash('sha256',(string)$n);},range(0,100)),1),[str_repeat('a',64)=>'1'],['bad'=>1]] as $bad){Check::throws(ConfigurationException::class,static function()use($ledger,$bad):void{$ledger->remove($bad);});}Check::same($queries,$e->pdo->queries);
    $wrong=$ids;$first=array_keys($wrong)[0];$wrong[$first]=(int)$wrong[$first]+1;Check::throws(StorageException::class,static function()use($unit,$ledger,$wrong):void{$unit->run(static function()use($ledger,$wrong):void{$ledger->remove($wrong);});});Check::same(3,$e->count('sosecurity_account_records'));Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));
    $notice=$e->notices()[0];$e->pdo->exec("UPDATE sosecurity_account_records SET payload=".($e->mysql?'REPEAT(0x00,payload_bytes)':'zeroblob(payload_bytes)')." WHERE kind='notice'");$deletes=0;$e->pdo->beforeStatement=static function(string $sql)use(&$deletes):void{if(strpos($sql,'DELETE FROM ')===0){++$deletes;}};
    Check::throws(StorageException::class,static function()use($unit,$ledger,$ids):void{$unit->run(static function()use($ledger,$ids):void{$ledger->remove($ids);});});Check::same(0,$deletes);Check::same(3,$e->count('sosecurity_account_records'));Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');list($unit,$ledger)=participant($e);$id=$s->notification($e->notices()[0])->selector();$row=$unit->run(static function()use($ledger,$id):array{return $ledger->read($id);});$bad=json_decode($row['payload'],true);$bad['format']=99;
    $unit->run(static function()use($ledger,$row,$bad):void{$ledger->put($row['record_id'],$row['owner'],'register',json_encode($bad),$row['retire_at'],$row['revision']);});$e->clock->time+=172800;$before=$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    foreach(['maintain','rotate'] as $method){Check::throws(StorageException::class,static function()use($s,$method):void{$s->$method();});Check::same(3,$e->count('sosecurity_account_records'));Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));}
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');list($unit,$ledger)=participant($e);$id=$s->notification($e->notices()[0])->selector();$unit->run(static function()use($ledger,$id):void{$row=$ledger->read($id);$ledger->remove([$id=>$row['revision']]);});$before=$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    foreach(['maintain','rotate'] as $method){Check::throws(StorageException::class,static function()use($s,$method):void{$s->$method();});Check::same(2,$e->count('sosecurity_account_records'));Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));}
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$e->clock->time+=172800;$before=$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    $e->pdo->exec('CREATE TABLE account_maintenance_child(namespace '.($e->mysql?'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin':'TEXT').' NOT NULL,FOREIGN KEY(namespace) REFERENCES sosecurity_account_roots(namespace) ON DELETE CASCADE)'.($e->mysql?' ENGINE=InnoDB':''));
    try{
        $namespace=$e->pdo->query('SELECT namespace FROM sosecurity_account_roots')->fetchColumn();$q=$e->pdo->prepare('INSERT INTO account_maintenance_child VALUES(?)');$q->execute([$namespace]);$q->closeCursor();
        foreach(['maintain','rotate'] as $method){Check::throws(ConfigurationException::class,static function()use($s,$method):void{$s->$method();});Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM account_maintenance_child')->fetchColumn());Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));}
    }finally{$e->pdo->exec('DROP TABLE account_maintenance_child');}
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$e->clock->time+=172800;$e->pdo->exec("UPDATE sosecurity_account_records SET payload=".($e->mysql?'REPEAT(0x00,16777214)':"CAST(x'7b00'||zeroblob(16777216) AS TEXT)")." WHERE kind='notice'");$before=$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    foreach(['maintain','rotate'] as $method){Check::throws(StorageException::class,static function()use($s,$method):void{$s->$method();});Check::same(3,$e->count('sosecurity_account_records'));Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));}Check::same(true,memory_get_peak_usage(true)<8388608);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$e->clock->time+=172800;list($unit,$ledger)=participant($e);$ids=revisions($e);$e->pdo->exec('CREATE TABLE maintenance_business(id INT NOT NULL PRIMARY KEY)'.($e->mysql?' ENGINE=InnoDB':''));
    try{
        $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$e->pdo->exec('INSERT INTO maintenance_business VALUES(1)');$unit->enlist(static function()use($ledger,$ids):void{Check::same(3,$ledger->remove($ids));});Check::same(3,$e->count('sosecurity_account_records'));Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM maintenance_business')->fetchColumn());$e->pdo->exec('ROLLBACK');Check::same(3,$e->count('sosecurity_account_records'));
        $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$e->pdo->exec('INSERT INTO maintenance_business VALUES(2)');Check::throws(StorageException::class,static function()use($unit,$ledger,$ids):void{$unit->enlist(static function()use($ledger,$ids):void{$ledger->remove($ids);throw new RuntimeException('synthetic local failure');});});Check::same(3,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM maintenance_business')->fetchColumn());$e->pdo->exec('COMMIT');Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM maintenance_business')->fetchColumn());
    }finally{try{$e->pdo->exec('ROLLBACK');}catch(Throwable $error){}$e->pdo->exec('DROP TABLE maintenance_business');}
});
echo 'PASS account ledger maintenance: '.Check::$assertions.' assertions on '.($socket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."; CAS batch preflight, all-body authentication, unknown/dangling state, FK refusal, oversized SQL data and host transaction ownership\n";
