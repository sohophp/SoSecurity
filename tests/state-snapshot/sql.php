<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    $queries=$pdo->queries;$s=snapshotSource($pdo);Check::same($queries,$pdo->queries);Check::same(true,$s->connection()===$pdo);$empty=$s->digest();Check::same(64,strlen($empty));Check::same($empty,$s->digest());
    snapshotInsert($pdo,'tenant',1,"a\0b",null,"界\0");$a=$s->digest();Check::same(false,$a===$empty);Check::same($a,$s->digest());
    $pdo->exec("UPDATE snapshot_test SET password=''");$b=$s->digest();Check::same(false,$a===$b);$q=$pdo->prepare('UPDATE snapshot_test SET password=?');$q->execute(["a\0b"]);$c=$s->digest();Check::same(false,$b===$c);$q->execute(["a\0c"]);Check::same(false,$c===$s->digest());$q->closeCursor();
    $filter=snapshotSource($pdo,32,1000,['scope'=>'tenant']);$before=$filter->digest();snapshotInsert($pdo,'other',1,'foreign');Check::same($before,$filter->digest());Check::same(false,$s->digest()===$before);
    Check::same(false,$filter->fingerprint()===$s->fingerprint());
    $decl=snapshotSpec();unset($decl['snapshot_test']['columns']['password']);$incomplete=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-profile',$decl);snapshotReason('account.snapshot_corrupt',static function()use($incomplete):void{$incomplete->digest();});
    $decl=snapshotSpec();$decl['snapshot_test']['primary']=['id'];$wrong=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-profile',$decl);snapshotReason('account.snapshot_corrupt',static function()use($wrong):void{$wrong->digest();});
});
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    $pdo->exec('BEGIN');try{for($i=0;$i<70;++$i){snapshotInsert($pdo,'tenant',$i,chr($i));}$pdo->exec('COMMIT');}catch(Throwable $e){$pdo->exec('ROLLBACK');throw $e;}$s=snapshotSource($pdo,32,70);$before=$s->digest();Check::same($before,$s->digest());snapshotInsert($pdo,'tenant',70,'last');snapshotReason('account.snapshot_capacity',static function()use($s):void{$s->digest();});Check::same(71,(int)$pdo->query('SELECT COUNT(*) FROM snapshot_test')->fetchColumn());
    $pdo->exec('DELETE FROM snapshot_test WHERE id=70');$pdo->exec('UPDATE snapshot_test SET id=100 WHERE id=69');Check::same(false,$before===$s->digest());
});
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer)use($mysql):void{
    snapshotInsert($pdo,'tenant',1,'owned');$s=snapshotSource($pdo);$digest=$s->digest();$pdo->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$pdo->exec("UPDATE snapshot_test SET tag='uncommitted'");Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{$s->digest();});Check::same('owned',$observer->query('SELECT tag FROM snapshot_test')->fetchColumn());Check::same('uncommitted',$pdo->query('SELECT tag FROM snapshot_test')->fetchColumn());$pdo->exec('ROLLBACK');Check::same($digest,$s->digest());
});
snapshotCase($mysql,static function(InboxTestConnection $pdo):void{
    snapshotInsert($pdo,"a\0\xff",1,'binary');$scope="a\0\xff";$maximum=32;$decl=snapshotSpec($maximum,1000,['scope'=>$scope]);$decl['snapshot_test']['where']['scope']=&$scope;$bodyType='blob:32';$decl['snapshot_test']['columns']['body']=&$bodyType;$s=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-profile',$decl);$fp=$s->fingerprint();$digest=$s->digest();$scope='different';$bodyType='blob:1';Check::same($fp,$s->fingerprint());Check::same($digest,$s->digest());
    foreach([var_export($s,true),print_r($s,true),json_encode($s)] as $dump){Check::same(false,strpos($dump,'binary')!==false);}Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{serialize($s);});
});
snapshotCase($mysql,static function(InboxTestConnection $pdo)use($mysql):void{
    snapshotInsert($pdo,'tenant',1,'');$s=snapshotSource($pdo,1048576);$pdo->exec('UPDATE snapshot_test SET body='.($mysql?'REPEAT(CHAR(0),1048576)':'zeroblob(1048576)'));$good=$s->digest();Check::same($good,$s->digest());$pdo->exec('UPDATE snapshot_test SET body='.($mysql?'REPEAT(CHAR(0),2097152)':'zeroblob(16777216)'));snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});
    // Allocator reservation may equal the enforced cap while live usage is much
    // smaller. Keep the runtime limit, and verify both measurements explicitly.
    Check::same('8M',ini_get('memory_limit'));Check::same(true,memory_get_peak_usage(true)<=8388608);Check::same(true,memory_get_peak_usage(false)<8388608);
});
if(!$mysql){foreach(["CAST('a'||x'00'||zeroblob(16777216) AS TEXT)","CAST(x'00' AS TEXT)",'0'] as $expression){snapshotCase(false,static function(InboxTestConnection $pdo)use($expression):void{snapshotInsert($pdo,'tenant',1,'');$s=snapshotSource($pdo,1048576);$pdo->exec('UPDATE snapshot_test SET body='.$expression);snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});Check::same(true,memory_get_peak_usage(true)<8388608);});}}
else{snapshotCase(true,static function(InboxTestConnection $pdo):void{$s=snapshotSource($pdo);$pdo->exec('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED');Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{$s->digest();});Check::same('READ-COMMITTED',$pdo->query('SELECT @@SESSION.transaction_isolation')->fetchColumn());$pdo->exec('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');});}
snapshotCase($mysql,static function(InboxTestConnection $pdo)use($mysql):void{
    $base=snapshotSpec();$bad=[];$v=$base;$v['snapshot_test']['maximum_rows']=0;$bad[]=$v;$v=$base;$v['snapshot_test']['columns']['body']='blob:1048577';$bad[]=$v;$v=$base;$v['snapshot_test']['primary']=['body'];$bad[]=$v;$v=$base;$v['snapshot_test']['primary']=['id','id'];$bad[]=$v;$v=$base;$v['snapshot_test']['where']=['unknown'=>'value'];$bad[]=$v;$v=$base;$v['snapshot_test']['where']=['id'=>-1];$bad[]=$v;$v=$base;$v['snapshot_test']['columns']['password']=new class{public function __toString():string{throw new RuntimeException('Snapshot declarations must not invoke object hooks.');}};$bad[]=$v;
    foreach($bad as $decl){$queries=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$decl):void{new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-profile',$decl);});Check::same($queries,$pdo->queries);}
    snapshotInsert($pdo,'tenant',1,'');$s=snapshotSource($pdo);$before=$s->digest();$pdo->exec('ALTER TABLE snapshot_test ADD COLUMN extra '.($mysql?'VARBINARY(32)':'TEXT').' NULL');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});Check::same('owned',$pdo->query('SELECT tag FROM snapshot_test')->fetchColumn());
});
if(!$mysql){snapshotCase(false,static function(InboxTestConnection $pdo):void{
    snapshotInsert($pdo,'tenant',1,'');$s=snapshotSource($pdo);$before=$s->digest();$pdo->exec('CREATE TEMP TABLE snapshot_test(value TEXT)');$pdo->exec("INSERT INTO temp.snapshot_test VALUES('foreign temporary data')");Check::same($before,$s->digest());$pdo->exec('DROP TABLE temp.snapshot_test');
    foreach(['password','tag','scope','id'] as $field){$pdo->exec('UPDATE main.snapshot_test SET '.$field."=CAST('a'||x'00'||zeroblob(16777216) AS TEXT)");snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});Check::same(true,memory_get_peak_usage(true)<8388608);$pdo->exec('DELETE FROM main.snapshot_test');snapshotInsert($pdo,'tenant',1,'');}
});}
echo 'PASS bounded typed SQL snapshots: '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; complete columns, all binary bytes, NULL/empty, composite keyset paging, row/field limits, immutable source profile and host transactions\n";
