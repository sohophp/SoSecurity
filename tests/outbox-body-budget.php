<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
foreach(['zeroblob(16777216)',"CAST(x'00'||zeroblob(16777216) AS TEXT)","CAST('' AS TEXT)","CAST('abcd'||x'00'||zeroblob(16777216) AS TEXT)","CAST(x'00' AS TEXT)",'0'] as $expression){outboxCase(false,static function(OutboxEnvironment $e)use($expression):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('empty','');$e->append($s,$m);$e->pdo->exec('UPDATE sosecurity_outbox_records SET payload_body='.$expression);
    $root=$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
    foreach([static function()use($s):void{$s->claim('tenant','orders','worker');},static function()use($s,$m):void{$s->status('tenant','orders',$m->id(),'alice');},static function()use($s):void{$s->candidates('tenant','orders','alice');},static function()use($s):void{$s->maintain('tenant','orders','admin');}] as $operation){Check::throws(SoSecurity\Storage\StorageException::class,$operation);}
    Check::same(1,$e->count());$record=$e->pdo->query('SELECT status,attempts FROM sosecurity_outbox_records')->fetch(PDO::FETCH_ASSOC);Check::same('pending',$record['status']);Check::same(0,(int)$record['attempts']);
    Check::same($root,$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));Check::same(true,memory_get_peak_usage(true)<8388608);
});}
// SQLite TEXT/INTEGER affinity does not enforce metadata widths/types. Bound every returned field in SQL.
foreach([['records','message_id'],['records','destination'],['records','aggregate_id'],['records','seal_key'],['records','attempts'],['roots','policy'],['roots','seal_key'],['roots','entries']] as $target){outboxCase(false,static function(OutboxEnvironment $e)use($target):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('metadata','');$e->append($s,$m);
    $e->pdo->exec('UPDATE sosecurity_outbox_'.$target[0].' SET '.$target[1]."=CAST('bad'||x'00'||zeroblob(16777216) AS TEXT)");
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s):void{$s->claim('tenant','orders','worker');});Check::same(1,$e->count());Check::same(true,memory_get_peak_usage(true)<8388608);
});}
// Check the SQL projection itself, so a later HMAC failure cannot hide an unbounded read.
outboxCase(false,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('all-fields','');$e->append($s,$m);
    // Observe through an independent connection and the same bounded projection: never
    // fetch an adversarial raw field merely to prove that a rejected operation is atomic.
    $observe=static function()use($e):array{
        $state=[];
        foreach(['roots'=>SoSecurity\Outbox\Schema::rootTypes(),'records'=>SoSecurity\Outbox\Schema::recordTypes()] as $table=>$types){
            unset($types['payload_body']);
            $state[$table]=$e->observer->query('SELECT '.SoSecurity\Support\SqlSchema::boundedProjection('sqlite',$types).' FROM sosecurity_outbox_'.$table)->fetchAll(PDO::FETCH_ASSOC);
        }
        return $state;
    };
    $snapshots=[];
    foreach(['roots'=>SoSecurity\Outbox\Schema::rootTypes(),'records'=>SoSecurity\Outbox\Schema::recordTypes()] as $table=>$types){
        $snapshots[$table]=$e->pdo->query('SELECT * FROM sosecurity_outbox_'.$table)->fetch(PDO::FETCH_ASSOC);
        foreach($types as $field=>$type){
            if($type==='blob'){continue;}
            $limit=$type==='digest'?64:($type==='int'?256:(int)substr($type,6));
            $projection=SoSecurity\Support\SqlSchema::boundedProjection('sqlite',[$field=>$type]);
            if($type!=='int'){
                $exact="x\0".str_repeat("\0",$limit-2);
                $e->pdo->exec('UPDATE sosecurity_outbox_'.$table.' SET '.$field."=CAST('x'||x'00'||zeroblob(".($limit-2).") AS TEXT)");
                Check::same($exact,$e->pdo->query('SELECT '.$projection.' FROM sosecurity_outbox_'.$table)->fetch(PDO::FETCH_ASSOC)[$field]);
            }
            // The visible prefix fits; the bytes after NUL push the value over its limit.
            $e->pdo->exec('UPDATE sosecurity_outbox_'.$table.' SET '.$field."=CAST('x'||x'00'||zeroblob(".($limit-1).") AS TEXT)");
            Check::same(null,$e->pdo->query('SELECT '.$projection.' FROM sosecurity_outbox_'.$table)->fetch(PDO::FETCH_ASSOC)[$field]);
            $before=$observe();
            foreach([static function()use($s):void{$s->claim('tenant','orders','worker');},static function()use($s,$m):void{$s->status('tenant','orders',$m->id(),'alice');},static function()use($s):void{$s->candidates('tenant','orders','alice');},static function()use($s):void{$s->maintain('tenant','orders','admin');}] as $operation){
                Check::throws(SoSecurity\Storage\StorageException::class,$operation);
                Check::same($before,$observe());
            }
            // Reject wrong SQLite storage classes even when their byte count fits.
            $e->pdo->exec('UPDATE sosecurity_outbox_'.$table.' SET '.$field.'='.($type==='int'?'1.5':"CAST('x' AS BLOB)"));
            Check::same(null,$e->pdo->query('SELECT '.$projection.' FROM sosecurity_outbox_'.$table)->fetch(PDO::FETCH_ASSOC)[$field]);
            $before=$observe();
            foreach([static function()use($s):void{$s->claim('tenant','orders','worker');},static function()use($s,$m):void{$s->status('tenant','orders',$m->id(),'alice');},static function()use($s):void{$s->candidates('tenant','orders','alice');},static function()use($s):void{$s->maintain('tenant','orders','admin');}] as $operation){
                Check::throws(SoSecurity\Storage\StorageException::class,$operation);
                Check::same($before,$observe());
            }
            $q=$e->pdo->prepare('UPDATE sosecurity_outbox_'.$table.' SET '.$field.'=:original');$q->bindValue(':original',$snapshots[$table][$field],$type==='int'?PDO::PARAM_INT:PDO::PARAM_STR);$q->execute();$q->closeCursor();
            Check::same($snapshots[$table],$e->pdo->query('SELECT * FROM sosecurity_outbox_'.$table)->fetch(PDO::FETCH_ASSOC));
        }
        Check::same($snapshots[$table],$e->pdo->query('SELECT * FROM sosecurity_outbox_'.$table)->fetch(PDO::FETCH_ASSOC));
    }
    Check::same('pending',$s->status('tenant','orders',$m->id(),'alice')->state());Check::same(true,memory_get_peak_usage(true)<8388608);
});
// A host callback/statement hook can change a key after history validation. Every
// subsequent key-only scan must still bound its result before PDO fetches it.
foreach(['claim','candidates','maintain'] as $action){outboxCase(false,static function(OutboxEnvironment $e)use($action):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->append($s,$e->message('key-scan',''));
    $before=$e->observer->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC);
    $root=$e->observer->query('SELECT * FROM sosecurity_outbox_roots')->fetchAll(PDO::FETCH_ASSOC);$injected=false;
    $e->pdo->beforeStatement=static function(string $sql)use($e,&$injected):void{
        if(!$injected&&preg_match('/(?:SELECT key_hash| AS key_hash) FROM /',$sql)){
            $injected=true;
            $e->pdo->exec("UPDATE sosecurity_outbox_records SET key_hash=CAST('x'||x'00'||zeroblob(16777216) AS TEXT)");
        }
    };
    outboxRefused('outbox.corrupt',static function()use($s,$action):void{$s->$action('tenant','orders','admin');});
    $e->pdo->beforeStatement=null;Check::same(true,$injected);
    Check::same($before,$e->observer->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC));
    Check::same($root,$e->observer->query('SELECT * FROM sosecurity_outbox_roots')->fetchAll(PDO::FETCH_ASSOC));
    Check::same(true,memory_get_peak_usage(true)<8388608);
});}
// Real binary NUL bytes remain supported; policy/hard input limits reject before any database writes.
outboxCase(false,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$body="a\0b\xff";$m=$e->message('valid-binary',$body,str_repeat('界',60));$e->append($s,$m);$claim=$s->claim('tenant','orders','worker');Check::same($body,$claim->message()->body());Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($e):void{$e->message('too-large',str_repeat('x',1048577));});Check::same(1,$e->count());
});
outboxCase(false,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');outboxRefused('outbox.payload',static function()use($e,$s):void{$e->append($s,$e->message('over-policy',"ab\0cd"));});Check::same(0,$e->count());
},new SoSecurity\Outbox\Policy(['maximum_payload_bytes'=>4]));
echo 'PASS SQL outbox BLOB bound: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; 16 MiB BLOB/NUL-prefixed TEXT rejected under memory_limit=8M\n";
