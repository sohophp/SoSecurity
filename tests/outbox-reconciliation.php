<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1] ?? '')==='mysql';
require __DIR__.'/outbox-reconciliation-support.php';

foreach(['received','cancelled'] as $outcome){foreach([false,true] as $attempted){resolutionCase($mysql,static function(OutboxEnvironment $e)use($outcome,$attempted):void{
    list($s,$m,$token)=resolutionRetired($e,$attempted);$successor=$e->message('successor','');$e->append($s,$successor);Check::same(null,$s->claim('tenant','orders','worker'));
    $evidence=hash('sha256','synthetic-'.$outcome);$phases=[];$guard=resolutionGuard($e,$m,$phases);resolutionBegin($e);resolutionAudit($e,$m,$outcome,$evidence);
    Check::same(true,$s->reconcile($m,'admin',$outcome,$evidence,$guard));
    Check::same(['request','current','commit'],$phases);Check::same('dead',$e->observer->query('SELECT status FROM sosecurity_outbox_records WHERE order_no=1')->fetchColumn());
    Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());Check::same(1,(int)$e->observer->query('SELECT format FROM sosecurity_outbox_roots')->fetchColumn());
    $e->pdo->exec('ROLLBACK');Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
    resolutionBegin($e);resolutionAudit($e,$m,$outcome,$evidence);Check::same(true,$s->reconcile($m,'admin',$outcome,$evidence,$guard));$e->pdo->exec('COMMIT');
    $status=$s->status('tenant','orders',$m->id(),'alice');Check::same('resolved',$status->state());Check::same($outcome,$status->resolution());Check::same(0,$status->sentAt());Check::same(0,$status->leaseUntil());Check::same($attempted?1:0,$status->attempts());
    $row=$e->pdo->query('SELECT format,token_digest,payload_present,sent_at FROM sosecurity_outbox_records WHERE order_no=1')->fetch(PDO::FETCH_ASSOC);Check::same(2,(int)$row['format']);Check::same($evidence,$row['token_digest']);Check::same(0,(int)$row['payload_present']);Check::same(0,(int)$row['sent_at']);
    if($token!==null){Check::same(false,$s->acknowledge('tenant','orders','worker',$token));Check::same(false,$s->fail('tenant','orders','worker',$token,'transport.timeout'));}
    resolutionBegin($e);Check::same(false,$s->reconcile($m,'admin',$outcome,$evidence,$guard));$e->pdo->exec('COMMIT');Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
    $next=$s->claim('tenant','orders','worker');Check::same($successor->id(),$next->message()->id());Check::same(true,$s->acknowledge('tenant','orders','worker',$next->token()));Check::same(null,$next->status()->resolution());
    Check::same(0,$s->maintain('tenant','orders','admin')['purged']);$e->clock->time+=2;Check::same(1,$s->maintain('tenant','orders','admin')['purged']);
    Check::same(null,$s->status('tenant','orders',$m->id(),'alice'));Check::same(2,(int)$e->pdo->query('SELECT format FROM sosecurity_outbox_roots')->fetchColumn());
    outboxRefused('outbox.expired',static function()use($e,$s,$m):void{$e->append($s,$m);});$new=$e->message('after-resolution');Check::same(3,$e->append($s,$new)->order());
    Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
});}}

// Both normal management and the explicit evidence policy must approve every phase.
foreach(['management','decision'] as $source){foreach(['request','current','commit'] as $phase){resolutionCase($mysql,static function(OutboxEnvironment $e)use($source,$phase):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$base=resolutionGuard($e,$m,$phases);
    $guard=static function(string $when,array $meta)use($base,$source,$phase):bool{return $base($when,$meta)&&!($source==='decision'&&$when===$phase);};
    $e->onManagement=static function(string $action,string $when)use($source,$phase):bool{return !($action==='reconcile'&&$source==='management'&&$when===$phase);};
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);outboxRefused('outbox.denied',static function()use($s,$m,$evidence,$guard):void{$s->reconcile($m,'admin','received',$evidence,$guard);});
    Check::same('dead',$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
    $e->pdo->exec('ROLLBACK');Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());Check::same(1,(int)$e->pdo->query('SELECT format FROM sosecurity_outbox_roots')->fetchColumn());
});}}

// No audit, wrong binding or changed terminal outcome cannot close an intent.
resolutionCase($mysql,static function(OutboxEnvironment $e):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$guard=resolutionGuard($e,$m,$phases);
    resolutionBegin($e);outboxRefused('outbox.denied',static function()use($s,$m,$evidence,$guard):void{$s->reconcile($m,'admin','received',$evidence,$guard);});$e->pdo->exec('ROLLBACK');
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);$changed=new Message($m->scope(),$m->producer(),$m->id(),$m->destination(),$m->topic(),$m->aggregate(),'changed');
    outboxRefused('outbox.conflict',static function()use($s,$changed,$evidence):void{$s->reconcile($changed,'admin','received',$evidence,static function():bool{return true;});});$e->pdo->exec('ROLLBACK');
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);Check::same(true,$s->reconcile($m,'admin','received',$evidence,$guard));$e->pdo->exec('COMMIT');
    foreach([['cancelled',$evidence],['received',hash('sha256','other')]] as $change){resolutionBegin($e);outboxRefused('outbox.conflict',static function()use($s,$m,$change):void{$s->reconcile($m,'admin',$change[0],$change[1],static function():bool{return true;});});$e->pdo->exec('ROLLBACK');}
    Check::same('received',$s->status('tenant','orders',$m->id(),'alice')->resolution());
});

foreach(['pending','early-dead','unretired'] as $variant){resolutionCase($mysql,static function(OutboxEnvironment $e)use($variant):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);
    if($variant!=='pending'){$claim=$s->claim('tenant','orders','worker');$s->fail('tenant','orders','worker',$claim->token(),'transport.timeout',false);}
    if($variant==='unretired'){$e->clock->time+=6;}
    $evidence=hash('sha256','evidence');$phases=[];$guard=resolutionGuard($e,$m,$phases);resolutionBegin($e);resolutionAudit($e,$m,'cancelled',$evidence);
    outboxRefused('outbox.reconciliation_state',static function()use($s,$m,$evidence,$guard):void{$s->reconcile($m,'admin','cancelled',$evidence,$guard);});$e->pdo->exec('ROLLBACK');Check::same(1,(int)$e->pdo->query('SELECT payload_present FROM sosecurity_outbox_records')->fetchColumn());
});}

resolutionCase($mysql,static function(OutboxEnvironment $e):void{
    list($s,$m)=resolutionRetired($e);$queries=$e->pdo->queries;$calls=0;$guard=static function()use(&$calls):bool{++$calls;return true;};
    foreach([['unknown',str_repeat('a',64)],['received',''],['received',str_repeat('a',65)],['received',str_repeat('a',63)."\0"]] as $bad){outboxRefused('configuration.outbox_resolution',static function()use($s,$m,$bad,$guard):void{$s->reconcile($m,'admin',$bad[0],$bad[1],$guard);});}
    Check::same($queries,$e->pdo->queries);Check::same(0,$calls);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s,$m,$guard):void{$s->reconcile($m,'admin','received',str_repeat('a',64),$guard);});Check::same(0,$calls);
});

// Reference-declaring policy callbacks cannot replace the internal binding or evidence.
resolutionCase($mysql,static function(OutboxEnvironment $e):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$base=resolutionGuard($e,$m,$phases);
    $guard=static function(&$phase,&$meta)use($base):bool{$result=$base($phase,$meta);$phase='forged';$meta=['outcome'=>'cancelled'];return $result;};
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);Check::same(true,$s->reconcile($m,'admin','received',$evidence,$guard));$e->pdo->exec('COMMIT');Check::same('received',$s->status('tenant','orders',$m->id(),'alice')->resolution());
});

foreach(['request','current','commit'] as $phase){resolutionCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$base=resolutionGuard($e,$m,$phases);
    $guard=static function(string $when,array $meta)use($base,$phase){if($when===$phase){return 1;}return $base($when,$meta);};
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);outboxRefused('outbox.denied',static function()use($s,$m,$evidence,$guard):void{$s->reconcile($m,'admin','received',$evidence,$guard);});$e->pdo->exec('ROLLBACK');Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());
});}
foreach(['current','commit'] as $phase){resolutionCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$base=resolutionGuard($e,$m,$phases);
    $guard=static function(string $when,array $meta)use($e,$base,$phase):bool{$allowed=$base($when,$meta);if($when===$phase){$e->pdo->exec("UPDATE sosecurity_outbox_records SET payload_body=CAST(x'00'||zeroblob(16777216) AS TEXT)");}return $allowed;};
    if($e->mysql){return;} // SQLite affinity/NUL adversarial value; MySQL's BLOB storage is separately covered.
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);Check::throws(StorageException::class,static function()use($s,$m,$evidence,$guard):void{$s->reconcile($m,'admin','received',$evidence,$guard);});$e->pdo->exec('ROLLBACK');Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());Check::same(true,memory_get_peak_usage(true)<8388608);
});}
resolutionCase($mysql,static function(OutboxEnvironment $e):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$base=resolutionGuard($e,$m,$phases);$until=$e->clock->time+1;
    $guard=static function(string $phase,array $meta)use($base,$e,$until):bool{if($phase==='commit'){++$e->clock->time;}return $base($phase,$meta)&&$e->clock->time<$until;};
    resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);outboxRefused('outbox.denied',static function()use($s,$m,$evidence,$guard):void{$s->reconcile($m,'admin','received',$evidence,$guard);});$e->pdo->exec('ROLLBACK');Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());
});

// A current/commit maintenance denial rolls back all purges, preserving the independent audit rows.
foreach(['current','commit'] as $phase){resolutionCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
    list($s,$m)=resolutionRetired($e);$second=$e->message('second-retired');$e->append($s,$second);$e->clock->time+=6;$s->maintain('tenant','orders','admin');
    foreach([$m,$second] as $message){$evidence=hash('sha256',$message->id());$phases=[];$guard=resolutionGuard($e,$message,$phases);resolutionBegin($e);resolutionAudit($e,$message,'cancelled',$evidence);$s->reconcile($message,'admin','cancelled',$evidence,$guard);$e->pdo->exec('COMMIT');}
    $e->clock->time+=2;$before=$e->pdo->query('SELECT revision FROM sosecurity_outbox_roots')->fetchColumn();$seen=[];
    $e->onManagement=static function(string $action,string $when,string $scope,string $producer,string $actor,array $meta)use($phase,$second,&$seen):bool{
        if($action==='purge_resolution'){$seen[]=$meta;return !($when===$phase&&$meta['id']===$second->id());}return true;
    };
    outboxRefused('outbox.denied',static function()use($s):void{$s->maintain('tenant','orders','admin');});Check::same(2,$e->count(true));Check::same($before,$e->pdo->query('SELECT revision FROM sosecurity_outbox_roots')->fetchColumn());
    Check::same('cancelled',$seen[0]['resolution']);Check::same(64,strlen($seen[0]['evidence_digest']));Check::same(64,strlen($seen[0]['payload_digest']));
    $e->onManagement=null;Check::same(2,$s->maintain('tenant','orders','admin')['purged']);Check::same(2,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());Check::same(2,(int)$e->pdo->query('SELECT format FROM sosecurity_outbox_roots')->fetchColumn());
});}

// Corrupt format/outcome/evidence bytes fail ordinary history verification, including after resolution.
foreach(["status='dead'",'format=1',"last_error='reconcile.unknown'","token_digest=''",'sent_at=1','payload_present=1'] as $change){resolutionCase($mysql,static function(OutboxEnvironment $e)use($change):void{
    list($s,$m)=resolutionRetired($e);$evidence=hash('sha256','evidence');$phases=[];$guard=resolutionGuard($e,$m,$phases);resolutionBegin($e);resolutionAudit($e,$m,'received',$evidence);$s->reconcile($m,'admin','received',$evidence,$guard);$e->pdo->exec('COMMIT');$e->pdo->exec('UPDATE sosecurity_outbox_records SET '.$change);
    Check::throws(StorageException::class,static function()use($s):void{$s->claim('tenant','orders','worker');});
});}

echo 'PASS SQL Outbox reconciliation: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; synthetic decisions, actual host audit transactions, terminal states, ordering and guarded GC\n";
