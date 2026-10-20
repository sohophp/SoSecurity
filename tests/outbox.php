<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/outbox-support.php';
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1] ?? '')==='mysql';
// Canonical event IDs preserve business reference/time; raw binary bodies and unknown settings are bounded.
Check::same(Message::identifier('order-1/version-2',100000),Message::identifier('order-1/version-2',100000));
foreach(['o1.00.'.str_repeat('a',64),'o1.-1.'.str_repeat('a',64),'o1.1.'.str_repeat('A',64),'o1.9223372036854775807.'.str_repeat('a',64)] as $id){Check::throws(ValidationException::class,static function()use($id):void{new Message('t','p',$id,'receiver','event','a','');});}
foreach([['unknown'=>1],['message_age'=>0],['recovery_age'=>1],['maximum_attempts'=>31],['maximum_manual_retries'=>11],['maximum_entries'=>0],['scan_limit'=>51],['maximum_backoff_seconds'=>1]] as $options){Check::throws(ConfigurationException::class,static function()use($options):void{new Policy($options);});}

outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $before=$e->pdo->queries;$s=$e->service();Check::same($before,$e->pdo->queries);$e->managed=false;Check::same(false,$s->initialize('tenant','orders','admin'));Check::same(0,$e->count());
    $e->managed=true;Check::same(true,$s->initialize('tenant','orders','admin'));Check::same(false,$s->initialize('tenant','orders','admin'));
    $calls=$e->calls;outboxRefused('configuration.transaction',static function()use($s,$e):void{$s->enqueue($e->message(),'alice');});Check::same($calls,$e->calls);Check::same(0,$e->count(true));
});
// Actual host commit/rollback, including SQL transactions hidden by old PDO; enqueue never sends or owns the host commit.
foreach(['native','manual'] as $mode){foreach([false,true] as $commit){outboxCase($mysql,static function(OutboxEnvironment $e)use($mode,$commit):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');if($mode==='native'){$e->pdo->beginTransaction();}else{$e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');}
    $e->pdo->exec('INSERT INTO outbox_test_business VALUES(1)');$status=$s->enqueue($e->message(),'alice');Check::same('pending',$status->state());Check::same(1,$status->order());Check::same(1,$e->count());Check::same(0,$e->count(true));Check::same(0,$e->business(true));
    $e->pdo->exec($commit?'COMMIT':'ROLLBACK');Check::same($commit?1:0,$e->count(true));Check::same($commit?1:0,$e->business(true));
    if(!$commit){Check::same(1,$e->append($s,$e->message())->order());}
});}}
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$a=$e->append($s,$m);$b=$e->append($s,$m);Check::same($a->deliveryId(),$b->deliveryId());Check::same(1,$b->order());Check::same(1,$e->count());
    foreach([new Message('tenant','orders',$m->id(),'receiver','order.changed','order-1','different'),new Message('tenant','orders',$m->id(),'other','order.changed','order-1',$m->body()),new Message('tenant','orders',$m->id(),'receiver','order.changed','other',$m->body())] as $changed){outboxRefused('outbox.conflict',static function()use($e,$s,$changed):void{$e->append($s,$changed);});}
    Check::same(1,$e->count());$seen=[];$e->onAuthority=static function(string $action,string $phase,string $scope,string $producer,string $actor,array $meta)use(&$seen):bool{if($action==='enqueue'&&$phase==='current'){$seen[]=$meta;}return true;};$m2=$e->message('event-2');$e->append($s,$m2);Check::same($m2->id(),$seen[0]['id']);Check::same($m2->fingerprint(),$seen[0]['fingerprint']);
    outboxRefused('outbox.conflict',static function()use($e,$s,$m):void{$e->append($s,new Message('tenant','orders',$m->id(),'receiver','order.changed','wrong','bad'));});Check::same('order-1',$seen[1]['aggregate']);Check::same($m->fingerprint(),$seen[1]['fingerprint']);
});
// Strict current authority rejects before local side effects and commit-phase withdrawal rolls them back.
foreach(['request','current','commit'] as $phase){outboxCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->onAuthority=static function(string $action,string $when)use($phase):bool{return $when!==$phase;};
    $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$e->pdo->exec('INSERT INTO outbox_test_business VALUES(1)');
    outboxRefused('outbox.denied',static function()use($e,$s):void{$s->enqueue($e->message(),'alice');});Check::same(0,$e->count());Check::same(1,$e->business());Check::same(0,$e->business(true));$e->pdo->exec('ROLLBACK');Check::same(0,$e->business(true));
});}
// Same-aggregate messages never overtake a lease; another aggregate can progress independently.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$first=$e->append($s,$e->message());$second=$e->append($s,$e->message('event-2'));$third=$e->append($s,$e->message('event-3','binary\x00','order-2'));
    $a=$s->claim('tenant','orders','worker-a');Check::same($first->id(),$a->message()->id());Check::same(132,strlen($a->token()));Check::same('leased',$a->status()->state());Check::same(1,$a->status()->attempts());Check::same(false,strpos(json_encode($e->rows()),$a->token())!==false);
    $b=$s->claim('tenant','orders','worker-b');Check::same($third->id(),$b->status()->id());Check::same(null,$s->claim('tenant','orders','worker-c'));
    Check::same(false,$s->acknowledge('tenant','orders','wrong-worker',$a->token()));Check::same(false,$s->acknowledge('tenant','orders','worker-a','malformed'));
    Check::same(true,$s->acknowledge('tenant','orders','worker-a',$a->token()));Check::same('sent',$s->status('tenant','orders',$first->id(),'alice')->state());Check::same('', $e->rows()[0]['payload_body'] ?? '');
    Check::same(true,$s->acknowledge('tenant','orders','worker-a',$a->token()));$c=$s->claim('tenant','orders','worker-c');Check::same($second->id(),$c->status()->id());Check::same(true,$s->acknowledge('tenant','orders','worker-c',$c->token()));Check::same(true,$s->acknowledge('tenant','orders','worker-b',$b->token()));
});
// An abandoned acknowledgment reuses delivery identity after lease recovery; old credentials cannot affect the new lease.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->append($s,$e->message());$old=$s->claim('tenant','orders','worker-a');++$e->clock->time;
    Check::same(false,$s->acknowledge('tenant','orders','worker-a',$old->token()));$new=$s->claim('tenant','orders','worker-b');Check::same($old->status()->deliveryId(),$new->status()->deliveryId());Check::same(false,$old->token()===$new->token());Check::same(2,$new->status()->attempts());
    Check::same(false,$s->acknowledge('tenant','orders','worker-a',$old->token()));Check::same(false,$s->fail('tenant','orders','worker-a',$old->token(),'transport.timeout'));Check::same(true,$s->acknowledge('tenant','orders','worker-b',$new->token()));$e->clock->time+=2;Check::same(true,$s->acknowledge('tenant','orders','worker-b',$new->token()));
},new Policy(['lease_seconds'=>1]));
// Backoff and finite automatic/manual retries; dead head blocks only its aggregate.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$c=$s->claim('tenant','orders','worker');Check::same(true,$s->fail('tenant','orders','worker',$c->token(),'transport.timeout'));Check::same(false,$s->fail('tenant','orders','worker',$c->token(),'transport.timeout'));Check::same(null,$s->claim('tenant','orders','worker'));
    $e->clock->time+=2;$c2=$s->claim('tenant','orders','worker');Check::same(2,$c2->status()->attempts());Check::same(true,$s->fail('tenant','orders','worker',$c2->token(),'transport.timeout'));Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());
    $e->append($s,$e->message('event-2'));$other=$e->append($s,$e->message('event-3','','other'));$free=$s->claim('tenant','orders','worker');Check::same($other->id(),$free->status()->id());$s->acknowledge('tenant','orders','worker',$free->token());Check::same(null,$s->claim('tenant','orders','worker'));
    $e->managed=false;Check::same(false,$s->retry('tenant','orders',$m->id(),'admin'));$e->managed=true;Check::same(true,$s->retry('tenant','orders',$m->id(),'admin'));$recovered=$s->claim('tenant','orders','worker');Check::same(3,$recovered->status()->attempts());Check::same($c->status()->deliveryId(),$recovered->status()->deliveryId());$s->fail('tenant','orders','worker',$recovered->token(),'transport.rejected',false);Check::same(false,$s->retry('tenant','orders',$m->id(),'admin'));
},new Policy(['maximum_attempts'=>2,'maximum_manual_retries'=>1,'backoff_seconds'=>2,'maximum_backoff_seconds'=>4]));
// Successful retention cleanup releases capacity, keeps increasing order and cannot revive the exact expired ID.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$old=$e->message();$e->append($s,$old);$c=$s->claim('tenant','orders','worker');$s->acknowledge('tenant','orders','worker',$c->token());
    outboxRefused('outbox.capacity',static function()use($e,$s):void{$e->append($s,$e->message('event-2'));});$e->clock->time+=3;$result=$s->maintain('tenant','orders','admin');Check::same(1,$result['purged']);Check::same(0,$e->count());
    outboxRefused('outbox.expired',static function()use($e,$s,$old):void{$e->append($s,$old);});$fresh=$e->append($s,$e->message('event-2'));Check::same(2,$fresh->order());
},new Policy(['message_age'=>3,'recovery_age'=>10,'retention_seconds'=>0,'lease_seconds'=>1,'maximum_entries'=>1]));
// Expired failures retire private payloads but keep a blocking tombstone; they are never treated as delivered.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$e->clock->time+=2;Check::same(null,$s->claim('tenant','orders','worker'));Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());
    Check::same(true,$s->retry('tenant','orders',$m->id(),'admin'));Check::same(true,$s->status('tenant','orders',$m->id(),'alice')->deliverUntil()>$e->clock->time);
    $e->clock->time+=8;$result=$s->maintain('tenant','orders','admin');Check::same(1,$result['retired']);Check::same(1,$e->count());Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());Check::same(0,(int)$e->rows()[0]['payload_present']);outboxRefused('outbox.expired',static function()use($s,$m):void{$s->retry('tenant','orders',$m->id(),'admin');});
},new Policy(['message_age'=>2,'recovery_age'=>10,'lease_seconds'=>1]));
// Binary/empty payloads work on old PDO; current authority and immutable debug/serialization boundaries remain real.
foreach(['',"\0\xff\x80secret"] as $body){outboxCase($mysql,static function(OutboxEnvironment $e)use($body):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('binary',$body);$e->append($s,$m);$c=$s->claim('tenant','orders','worker');Check::same($body,$c->message()->body());
    foreach([$s,$m,$c,$c->status()] as $object){Check::same('{}',json_encode($object));Check::same(false,strpos(print_r($object,true),'secret')!==false);Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});}
    $e->allowed=false;Check::same(false,$s->acknowledge('tenant','orders','worker',$c->token()));Check::same(null,$s->status('tenant','orders',$m->id(),'alice'));$e->allowed=true;Check::same(true,$s->acknowledge('tenant','orders','worker',$c->token()));
});}
// Key rotation verifies old data first, reseals records/root, then permits removing the old key.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$both=new SoSecurity\Support\HmacKeys('new',['old'=>str_repeat('o',32),'new'=>str_repeat('n',32)]);$new=$e->service($both);Check::same(1,$new->maintain('tenant','orders','admin')['rekeyed']);
    $only=$e->service(new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32)]));$c=$only->claim('tenant','orders','worker');Check::same($m->body(),$c->message()->body());Check::same(true,$only->acknowledge('tenant','orders','worker',$c->token()));
});
echo 'PASS SQL outbox core: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; core stage, native sender/receiver acceptance remains open\n";
