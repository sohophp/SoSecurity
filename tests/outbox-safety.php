<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Outbox\Policy;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ConfigurationException;

$mysql=($argv[1] ?? '')==='mysql';
// Real storage corruption hidden by candidate predicates must never become an eligible/confirmed message.
foreach(['delete','body','state','empty-key','extra','missing-root'] as $fault){outboxCase($mysql,static function(OutboxEnvironment $e)use($fault):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);
    if($fault==='delete'){$e->pdo->exec('DELETE FROM sosecurity_outbox_records');}
    elseif($fault==='missing-root'){$e->pdo->exec('DELETE FROM sosecurity_outbox_roots');}
    elseif($fault==='body'){$q=$e->pdo->prepare('UPDATE sosecurity_outbox_records SET payload_body=:body');$q->bindValue(':body',str_repeat('x',strlen($m->body())),PDO::PARAM_LOB);$q->execute();}
    elseif($fault==='state'){$e->pdo->exec("UPDATE sosecurity_outbox_records SET status='sent'");}
    elseif($fault==='empty-key'){$e->pdo->exec("UPDATE sosecurity_outbox_records SET key_hash=''");}
    else{$columns=array_keys($e->rows()[0]);$values=array_map(static function(string $name):string{if($name==='key_hash'){return "''";}if($name==='order_no'){return '2';}return $name;},$columns);$e->pdo->exec('INSERT INTO sosecurity_outbox_records('.implode(',',$columns).') SELECT '.implode(',',$values).' FROM sosecurity_outbox_records');}
    Check::throws(StorageException::class,static function()use($s):void{$s->claim('tenant','orders','worker');});Check::throws(StorageException::class,static function()use($s,$m):void{$s->status('tenant','orders',$m->id(),'alice');});
});}
// Current callbacks cannot silently bless deleted history or altered bodies when the root is resealed.
foreach(['current','commit'] as $phase){outboxCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->append($s,$e->message());$e->onAuthority=static function(string $action,string $when)use($e,$phase):bool{if($action==='enqueue'&&$when===$phase){$e->pdo->exec('DELETE FROM sosecurity_outbox_records WHERE order_no=1');}return true;};
    Check::throws(StorageException::class,static function()use($e,$s):void{$e->append($s,$e->message('event-2'));});$e->onAuthority=null;Check::same(1,$e->count());Check::same(1,$s->status('tenant','orders',$e->message()->id(),'alice')->order());
});}
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$e->onAuthority=static function(string $action,string $phase)use($e,$m):bool{if($action==='claim'&&$phase==='commit'){$q=$e->pdo->prepare('UPDATE sosecurity_outbox_records SET payload_body=:body');$q->bindValue(':body',str_repeat('x',strlen($m->body())),PDO::PARAM_LOB);$q->execute();}return true;};
    Check::throws(StorageException::class,static function()use($s):void{$s->claim('tenant','orders','worker');});$e->onAuthority=null;Check::same(0,$s->status('tenant','orders',$m->id(),'alice')->attempts());Check::same($m->body(),$s->claim('tenant','orders','worker')->message()->body());
});
// Expiry during commit/return never exposes an expired lease; late settlement cannot commit success.
foreach(['commit','return'] as $phase){outboxCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$e->onAuthority=static function(string $action,string $when)use($e,$phase):bool{if($action==='claim'&&$when===$phase){++$e->clock->time;}return true;};
    outboxRefused('outbox.lease',static function()use($s):void{$s->claim('tenant','orders','worker');});$e->onAuthority=null;$status=$s->status('tenant','orders',$m->id(),'alice');Check::same($phase==='commit'?0:1,$status->attempts());$new=$s->claim('tenant','orders','next-worker');Check::same($phase==='commit'?1:2,$new->status()->attempts());
},new Policy(['lease_seconds'=>1]));}
foreach(['acknowledge','fail'] as $action){outboxCase($mysql,static function(OutboxEnvironment $e)use($action):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$claim=$s->claim('tenant','orders','worker');$e->onAuthority=static function(string $whenAction,string $phase)use($e,$action):bool{if($whenAction===$action&&$phase==='commit'){++$e->clock->time;}return true;};
    outboxRefused('outbox.lease',static function()use($s,$claim,$action):void{if($action==='acknowledge'){$s->acknowledge('tenant','orders','worker',$claim->token());}else{$s->fail('tenant','orders','worker',$claim->token(),'transport.timeout');}});
    $e->onAuthority=null;Check::same('leased',$s->status('tenant','orders',$m->id(),'alice')->state());Check::same(false,$s->acknowledge('tenant','orders','worker',$claim->token()));
},new Policy(['lease_seconds'=>1]));}
// Constructor/management identity changes are explicit failures; schema and durability are never repaired implicitly.
foreach(['site','epoch','policy','key'] as $change){outboxCase($mysql,static function(OutboxEnvironment $e)use($change):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);
    $changed=$e->service($change==='key'?new SoSecurity\Support\HmacKeys('wrong',['wrong'=>str_repeat('w',32)]):null,null,null,$change==='site'?'another':null,$change==='epoch'?str_repeat('f',64):null,$change==='policy'?new Policy(['lease_seconds'=>61]):null);
    Check::throws($change==='epoch'||$change==='policy'?ConfigurationException::class:StorageException::class,static function()use($changed):void{$changed->claim('tenant','orders','worker');});Check::same(1,$e->count());
});}
foreach(['missing','trigger','index'] as $change){outboxCase($mysql,static function(OutboxEnvironment $e)use($change):void{
    if($change==='missing'){$e->pdo->exec('DROP TABLE sosecurity_outbox_records');}
    elseif($change==='trigger'){$e->pdo->exec('CREATE TRIGGER outbox_test_trigger BEFORE INSERT ON sosecurity_outbox_records '.($e->mysql?'FOR EACH ROW SET NEW.attempts=0':'BEGIN SELECT 1; END'));}
    else{$e->pdo->exec(($e->mysql?'ALTER TABLE sosecurity_outbox_records DROP INDEX ':'DROP INDEX ').'sosecurity_outbox_order');}
    try{Check::throws($change==='missing'?StorageException::class:ConfigurationException::class,static function()use($e):void{$e->service()->initialize('tenant','orders','admin');});Check::same(0,$e->business());}finally{if($change==='trigger'){$e->pdo->exec('DROP TRIGGER outbox_test_trigger');}}
});}
// Reference-declaring callbacks receive copies of scope/actor/metadata, never the internal row or connection.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service(null,static function(&$action,&$phase,&$scope,&$producer,&$actor,&$metadata):bool{$action='forged';$phase='changed';$scope=null;$producer=null;$actor=null;$metadata=['id'=>'forged'];return true;});$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$c=$s->claimMessage('tenant','orders','worker',$m->id());Check::same($m->id(),$c->message()->id());Check::same(true,$s->acknowledge('tenant','orders','worker',$c->token()));
});
// Candidate pages expose actual order cursors; a bounded first scan must not starve unrelated work beyond that page.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$a=$e->message();$e->append($s,$a);$held=$s->claim('tenant','orders','worker-a');$e->append($s,$e->message('blocked'));$other=$e->message('free','','other');$e->append($s,$other);
    $page=$s->candidates('tenant','orders','worker-b',2);Check::same(2,count($page['records']));Check::same(2,$page['next_cursor']);Check::same(false,$page['complete']);$tail=$s->candidates('tenant','orders','worker-b',2,$page['next_cursor']);Check::same(3,$tail['next_cursor']);Check::same(true,$tail['complete']);Check::same($other->id(),$tail['records'][0]->id());
    Check::same(null,$s->claimMessage('tenant','orders','worker-b',$e->message('blocked')->id()));$c=$s->claimMessage('tenant','orders','worker-b',$other->id());Check::same($other->id(),$c->status()->id());Check::same(true,$s->acknowledge('tenant','orders','worker-b',$c->token()));Check::same(true,$s->acknowledge('tenant','orders','worker-a',$held->token()));
},new Policy(['scan_limit'=>1]));
// Cumulative attempt budget cannot be reset by manual retries, process replacement or automatic lease recovery.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message();$e->append($s,$m);$delivery=null;
    for($attempt=1;$attempt<=100;++$attempt){
        $c=$s->claim('tenant','orders','worker');Check::same($attempt,$c->status()->attempts());if($delivery===null){$delivery=$c->status()->deliveryId();}Check::same($delivery,$c->status()->deliveryId());Check::same(true,$s->fail('tenant','orders','worker',$c->token(),'transport.timeout'));++$e->clock->time;
        if($attempt<100&&$attempt%30===0){Check::same(true,$s->retry('tenant','orders',$m->id(),'admin'));}
    }
    Check::same('dead',$s->status('tenant','orders',$m->id(),'alice')->state());Check::same(false,$s->retry('tenant','orders',$m->id(),'admin'));Check::same(null,$s->claim('tenant','orders','worker'));Check::same(100,(int)$e->rows()[0]['generation']);
},new Policy(['maximum_attempts'=>30,'maximum_manual_retries'=>10,'backoff_seconds'=>1,'maximum_backoff_seconds'=>1,'message_age'=>1000,'recovery_age'=>1000]));
echo 'PASS SQL outbox safety: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; core safety stage, not complete R4.3\n";
