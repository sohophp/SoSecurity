<?php
declare(strict_types=1);
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy;

function resolutionCase(bool $mysql,callable $work):void
{
    outboxCase($mysql,static function(OutboxEnvironment $e)use($work):void{
        $e->pdo->exec('DROP TABLE IF EXISTS outbox_test_decisions');
        $e->pdo->exec('CREATE TABLE outbox_test_decisions(event_id VARCHAR(96) NOT NULL PRIMARY KEY,fingerprint CHAR(64) NOT NULL,body_digest CHAR(64) NOT NULL,outcome VARCHAR(16) NOT NULL,evidence CHAR(64) NOT NULL)'.($e->mysql?' ENGINE=InnoDB':''));
        try{$work($e);}finally{try{$e->pdo->exec('ROLLBACK');}catch(Throwable $ignored){}$e->pdo->exec('DROP TABLE outbox_test_decisions');}
    },new Policy(['message_age'=>3,'recovery_age'=>6,'retention_seconds'=>2]));
}
function resolutionBegin(OutboxEnvironment $e):void {$e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');}
function resolutionAudit(OutboxEnvironment $e,Message $m,string $outcome,string $evidence):void
{
    $q=$e->pdo->prepare('INSERT INTO outbox_test_decisions VALUES(:id,:fingerprint,:digest,:outcome,:evidence)');$q->execute(['id'=>$m->id(),'fingerprint'=>$m->fingerprint(),'digest'=>hash('sha256',$m->body()),'outcome'=>$outcome,'evidence'=>$evidence]);$q->closeCursor();
}
/** Synthetic host evidence, real PDO visibility. This is not a signed remote receipt test. */
function resolutionGuard(OutboxEnvironment $e,Message $m,array &$phases):callable
{
    return static function(string $phase,array $meta)use($e,$m,&$phases):bool{
        $phases[]=$phase;
        if($meta['site']!=='outbox-test'||$meta['epoch']!==$e->epoch||$meta['scope']!==$m->scope()||$meta['producer']!==$m->producer()||$meta['actor']!=='admin'||$meta['id']!==$m->id()||$meta['fingerprint']!==$m->fingerprint()||$meta['payload_bytes']!==strlen($m->body())||$meta['payload_digest']!==hash('sha256',$m->body())||$meta['created_at']!==$m->createdAt()||$meta['destination']!==$m->destination()||$meta['topic']!==$m->topic()||$meta['aggregate']!==$m->aggregate()){return false;}
        $q=$e->pdo->prepare('SELECT 1 FROM outbox_test_decisions WHERE event_id=:id AND fingerprint=:fingerprint AND body_digest=:digest AND outcome=:outcome AND evidence=:evidence');$q->execute(['id'=>$meta['id'],'fingerprint'=>$meta['fingerprint'],'digest'=>$meta['payload_digest'],'outcome'=>$meta['outcome'],'evidence'=>$meta['evidence_digest']]);$found=$q->fetchColumn()!==false;$q->closeCursor();return $found;
    };
}
function resolutionRetired(OutboxEnvironment $e,bool $attempted=true):array
{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('retired',"a\0b\xff");$e->append($s,$m);$token=null;
    if($attempted){$claim=$s->claim('tenant','orders','worker');$token=$claim->token();$s->fail('tenant','orders','worker',$token,'transport.timeout',false);}
    $e->clock->time+=6;Check::same(1,$s->maintain('tenant','orders','admin')['retired']);return [$s,$m,$token];
}
