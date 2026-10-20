<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
$mysql=($argv[1] ?? '')==='mysql';
// Keep this positive large-payload case separate from the 8 MiB corrupt-read tests.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');
    $body="\0".str_repeat('x',1048574)."\0";
    $message=$e->message('hard-exact',$body);$e->append($s,$message);
    $claim=$s->claim('tenant','orders','worker');
    Check::same(1048576,strlen($claim->message()->body()));
    Check::same($body,$claim->message()->body());
    Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    $root=$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
    $queries=$e->pdo->queries;$calls=$e->calls;
    Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($e):void{
        $e->message('hard-over',"\0".str_repeat('x',1048575)."\0");
    });
    Check::same($queries,$e->pdo->queries);Check::same($calls,$e->calls);
    Check::same($root,$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));
    Check::same(1,$e->count());
},new SoSecurity\Outbox\Policy(['maximum_payload_bytes'=>1048576]));
echo 'PASS SQL outbox hard payload limit: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."\n";
