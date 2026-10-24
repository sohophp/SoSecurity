<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/outbox-support.php';
require __DIR__.'/idempotency-support.php';
require __DIR__.'/audit-sql-support.php';
use SoSecurity\Exception\ConfigurationException;
$mysql=($argv[1]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required');}
// Only initial enqueue, one initial claim and its known acknowledgment. No delivery or recovery.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
 $service=$e->service();Check::same(true,$service->initialize('tenant','orders','admin'));
 $status=$e->append($service,$e->message());Check::same(1,$status->order());Check::same(1,$e->count());
 $claim=$service->claim('tenant','orders','worker');Check::same($status->id(),$claim->status()->id());Check::same(true,$service->acknowledge('tenant','orders','worker',$claim->token()));
 $e->pdo->exec('CREATE UNIQUE INDEX owned_outbox_extra ON sosecurity_outbox_roots(policy)');
 Check::throws(ConfigurationException::class,static function()use($service):void{$service->initialize('tenant','other-orders','admin');});Check::same(1,$e->count());
});
// A complete known response may be looked up; an unknown result is never resumed.
idemCase($mysql,static function(IdempotencyEnvironment $e):void{
 $service=$e->service();Check::same(true,$service->initialize('tenant','alice','orders.create'));
 $first=$service->execute($e->request(),$e->handler());Check::same(false,$first->replayed());Check::same(201,$first->response()->status());Check::same(1,$e->handlerCalls);
 $known=$service->lookup($e->request());Check::same(true,$known->replayed());Check::same($first->executionId(),$known->executionId());Check::same(1,$e->handlerCalls);
 $e->pdo->exec('CREATE UNIQUE INDEX owned_idem_extra ON sosecurity_idempotency_roots(epoch)');
 Check::throws(ConfigurationException::class,static function()use($service):void{$service->initialize('tenant','bob','orders.create');});Check::same(1,$e->count());
});
$e=new AuditSqlEnvironment($mysql);
try{
 $sink=new SoSecurity\Audit\SqlSink($e->pdo,'owned-schema-audit',3,60,$e->clock);$sink->initialize();
 (new SoSecurity\Audit\AuditLogger($sink,str_repeat('k',32)))->record('owned.schema','tenant',null);Check::same(1,$e->count());
 $e->pdo->exec('CREATE UNIQUE INDEX owned_audit_extra ON sosecurity_audit_roots(policy)');
 Check::throws(ConfigurationException::class,static function()use($e):void{(new SoSecurity\Audit\SqlSink($e->pdo,'owned-schema-other',3,60,$e->clock))->initialize();});Check::same(1,$e->count());
}finally{$e->close();}
echo 'PASS private schema product consumers '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
