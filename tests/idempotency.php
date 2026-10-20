<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/idempotency-support.php';
use SoSecurity\Idempotency\Request;
use SoSecurity\Idempotency\Response;
use SoSecurity\Idempotency\Policy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1] ?? '')==='mysql';
function reason(string $reason,callable $body):void
{
    ++Check::$assertions;try{$body();}catch(SecurityException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected security refusal '.$reason);
}
foreach([['ttl'=>0],['maximum_entries'=>100001],['maximum_response_bytes'=>1048577],['io_milliseconds'=>30001],['unknown'=>1]] as $options){Check::throws(ConfigurationException::class,static function()use($options){new Policy($options);});}
$ttl=10;$p=new Policy(['ttl'=>&$ttl]);$ttl=0;Check::same(10,$p->ttl());$options=$p->options();$options['ttl']=0;Check::same(10,$p->ttl());
foreach([['GET','/orders'],['POST','https://untrusted.example/'],['POST',"/orders\r\n"],['POST','/orders#fragment']] as $case){Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($case){new Request('tenant','alice','orders.create','request-key-00000001',$case[0],$case[1],'{}');});}
Check::throws(SoSecurity\Exception\ValidationException::class,static function(){new Request('tenant','alice','orders.create','short','POST','/orders','{}');});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $queries=$e->pdo->queries;$s=$e->service();Check::same($queries,$e->pdo->queries);Check::same(0,$e->authorityCalls);Check::same(0,$e->managementCalls);
    reason('idempotency.uninitialized',static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same(0,$e->count());
    Check::same(true,$s->initialize('tenant','alice','orders.create'));Check::same(false,$s->initialize('tenant','alice','orders.create'));Check::same(null,$s->lookup($e->request()));
    $first=$s->execute($e->request(),$e->handler());Check::same(false,$first->replayed());Check::same(201,$first->response()->status());Check::same(32,strlen($first->executionId()));Check::same(1,$e->count());Check::same(1,$e->handlerCalls);
    $again=$s->execute($e->request(),$e->handler());Check::same(true,$again->replayed());Check::same($first->executionId(),$again->executionId());Check::same($first->response()->body(),$again->response()->body());Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
    Check::same(true,$e->service()->lookup($e->request())->replayed());
    reason('idempotency.conflict',static function()use($s,$e){$s->execute($e->request('request-key-00000001','changed'),$e->handler());});Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
    $e->allowed=false;Check::same(null,$s->lookup($e->request()));Check::same(null,$s->execute($e->request(),$e->handler()));Check::same(1,$e->handlerCalls);$e->allowed=true;
    $e->onAuthority=static function(string $phase):bool{return $phase!=='replay';};reason('idempotency.denied',static function()use($s,$e){$s->lookup($e->request());});Check::same(1,$e->count());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');
    Check::throws(DependencyException::class,static function()use($s,$e){$s->execute($e->request(),static function(PDO $pdo):Response{$pdo->exec("INSERT INTO idempotency_test_business VALUES('tenant','alice','order-1','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',5)");throw new RuntimeException('SYNTHETIC-HANDLER-SECRET');});});
    Check::same(0,$e->count());Check::same([],$e->records());Check::same(null,$s->lookup($e->request()));Check::same(false,$s->execute($e->request(),$e->handler())->replayed());Check::same(1,$e->count());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$original=$e->request();$s->execute($original,$e->handler());$seen=[];
    $e->onAuthority=static function(string $phase,Request $incoming,array $metadata)use(&$seen):bool{if($phase==='replay'){$seen[]=$metadata['fingerprint'];}return true;};$changed=$e->request('request-key-00000001','different-order');Check::same(false,$original->fingerprint()===$changed->fingerprint());
    reason('idempotency.conflict',static function()use($s,$e,$changed){$s->execute($changed,$e->handler());});Check::same([$original->fingerprint()],array_values(array_unique($seen)));Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$e->onAuthority=static function(string $phase):bool{return $phase!=='commit';};
    reason('idempotency.denied',static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same(0,$e->count());Check::same([],$e->records());$e->onAuthority=null;Check::same(false,$s->execute($e->request(),$e->handler())->replayed());Check::same(1,$e->count());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$e->onAuthority=static function(string $phase):bool{return $phase!=='return';};
    reason('idempotency.denied',static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same(1,$e->count());Check::same(1,$e->handlerCalls);$e->onAuthority=null;Check::same(true,$s->execute($e->request(),$e->handler())->replayed());Check::same(1,$e->handlerCalls);
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->clock->time+=2;
    reason('idempotency.expired',static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same(1,$e->handlerCalls);$rows=$e->records();Check::same('expired',$rows[0]['status']);Check::same('0',(string)$e->pdo->query('SELECT length(response_body) FROM sosecurity_idempotency_records')->fetchColumn());Check::same(1,$e->count());
    --$e->clock->time;Check::throws(StorageException::class,static function()use($s,$e){$s->lookup($e->request());});Check::throws(StorageException::class,static function()use($e){$e->service()->lookup($e->request());});
},new Policy(['ttl'=>2]));
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->clock->time+=2;
    $result=$s->maintain('tenant','alice','orders.create',1);Check::same(1,$result['scanned']);Check::same(1,$result['compacted']);Check::same(false,$result['complete']);Check::same(64,strlen($result['next_cursor']));
    $last=$s->maintain('tenant','alice','orders.create',1,$result['next_cursor']);Check::same(true,$last['complete']);Check::same(0,$last['scanned']);
    reason('idempotency.expired',static function()use($s,$e){$s->execute($e->request(),$e->handler());});reason('idempotency.capacity',static function()use($s,$e){$s->execute($e->request('request-key-00000002','order-2'),$e->handler());});Check::same(1,$e->handlerCalls);
},new Policy(['ttl'=>2,'maximum_entries'=>1]));
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$first=$s->execute($e->request(),$e->handler());
    $rotated=new SoSecurity\Support\HmacKeys('new',['old'=>str_repeat('i',32),'new'=>str_repeat('n',32)]);$next=$e->service($rotated);$stats=$next->maintain('tenant','alice','orders.create');Check::same(1,$stats['rekeyed']);
    $single=$e->service(new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32)]));Check::same($first->response()->body(),$single->lookup($e->request())->response()->body());Check::same(1,$e->handlerCalls);
});
foreach(['response_body','fingerprint','seal','status','response_bytes'] as $field){idemCase($mysql,static function(IdempotencyEnvironment $e)use($field){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());
    $values=['response_body'=>'forged-body','fingerprint'=>str_repeat('f',64),'seal'=>str_repeat('0',64),'status'=>'expired','response_bytes'=>'0'];$q=$e->pdo->prepare('UPDATE sosecurity_idempotency_records SET '.$field.'=:value');$q->execute(['value'=>$values[$field]]);
    Check::throws(StorageException::class,static function()use($s,$e){$s->lookup($e->request());});Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
});}
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->pdo->exec('DELETE FROM sosecurity_idempotency_records');
    reason('idempotency.history',static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same(1,$e->handlerCalls);
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->pdo->exec("UPDATE sosecurity_idempotency_records SET key_hash='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'");
    // Keep the row count unchanged. A sealed count alone cannot authenticate the absence of a completed key.
    reason('idempotency.history',static function()use($s,$e){$s->execute($e->request(),static function(PDO $pdo)use($e):Response{++$e->handlerCalls;$pdo->exec('UPDATE idempotency_test_business SET amount=amount+5');return new Response(200,'repeated');});});Check::same(1,$e->handlerCalls);Check::same('5',(string)$e->pdo->query('SELECT amount FROM idempotency_test_business')->fetchColumn());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->pdo->exec('DELETE FROM sosecurity_idempotency_roots');
    reason('idempotency.uninitialized',static function()use($s,$e){$s->execute($e->request(),$e->handler());});reason('idempotency.history',static function()use($s){$s->initialize('tenant','alice','orders.create');});Check::same(1,$e->handlerCalls);
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());
    Check::throws(ConfigurationException::class,static function()use($e){$e->service(null,null,null,null,str_repeat('f',64))->lookup($e->request());});
    Check::throws(ConfigurationException::class,static function()use($e){$e->service(null,null,null,null,null,new Policy(['ttl'=>10]))->lookup($e->request());});
    reason('idempotency.uninitialized',static function()use($e){$e->service(null,null,null,'other-site')->lookup($e->request());});
    $s->initialize('tenant','bob','orders.create');$other=$s->execute($e->request('request-key-00000001','order-1','tenant','bob'),$e->handler());Check::same(false,$other->replayed());Check::same(2,$e->count());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$result=$s->execute($e->request(),static function():Response{return new Response(422,'safe business rejection');});Check::same(422,$result->response()->status());Check::same(0,$e->count());
    Check::same(true,$s->execute($e->request(),static function(){throw new RuntimeException('MUST-NOT-RUN');})->replayed());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$request=new Request('tenant','alice','orders.create','request-key-00000001','POST','/binary',"\x00\xffpayload");$result=$s->execute($request,static function():Response{return new Response(200,"\x00\xffresult");});Check::same("\x00\xffresult",$result->response()->body());Check::same("\x00\xffresult",$s->lookup($request)->response()->body());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$result=$s->execute($e->request(),static function():Response{return new Response(204,'');});Check::same(204,$result->response()->status());Check::same('',$result->response()->body());Check::same('',$s->lookup($e->request())->response()->body());Check::same(true,$s->execute($e->request(),static function(){throw new RuntimeException('EMPTY-MUST-NOT-RUN');})->replayed());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');
    Check::throws(DependencyException::class,static function()use($s,$e){$s->execute($e->request(),static function(){return true;});});Check::same([],$e->records());
    $e->managed=false;Check::same(false,$s->initialize('other','alice','orders.create'));Check::same(null,$s->maintain('tenant','alice','orders.create'));Check::same(0,$e->count());
});
echo 'PASS SQL idempotency: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; component stage, not full R4.3 acceptance\n";
