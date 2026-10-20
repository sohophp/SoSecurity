<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/idempotency-support.php';
use SoSecurity\Idempotency\Policy;
use SoSecurity\Idempotency\Request;
use SoSecurity\Idempotency\Response;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1] ?? '')==='mysql';
function refused(string $reason,callable $operation):void
{
    ++Check::$assertions;try{$operation();}catch(SecurityException $error){Check::same($reason,$error->reason());return;}catch(ConfigurationException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected '.$reason);
}
// Actual host writes must remain pending, including SQL-started transactions invisible to old PDO.
foreach(['native','sql'] as $mode){idemCase($mysql,static function(IdempotencyEnvironment $e)use($mode){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$calls=$e->authorityCalls;$management=$e->managementCalls;
    if($mode==='native'){$e->pdo->beginTransaction();}else{$e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');}
    $e->pdo->exec("INSERT INTO idempotency_test_business VALUES('tenant','alice','host-pending','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',9)");
    foreach([static function()use($s,$e){$s->execute($e->request(),$e->handler());},static function()use($s){$s->initialize('tenant','alice','orders.create');},static function()use($s){$s->maintain('tenant','alice','orders.create');}] as $operation){refused('configuration.transaction',$operation);}
    Check::same($calls,$e->authorityCalls);Check::same($management,$e->managementCalls);Check::same(0,$e->handlerCalls);Check::same(1,$e->count());
    // An independent real connection sees no host write, then sees it only after the host explicitly commits.
    $observer=$e->mysql?new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]):new PDO('sqlite:'.$e->database);
    Check::same('0',(string)$observer->query('SELECT COUNT(*) FROM idempotency_test_business')->fetchColumn());
    if($mode==='native'){$e->pdo->commit();}else{$e->pdo->exec('COMMIT');}
    Check::same('1',(string)$observer->query('SELECT COUNT(*) FROM idempotency_test_business')->fetchColumn());Check::same(false,$s->execute($e->request(),$e->handler())->replayed());Check::same(2,$e->count());
});}
if($mysql){idemCase(true,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$calls=$e->authorityCalls;$e->pdo->exec('SET autocommit=0');
    try{refused('configuration.transaction',static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same($calls,$e->authorityCalls);}finally{$e->pdo->exec('ROLLBACK');$e->pdo->exec('SET autocommit=1');}
});}
// Parameter identity includes exact method, target/query and trusted server bindings, independent of array order.
if($mysql){idemCase(true,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$writerConnection=new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $writer=new SoSecurity\Idempotency\SqlExecutor($writerConnection,'idem-test',$e->epoch,$e->keys,static function():bool{return true;},$e->policy,$e->clock);$created=null;
    $e->pdo->afterExec=static function(string $sql)use($e,$writer,&$created):void{if(strpos($sql,'SAVEPOINT sosecurity_unit_')!==0){return;}$e->pdo->afterExec=null;
        // Establish an old REPEATABLE READ snapshot before the second connection commits the same key.
        Check::same('0',(string)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_idempotency_records')->fetchColumn());$created=$writer->execute($e->request(),$e->handler());
    };
    $replayed=$s->execute($e->request(),$e->handler());Check::same(true,$replayed->replayed());Check::same($created->executionId(),$replayed->executionId());Check::same($created->response()->body(),$replayed->response()->body());Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
});}
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$original=$e->request();
    foreach([['PATCH','/orders',$original->bindings()],['POST','/orders?expand=1',$original->bindings()],['POST','/orders',['content_type'=>'text/plain']]] as $change){$request=new Request('tenant','alice','orders.create',$original->key(),$change[0],$change[1],$original->body(),$change[2]);refused('idempotency.conflict',static function()use($s,$e,$request){$s->execute($request,$e->handler());});}
    Check::same(1,$e->handlerCalls);$value='one';$request=new Request('tenant','alice','orders.create','request-key-00000002','POST','/orders','{}',['z'=>&$value,'a'=>'two']);$fingerprint=$request->fingerprint();$value='changed';Check::same('one',$request->bindings()['z']);Check::same($fingerprint,(new Request('tenant','alice','orders.create','request-key-00000002','POST','/orders','{}',['a'=>'two','z'=>'one']))->fingerprint());
});
// A trusted callback may use reference parameters, but cannot replace internal dependencies or execution identity.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service(null,static function(&$phase,&$request,&$metadata):bool{$phase='overwritten';$request=null;$metadata=['execution_id'=>'forged'];return true;});$s->initialize('tenant','alice','orders.create');$expected=null;
    $result=$s->execute($e->request(),static function(&$pdo,&$request,&$execution)use(&$expected):Response{$expected=$execution;$pdo=null;$request=null;$execution='changed';return new Response(201,'saved');});
    Check::same($expected,$result->executionId());Check::same('saved',$s->lookup($e->request())->response()->body());Check::same(0,$e->count());
});
// Time/clock failures after a real business write must not prevent rollback of our known-owned transaction.
foreach(['budget','clock'] as $failure){idemCase($mysql,static function(IdempotencyEnvironment $e)use($failure){
    $s=$e->service();$e->initializeTimingFixture();$handler=$e->handler();
    Check::throws(StorageException::class,static function()use($s,$e,$handler,$failure){$s->execute($e->request(),static function(PDO $pdo,Request $request,string $execution)use($e,$handler,$failure):Response{$response=$handler($pdo,$request,$execution);if($failure==='budget'){usleep(350000);}else{--$e->clock->time;}return $response;});});
    Check::same(0,$e->count());Check::same([],$e->records());if($failure==='clock'){++$e->clock->time;}Check::same(false,$s->execute($e->request(),$e->handler())->replayed());Check::same(1,$e->count());
},new Policy(['io_milliseconds'=>250]));}
// A callback cannot secretly commit, roll back, replace the transaction, or disguise it with an exception.
foreach(['COMMIT','ROLLBACK'] as $ending){foreach([false,true] as $throws){idemCase($mysql,static function(IdempotencyEnvironment $e)use($ending,$throws){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$handler=$e->handler();
    refused('sql.cleanup',static function()use($s,$e,$handler,$ending,$throws){$s->execute($e->request(),static function(PDO $pdo,Request $request,string $execution)use($e,$handler,$ending,$throws):Response{$response=$handler($pdo,$request,$execution);$pdo->exec($ending);$pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$pdo->exec("INSERT INTO idempotency_test_business VALUES('tenant','alice','replacement','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',7)");if($throws){throw new RuntimeException('SYNTHETIC-PRIVATE-EXCEPTION');}return $response;});});
    Check::same($ending==='COMMIT'?2:1,$e->count());refused('sql.cleanup',static function()use($s,$e){$s->lookup($e->request());});
    // The replacement transaction belongs to the host and must not have been rolled back by service cleanup.
    $e->pdo->exec('ROLLBACK');Check::same($ending==='COMMIT'?1:0,$e->count());$e->reconnect();
    if($ending==='COMMIT'){refused('idempotency.uncertain',static function()use($e){$e->service()->execute($e->request(),$e->handler());});}else{Check::same(false,$e->service()->execute($e->request(),$e->handler())->replayed());}
});}}
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$handler=$e->handler();
    refused('sql.cleanup',static function()use($s,$e,$handler){$s->execute($e->request(),static function(PDO $pdo,Request $request,string $execution)use($handler,$e):Response{$handler($pdo,$request,$execution);$e->pdo->failRollback=true;throw new RuntimeException('PRIVATE');});});
    Check::same(1,$e->count());refused('sql.cleanup',static function()use($s,$e){$s->lookup($e->request());});$e->pdo->failRollback=false;$e->pdo->exec('ROLLBACK');Check::same(0,$e->count());$e->reconnect();Check::same(false,$e->service()->execute($e->request(),$e->handler())->replayed());
});
// An uncertain COMMIT must never automatically retry the business callback.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$e->pdo->afterCommit=static function(){throw new RuntimeException('SIMULATED-LOST-COMMIT-ACK');};
    refused('sql.cleanup',static function()use($s,$e){$s->execute($e->request(),$e->handler());});$e->pdo->afterCommit=null;Check::same(1,$e->count());Check::same(1,$e->handlerCalls);refused('sql.cleanup',static function()use($s,$e){$s->lookup($e->request());});Check::same(true,$e->service()->execute($e->request(),$e->handler())->replayed());Check::same(1,$e->handlerCalls);
});
// Refuse oversized responses before committing business writes, including a one-byte response budget.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$handler=$e->handler();refused('idempotency.handler_response',static function()use($s,$e,$handler){$s->execute($e->request(),static function(PDO $pdo,Request $request,string $execution)use($handler):Response{$handler($pdo,$request,$execution);return new Response(200,'large');});});Check::same(0,$e->count());Check::same([],$e->records());
},new Policy(['maximum_response_bytes'=>1]));
foreach([1,'yes',null] as $answer){idemCase($mysql,static function(IdempotencyEnvironment $e)use($answer){
    $s=$e->service(null,static function()use($answer){return $answer;});$s->initialize('tenant','alice','orders.create');Check::same(null,$s->execute($e->request(),$e->handler()));Check::same(0,$e->handlerCalls);Check::same([],$e->records());
});}
// No auto-DDL or schema repair. Triggered/altered state tables and relaxed durability are explicit failures.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$e->pdo->exec('DROP TABLE sosecurity_idempotency_records');Check::throws(StorageException::class,static function()use($s){$s->initialize('tenant','alice','orders.create');});Check::throws(PDOException::class,static function()use($e){$e->pdo->query('SELECT 1 FROM sosecurity_idempotency_records');});Check::same(0,$e->count());
});
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$e->pdo->exec('CREATE TRIGGER idempotency_test_trigger BEFORE INSERT ON sosecurity_idempotency_records '.($e->mysql?'FOR EACH ROW SET NEW.status_code=0':'BEGIN SELECT 1; END'));
    try{refused('configuration.sql_schema',static function()use($s){$s->initialize('tenant','alice','orders.create');});}finally{$e->pdo->exec('DROP TRIGGER idempotency_test_trigger');}
    Check::same(true,$s->initialize('tenant','alice','orders.create'));Check::same(0,$e->count());
});
if(!$mysql){idemCase(false,static function(IdempotencyEnvironment $e){
    $s=$e->service();$e->pdo->exec('PRAGMA synchronous=OFF');refused('configuration.sql_durability',static function()use($s){$s->initialize('tenant','alice','orders.create');});$e->pdo->exec('PRAGMA synchronous=FULL');Check::same(true,$s->initialize('tenant','alice','orders.create'));
});}
if(!$mysql){foreach(['temporary-trigger','partial-index'] as $badSchema){idemCase(false,static function(IdempotencyEnvironment $e)use($badSchema){
    if($badSchema==='temporary-trigger'){$e->pdo->exec('CREATE TEMP TRIGGER idempotency_test_trigger BEFORE INSERT ON main.sosecurity_idempotency_records BEGIN SELECT 1; END');}
    else{$e->pdo->exec('DROP INDEX sosecurity_idempotency_execution');$e->pdo->exec("CREATE UNIQUE INDEX sosecurity_idempotency_execution ON sosecurity_idempotency_records(execution_id) WHERE status='done'");}
    refused('configuration.sql_schema',static function()use($e){$e->service()->initialize('tenant','alice','orders.create');});Check::same(0,$e->count());
});}}
// Authentication before replay does not permit returning a body changed by that authorization callback.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->onAuthority=static function(string $phase)use($e):bool{if($phase==='replay'){$e->pdo->exec("UPDATE sosecurity_idempotency_records SET response_body='forged'");}return true;};Check::throws(StorageException::class,static function()use($s,$e){$s->lookup($e->request());});$e->onAuthority=null;Check::same(true,$s->lookup($e->request())->replayed());Check::same(1,$e->count());
});
// Secrets captured by authority/handler objects never appear in supported object debug or serialization.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $secret='SYNTHETIC-IDEMPOTENCY-PRIVATE';$s=$e->service(null,static function()use($secret):bool{return $secret!=='';});$s->initialize('tenant','alice','orders.create');$request=new Request('tenant','alice','orders.create','request-key-00000001','POST','/orders',$secret);$outcome=$s->execute($request,static function()use($secret):Response{return new Response(200,$secret);});
    foreach([$s,$request,$outcome,$outcome->response()] as $object){Check::same(false,strpos(print_r($object,true),$secret)!==false);ob_start();var_dump($object);$debug=ob_get_clean();Check::same(false,strpos($debug,$secret)!==false);Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object){serialize($object);});}
});
// Persist expiry observed after a confirmed commit, even when the current authority denies or throws.
foreach(['execute','lookup'] as $operation){foreach(['allow','deny','throw'] as $completion){idemCase($mysql,static function(IdempotencyEnvironment $e)use($operation,$completion){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');if($operation==='lookup'){$s->execute($e->request(),$e->handler());}
    $e->onAuthority=static function(string $phase)use($e,$completion):bool{if($phase==='return'){$e->clock->time=100002;if($completion==='throw'){throw new RuntimeException('PRIVATE-LATE-AUTHORITY');}return $completion==='allow';}return true;};
    refused($completion==='throw'?'idempotency.authority':'idempotency.expired',static function()use($s,$e,$operation){if($operation==='execute'){$s->execute($e->request(),$e->handler());}else{$s->lookup($e->request());}});
    Check::same(1,$e->count());Check::same(1,$e->handlerCalls);Check::same('expired',$e->records()[0]['status']);Check::same('0',(string)$e->pdo->query('SELECT length(response_body) FROM sosecurity_idempotency_records')->fetchColumn());$e->onAuthority=null;$e->clock->time=100001;
    Check::throws(StorageException::class,static function()use($e){$e->service()->lookup($e->request());});
},new Policy(['ttl'=>2]));}}
// A completion timeout cannot renew the original SQL budget or execute the business a second time.
idemCase($mysql,static function(IdempotencyEnvironment $e){
    $s=$e->service();$e->initializeTimingFixture();$e->onAuthority=static function(string $phase):bool{if($phase==='return'){usleep(350000);}return true;};
    Check::throws(StorageException::class,static function()use($s,$e){$s->execute($e->request(),$e->handler());});Check::same(1,$e->count());Check::same(1,$e->handlerCalls);$e->onAuthority=null;Check::same(true,$s->execute($e->request(),$e->handler())->replayed());Check::same(1,$e->handlerCalls);
},new Policy(['io_milliseconds'=>250]));
echo 'PASS SQL idempotency safety: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; owned SQL component stage\n";
