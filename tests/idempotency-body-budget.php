<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/idempotency-support.php';
// The actual stored value exceeds this process's 8 MiB PHP limit. Only SQL length metadata may be loaded first.
idemCase(false,static function(IdempotencyEnvironment $e){
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$e->pdo->exec('UPDATE sosecurity_idempotency_records SET response_body=zeroblob(16777216)');
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s,$e){$s->lookup($e->request());});Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s){$s->maintain('tenant','alice','orders.create');});Check::same(1,$e->count());Check::same(1,$e->handlerCalls);Check::same(true,memory_get_peak_usage(true)<8388608);
});
// SQLite BLOB affinity can be bypassed with TEXT. TEXT length stops at NUL: reject its actual type before fetching.
foreach(["CAST(x'00'||zeroblob(16777216) AS TEXT)","CAST('' AS TEXT)","CAST('abcd'||x'00'||zeroblob(16777216) AS TEXT)"] as $expression){idemCase(false,static function(IdempotencyEnvironment $e)use($expression):void{
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),static function():SoSecurity\Idempotency\Response{return new SoSecurity\Idempotency\Response(204,'');});$e->pdo->exec('UPDATE sosecurity_idempotency_records SET response_body='.$expression);
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s,$e):void{$s->lookup($e->request());});Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s):void{$s->maintain('tenant','alice','orders.create');});Check::same(0,$e->handlerCalls);Check::same(0,$e->count());Check::same(true,memory_get_peak_usage(true)<8388608);
});}
echo 'PASS SQL idempotency BLOB bound: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; 16 MiB BLOB/NUL-prefixed TEXT and wrong SQLite storage class rejected under memory_limit=8M\n";
