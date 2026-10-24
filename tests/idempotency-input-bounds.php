<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/idempotency-support.php';
use SoSecurity\Idempotency\Response;
use SoSecurity\Storage\StorageException;
$mysql=($argv[1] ?? '')==='mysql';
// Keep valid bytes and exactly-once local business effects, including NUL and non-UTF-8.
idemCase($mysql,static function(IdempotencyEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','alice','orders.create');
    $all='';for($byte=0;$byte<256;++$byte){$all.=chr($byte);}
    foreach(['',"\0","a\0b\xff",$all] as $index=>$body){
        $request=$e->request('binary-request-key-'.$index,'binary-'.$index);$calls=0;
        $handler=static function()use($body,&$calls):Response{++$calls;return new Response(200,$body);};
        Check::same($body,$s->execute($request,$handler)->response()->body());
        Check::same($body,$s->execute($request,$handler)->response()->body());Check::same(1,$calls);
    }
});
$fields=[
    'roots'=>['epoch','policy','history_digest','seal_key','seal'],
    'records'=>['key_hash','execution_id','epoch','policy','fingerprint','status','response_digest','seal_key','seal'],
];
foreach($fields as $table=>$names){foreach($names as $field){idemCase($mysql,static function(IdempotencyEnvironment $e)use($mysql,$table,$field):void{
    $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());
    $before=$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_idempotency_roots')->fetch(PDO::FETCH_ASSOC);
    $name='sosecurity_idempotency_'.$table;
    if($mysql){
        // Exact MySQL CHAR/VARBINARY declarations reject oversized metadata at write time.
        try{$e->pdo->exec('UPDATE '.$name.' SET '.$field."=REPEAT('a',16777216)");throw new RuntimeException('MySQL accepted oversized metadata.');}
        catch(PDOException $error){Check::same(1406,(int)$error->errorInfo[1]);}
        Check::same(true,$s->lookup($e->request())->replayed());
        $before['revision']=$e->pdo->query('SELECT revision FROM sosecurity_idempotency_roots')->fetchColumn();
        // In-range but invalid metadata still must be rejected by the authenticated reader.
        $e->pdo->exec('UPDATE '.$name.' SET '.$field."='bad'");
    }else{
        // Construct bytes within the SQL engine, never as a large PHP test string.
        $e->pdo->exec('UPDATE '.$name.' SET '.$field.'=hex(zeroblob(8388608))');
    }
    foreach(['lookup','execute','maintain'] as $method){
        Check::throws(StorageException::class,static function()use($s,$e,$method):void{
            if($method==='maintain'){$s->maintain('tenant','alice','orders.create');}
            elseif($method==='execute'){$s->execute($e->request(),$e->handler());}
            else{$s->lookup($e->request());}
        });
    }
    // No business callback, extra execution or root revision is committed by refused operations.
    Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
    Check::same(1,(int)$e->pdo->query('SELECT count(*) FROM sosecurity_idempotency_records')->fetchColumn());
    Check::same($before['revision'],$e->pdo->query('SELECT revision FROM sosecurity_idempotency_roots')->fetchColumn());
});}}
if(!$mysql){
    // CASE projection aliases must not replace the indexed physical pagination order.
    idemCase(false,static function(IdempotencyEnvironment $e):void{
        $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());$queries=[];
        $e->pdo->beforeStatement=static function(string $sql)use(&$queries):void{
            if(strpos($sql,'SELECT ')===0&&strpos($sql,'sosecurity_idempotency_records')!==false&&strpos($sql,'ORDER BY')!==false){$queries[$sql]=true;}
        };
        $s->lookup($e->request());$s->maintain('tenant','alice','orders.create');$e->pdo->beforeStatement=null;
        Check::same(2,count($queries));
        foreach(array_keys($queries) as $sql){
            preg_match_all('/:([a-z_]+)/',$sql,$matches);$parameters=[];foreach($matches[1] as $name){$parameters[$name]='';}
            $q=$e->pdo->prepare('EXPLAIN QUERY PLAN '.$sql);$q->execute($parameters);
            foreach($q->fetchAll(PDO::FETCH_ASSOC) as $row){Check::same(false,strpos($row['detail'],'TEMP B-TREE')!==false);}
        }
    });
    foreach(["CAST(x'00'||zeroblob(16777216) AS TEXT)","CAST('a'||x'00'||zeroblob(16777216) AS TEXT)","zeroblob(16777216)","CAST('bad' AS TEXT)"] as $expression){idemCase(false,static function(IdempotencyEnvironment $e)use($expression):void{
        $s=$e->service();$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());
        $e->pdo->exec('UPDATE sosecurity_idempotency_roots SET seal='.$expression);
        Check::throws(StorageException::class,static function()use($s,$e):void{$s->lookup($e->request());});
        Check::same(1,$e->handlerCalls);Check::same(1,$e->count());
    });}
    idemCase(false,static function(IdempotencyEnvironment $e):void{
        $s=$e->service();$s->initialize('tenant','alice','orders.create');$e->pdo->exec("UPDATE sosecurity_idempotency_roots SET revision='bad'");
        Check::throws(StorageException::class,static function()use($s,$e):void{$s->execute($e->request(),$e->handler());});Check::same(0,$e->handlerCalls);Check::same(0,$e->count());
    });
}
echo 'PHP '.PHP_VERSION.': '.Check::$assertions.' idempotency input-bound assertions passed ('.($mysql?'mysql':'sqlite').")\n";
