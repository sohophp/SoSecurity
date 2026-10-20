<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
$mysql=($argv[1] ?? '')==='mysql';
// Exercise the full byte range, rather than relying on UTF-8 or NUL alone.
// The accepted body fits exactly; appending one NUL must be refused before SQL.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');
    $body='';for($byte=0;$byte<256;++$byte){$body.=chr($byte);}
    $m=$e->message('all-bytes',$body);$e->append($s,$m);
    $queries=$e->pdo->queries;$calls=$e->calls;
    outboxRefused('outbox.payload',static function()use($e,$s,$body):void{$s->enqueue($e->message('all-bytes-over',$body."\0"),'alice');});
    Check::same($queries,$e->pdo->queries);Check::same($calls,$e->calls);
    Check::same(1,$e->count(true));
    $claim=$s->claimMessage('tenant','orders','worker',$m->id());
    Check::same($body,$claim->message()->body());
    Check::same(hash('sha256',$body),hash('sha256',$claim->message()->body()));
    Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
},new SoSecurity\Outbox\Policy(['maximum_payload_bytes'=>256]));
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$body="a\0b\xff";
    $accepted=$e->message('exact-limit',$body,str_repeat('x',256));$e->append($s,$accepted);
    $claim=$s->claim('tenant','orders','worker');Check::same($body,$claim->message()->body());Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    outboxRefused('outbox.payload',static function()use($e,$s):void{$e->append($s,$e->message('over-policy',"ab\0cd"));});Check::same(1,$e->count());
    $queries=$e->pdo->queries;
    Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($e):void{$e->message('over-hard-limit',str_repeat('x',1048577));});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($e):void{$e->message('over-label','',str_repeat('x',257));});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($e):void{$e->message('nul-label','',"a\0b");});
    Check::same($queries,$e->pdo->queries);Check::same(1,$e->count());
},new SoSecurity\Outbox\Policy(['maximum_payload_bytes'=>4]));
// Boundaries count bytes, including leading/trailing NUL and multi-byte UTF-8.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');
    foreach(['',"\0","\0abc","abc\0","a\0b\xff","界\0"] as $index=>$body){
        $m=$e->message('binary-'.$index,$body);$e->append($s,$m);
        $claim=$s->claimMessage('tenant','orders','worker',$m->id());
        Check::same($body,$claim->message()->body());
        Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    }
    $before=$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
    foreach(["\0abcd","abcd\0","界ab"] as $index=>$body){
        $m=$e->message('rejected-'.$index,$body);$queries=$e->pdo->queries;$calls=$e->calls;
        outboxRefused('outbox.payload',static function()use($s,$m):void{$s->enqueue($m,'alice');});
        Check::same($queries,$e->pdo->queries);Check::same($calls,$e->calls);
    }
    Check::same($before,$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));
    Check::same(6,$e->count(true));
    // Rejection neither commits nor aborts an existing host transaction.
    $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
    try{
        $e->pdo->exec('INSERT INTO outbox_test_business(id) VALUES(1)');$queries=$e->pdo->queries;
        outboxRefused('outbox.payload',static function()use($s,$e):void{$s->enqueue($e->message('host-rejected',"ab\0cd"),'alice');});
        Check::same($queries,$e->pdo->queries);Check::same(0,$e->business(true));
        $e->pdo->exec('COMMIT');
    }catch(Throwable $error){$e->pdo->exec('ROLLBACK');throw $error;}
    Check::same(1,$e->business(true));Check::same(6,$e->count(true));
},new SoSecurity\Outbox\Policy(['maximum_payload_bytes'=>4]));
outboxCase($mysql,static function(OutboxEnvironment $e)use($mysql):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->append($s,$e->message());
    $revision=$e->pdo->query('SELECT revision FROM sosecurity_outbox_roots')->fetchColumn();
    $e->pdo->exec('UPDATE sosecurity_outbox_records SET payload_body='.($mysql?"REPEAT(CHAR(0),2097152)":'zeroblob(2097152)'));
    foreach([static function()use($s):void{$s->claim('tenant','orders','worker');},static function()use($s):void{$s->candidates('tenant','orders','alice');},static function()use($s):void{$s->maintain('tenant','orders','admin');}] as $operation){Check::throws(SoSecurity\Storage\StorageException::class,$operation);}
    Check::same(1,$e->count());Check::same('pending',$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same(0,(int)$e->pdo->query('SELECT attempts FROM sosecurity_outbox_records')->fetchColumn());
    Check::same($revision,$e->pdo->query('SELECT revision FROM sosecurity_outbox_roots')->fetchColumn());Check::same(true,memory_get_peak_usage(true)<8388608);
});
// A rejected message must leave the host free to enqueue valid binary data and
// atomically commit or roll back that data together with its own business write.
foreach([false,true] as $commit){outboxCase($mysql,static function(OutboxEnvironment $e)use($commit):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');
    $root=$e->observer->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
    $body="\0ab\0";$accepted=$e->message('after-rejection',$body);
    $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
    try{
        $e->pdo->exec('INSERT INTO outbox_test_business(id) VALUES(1)');
        $queries=$e->pdo->queries;$calls=$e->calls;
        outboxRefused('outbox.payload',static function()use($e,$s):void{$s->enqueue($e->message('rejected',"\0abc\0"),'alice');});
        Check::same($queries,$e->pdo->queries);Check::same($calls,$e->calls);
        $s->enqueue($accepted,'alice');
        Check::same(1,$e->business());Check::same(1,$e->count());
        Check::same(0,$e->business(true));Check::same(0,$e->count(true));
        Check::same($root,$e->observer->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));
        $e->pdo->exec($commit?'COMMIT':'ROLLBACK');
    }catch(Throwable $error){$e->pdo->exec('ROLLBACK');throw $error;}
    Check::same($commit?1:0,$e->business(true));Check::same($commit?1:0,$e->count(true));
    if($commit){
        $claim=$s->claim('tenant','orders','worker');Check::same($body,$claim->message()->body());
        Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    }else{
        Check::same($root,$e->observer->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));
        Check::same(null,$s->claim('tenant','orders','worker'));
    }
},new SoSecurity\Outbox\Policy(['maximum_payload_bytes'=>4]));}
// UTF-8 metadata limits count bytes, rather than characters or bytes before NUL.
outboxCase($mysql,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');
    $aggregate=str_repeat('界',85).'x';Check::same(256,strlen($aggregate));
    $m=$e->message('utf8-exact',"a\0b",$aggregate);$e->append($s,$m);
    $claim=$s->claimMessage('tenant','orders','worker',$m->id());
    Check::same($aggregate,$claim->message()->aggregate());Check::same("a\0b",$claim->message()->body());
    Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    $root=$e->observer->query('SELECT * FROM sosecurity_outbox_roots')->fetchAll(PDO::FETCH_ASSOC);
    $queries=$e->pdo->queries;$calls=$e->calls;
    foreach([$aggregate.'x',str_repeat('界',86),"valid\0hidden"] as $invalid){
        Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($e,$invalid):void{$e->message('utf8-rejected','',$invalid);});
        Check::same($queries,$e->pdo->queries);Check::same($calls,$e->calls);
    }
    Check::same($root,$e->observer->query('SELECT * FROM sosecurity_outbox_roots')->fetchAll(PDO::FETCH_ASSOC));
    Check::same(1,$e->count(true));
});
// Mutate after authenticated metadata was read but before the separate body query.
// Generate oversized data inside SQL so the test itself never allocates it in PHP.
// Equal-length binary replacement must also fail: a size guard cannot replace
// checking the authenticated digest of every byte, including bytes after NUL.
$expressions=$mysql?["REPEAT(CHAR(0),2097152)","UNHEX('006162')","UNHEX('610162')","UNHEX('610063')"]:['zeroblob(16777216)',"CAST(x'00'||zeroblob(16777216) AS TEXT)","CAST('a'||x'00'||zeroblob(16777216) AS TEXT)","x'006162'","x'610162'","x'610063'"];
foreach($expressions as $expression){foreach(['claim','status','maintain'] as $action){
    outboxCase($mysql,static function(OutboxEnvironment $e)use($expression,$action):void{
        $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('late-body',"a\0b");$e->append($s,$m);
        $root=$e->observer->query('SELECT * FROM sosecurity_outbox_roots')->fetchAll(PDO::FETCH_ASSOC);
        $records=$e->observer->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC);
        $injected=false;$length=SoSecurity\Support\SqlSchema::blobLength($e->mysql?'mysql':'sqlite','payload_body');
        $e->pdo->beforeStatement=static function(string $sql)use($e,$expression,$length,&$injected):void{
            if(!$injected&&strpos($sql,' AND '.$length.'=:bytes')!==false){
                $injected=true;$e->pdo->exec('UPDATE sosecurity_outbox_records SET payload_body='.$expression);
            }
        };
        outboxRefused('outbox.corrupt',static function()use($s,$m,$action):void{
            if($action==='status'){$s->status('tenant','orders',$m->id(),'alice');}
            else{$s->$action('tenant','orders','admin');}
        });
        $e->pdo->beforeStatement=null;Check::same(true,$injected);
        Check::same($root,$e->observer->query('SELECT * FROM sosecurity_outbox_roots')->fetchAll(PDO::FETCH_ASSOC));
        Check::same($records,$e->observer->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC));
        Check::same(true,memory_get_peak_usage(true)<8388608);
        $claim=$s->claimMessage('tenant','orders','worker',$m->id());Check::same("a\0b",$claim->message()->body());
        Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    });
}}
echo 'PASS SQL outbox input bounds: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."\n";
