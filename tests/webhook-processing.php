<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Webhook\SqlProcessor;
use SoSecurity\Webhook\ProcessingPolicy;
use SoSecurity\Webhook\Message;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1] ?? '')==='mysql';
function processingCase(bool $mysql,callable $body):void
{
    $e=new InboxEnvironment($mysql);try{
        $e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');
        $schema=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql');foreach(explode(';',$schema) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
        $e->pdo->exec('DROP TABLE IF EXISTS webhook_test_effects');$e->pdo->exec('CREATE TABLE webhook_test_effects(receipt_id CHAR(32) NOT NULL PRIMARY KEY,resource_id VARCHAR(64) NOT NULL,version VARCHAR(64) NOT NULL)'.($mysql?' ENGINE=InnoDB':''));
        $body($e);
    }finally{if($mysql){$e->pdo->exec('DROP TABLE IF EXISTS webhook_test_effects');$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');}$e->close();}
}
function processor(InboxEnvironment $e,?ProcessingPolicy $policy=null,?callable $association=null,?callable $worker=null,?callable $management=null):SqlProcessor
{
    return new SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(string $body){$data=json_decode($body,true);return new Message($data['id'],$data['type'],$data['resource'],['version'=>$data['version']]);},$association ?? static function(){return true;},$worker ?? static function(){return true;},$policy,$e->clock,$management);
}
function effect(int &$calls):callable
{
    return static function(PDO $pdo,Message $message,string $payload,$status)use(&$calls):bool{++$calls;$query=$pdo->prepare('INSERT INTO webhook_test_effects(receipt_id,resource_id,version) VALUES(:receipt,:resource,:version)');$query->execute(['receipt'=>$status->receiptId(),'resource'=>$message->resource(),'version'=>$message->context()['version']]);return true;};
}
function effectCount(InboxEnvironment $e):int {return (int)$e->pdo->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn();}

Check::throws(ConfigurationException::class,static function(){new ProcessingPolicy(['maximum_attempts'=>0]);});
Check::throws(ConfigurationException::class,static function(){new ProcessingPolicy(['backoff'=>['bad'=>1]]);});
Check::throws(ConfigurationException::class,static function(){new ProcessingPolicy(['backoff'=>[5,1]]);});
$delay=1;$input=['backoff'=>[&$delay]];$policy=new ProcessingPolicy($input);$fp=$policy->fingerprint();$delay=900;Check::same($fp,$policy->fingerprint());Check::same(1,$policy->retryDelay(1));
processingCase($mysql,static function(InboxEnvironment $e){
    $queries=$e->pdo->queries;$s=processor($e);Check::same($queries,$e->pdo->queries);Check::same([], $s->pending('worker')['receipt_ids']);$receipt=$e->receive();$id=$receipt->id();Check::same([$id],$s->pending('worker')['receipt_ids']);Check::same(null,$s->status($id,'worker'));
    $claim=$s->claim($id,'worker');Check::same('leased',$claim->metadata()->status());Check::same(1,$claim->metadata()->attempt());Check::same(null,$s->claim($id,'worker'));Check::same(null,$s->claim($id,'other'));Check::same([], $s->pending('worker')['receipt_ids']);
    $calls=0;Check::same(null,$s->execute('other',$claim->token(),effect($calls)));Check::same(0,$calls);$done=$s->execute('worker',$claim->token(),effect($calls));Check::same('succeeded',$done->status());Check::same(1,$calls);Check::same(1,effectCount($e));
    Check::same(null,$s->execute('worker',$claim->token(),effect($calls)));Check::same(1,$calls);Check::same(null,$s->claim($id,'worker'));Check::same('succeeded',processor($e)->status($id,'worker')->status());Check::same(null,$s->retry($id,'admin'));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e,new ProcessingPolicy(['maximum_attempts'=>2]),null,null,static function(){return true;});$id=$e->receive()->id();$claim=$s->claim($id,'worker');$calls=0;
    Check::throws(DependencyException::class,static function()use($s,$claim,&$calls){$s->execute('worker',$claim->token(),static function(PDO $pdo)use(&$calls){++$calls;$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");throw new RuntimeException('PRIVATE-HANDLER-SECRET');});});Check::same(0,effectCount($e));Check::same('leased',$s->status($id,'worker')->status());
    $retry=$s->fail('worker',$claim->token(),'provider.busy');Check::same('retry',$retry->status());Check::same(100001,$retry->availableAt());Check::same(null,$s->claim($id,'worker'));Check::same(null,$s->fail('worker',$claim->token(),'provider.busy'));
    ++$e->clock->time;$second=$s->claim($id,'worker');Check::same(2,$second->metadata()->attempt());Check::same('dead',$s->fail('worker',$second->token(),'provider.busy')->status());Check::same(null,$s->claim($id,'worker'));Check::same('retry',$s->retry($id,'admin')->status());$third=$s->claim($id,'worker');Check::same(1,$third->metadata()->attempt());Check::same(3,$third->metadata()->toArray()['total_attempts']);Check::same(1,$third->metadata()->toArray()['manual_retries']);Check::same('succeeded',$s->execute('worker',$third->token(),effect($calls))->status());Check::same(1,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e,new ProcessingPolicy(['lease_seconds'=>2]));$id=$e->receive()->id();$first=$s->claim($id,'worker');$e->clock->time+=2;$second=$s->claim($id,'other');$calls=0;Check::same(null,$s->execute('worker',$first->token(),effect($calls)));Check::same(null,$s->fail('worker',$first->token(),'stale'));Check::same(0,$calls);Check::same('succeeded',$s->execute('other',$second->token(),effect($calls))->status());Check::same(1,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e,new ProcessingPolicy(['lease_seconds'=>2]));$id=$e->receive()->id();$claim=$s->claim($id,'worker');
    Check::throws(SecurityException::class,static function()use($s,$e,$claim){$s->execute('worker',$claim->token(),static function(PDO $pdo)use($e):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$e->clock->time+=2;return true;});});Check::same(0,effectCount($e));Check::same('leased',$s->status($id,'worker')->status());Check::same(null,$s->execute('worker',$claim->token(),static function(){throw new RuntimeException('MUST-NOT-RUN');}));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $allowed=true;$guard=static function()use(&$allowed){return $allowed;};$s=processor($e,null,$guard);$id=$e->receive()->id();$claim=$s->claim($id,'worker');
    Check::throws(SecurityException::class,static function()use($s,$claim,&$allowed){$s->execute('worker',$claim->token(),static function(PDO $pdo)use(&$allowed):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$allowed=false;return true;});});Check::same(0,effectCount($e));Check::same(null,$s->status($id,'worker'));$allowed=true;Check::same('leased',$s->status($id,'worker')->status());
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');$calls=0;
    $e->pdo->beforeCommit=static function()use($e){$e->clock->time+=61;};
    Check::throws(SecurityException::class,static function()use($s,$claim,&$calls){$s->execute('worker',$claim->token(),effect($calls));});$e->pdo->beforeCommit=null;Check::same(1,effectCount($e));Check::same('succeeded',$s->status($id,'worker')->status());Check::same(null,$s->execute('worker',$claim->token(),effect($calls)));Check::same(1,$calls);
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');$calls=0;
    $e->pdo->exec("UPDATE sosecurity_webhook_processing SET status='succeeded'");Check::throws(StorageException::class,static function()use($s,$claim,&$calls){$s->execute('worker',$claim->token(),effect($calls));});Check::same(0,$calls);Check::same(0,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$e->pdo->exec("UPDATE sosecurity_webhook_inbox SET payload='corrupt'");Check::throws(StorageException::class,static function()use($s,$id){$s->claim($id,'worker');});Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$e->pdo->beginTransaction();$e->pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");Check::throws(ConfigurationException::class,static function()use($s,$id){$s->claim($id,'worker');});Check::same(true,$e->pdo->inTransaction());$e->pdo->rollBack();Check::same(0,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$queries=$e->pdo->queries;
    foreach([false,1,'1',null] as $denied){$s=processor($e,null,null,static function()use($denied){return $denied;});Check::same(null,$s->claim($id,'worker'));Check::same([], $s->pending('worker')['receipt_ids']);}
    Check::same($queries,$e->pdo->queries);Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$s=processor($e,new ProcessingPolicy(['maximum_attempts'=>1,'maximum_manual_retries'=>1]),null,null,static function(){return true;});$claim=$s->claim($id,'worker');
    Check::same('dead',$s->fail('worker',$claim->token(),'rejected',false)->status());Check::same('retry',$s->retry($id,'admin')->status());$again=$s->claim($id,'worker');Check::same('dead',$s->fail('worker',$again->token(),'rejected')->status());Check::same(null,$s->retry($id,'admin'));Check::same(2,$s->status($id,'worker')->toArray()['total_attempts']);
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$s=processor($e);$claim=$s->claim($id,'worker');$calls=0;
    Check::throws(SecurityException::class,static function()use($s,$claim){$s->execute('worker',$claim->token(),static function(PDO $pdo):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");return false;});});Check::same(0,effectCount($e));Check::same('leased',$s->status($id,'worker')->status());
    Check::throws(DependencyException::class,static function()use($s,$claim,$id){$s->execute('worker',$claim->token(),static function(PDO $pdo)use($s,$id):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$s->claim($id,'other');return true;});});Check::same(0,effectCount($e));
    Check::same('succeeded',$s->execute('worker',$claim->token(),effect($calls))->status());Check::same(1,$calls);
});
processingCase($mysql,static function(InboxEnvironment $e){
    $receipt=$e->receive();$s=processor($e);$calls=0;
    $other=new SqlProcessor($e->pdo,'another-site',$e->endpoint,$e->seals,static function(){throw new RuntimeException('MUST-NOT-MAP');},static function(){return true;},static function(){return true;},null,$e->clock);
    Check::same(null,$other->claim($receipt->id(),'worker'));Check::same([], $other->pending('worker')['receipt_ids']);Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());
    $claim=$s->claim($receipt->id(),'worker');Check::same(null,$s->execute('worker','wc1.'.$receipt->id().'.2.'.str_repeat('0',64),effect($calls)));Check::same(0,$calls);Check::same(1,$s->status($receipt->id(),'worker')->attempt());
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$s=processor($e);$claim=$s->claim($id,'worker');$calls=0;
    Check::throws(StorageException::class,static function()use($e,$id){processor($e,new ProcessingPolicy(['maximum_attempts'=>1]))->claim($id,'worker');});
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$context=null;$e->keyOnline=false;$e->clock->time+=1000;
    $s=processor($e,null,static function($endpoint,$message,$phase,$provenance)use(&$context){$context=$provenance;return true;});$claim=$s->claim($id,'worker');Check::same('leased',$claim->metadata()->status());Check::same(['receipt_id'=>$id,'received_at'=>100000,'source_key'=>'test','source_time'=>100000],$context);
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$s=processor($e);$e->pdo->exec($e->mysql?'DROP INDEX sosecurity_webhook_pending ON sosecurity_webhook_processing':'DROP INDEX sosecurity_webhook_pending');Check::throws(ConfigurationException::class,static function()use($s,$id){$s->claim($id,'worker');});Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());
});
processingCase($mysql,static function(InboxEnvironment $e){
    if($e->mysql){return;}$s=processor($e);$id=$e->receive()->id();$e->pdo->exec('BEGIN IMMEDIATE');$e->pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");Check::throws($e->pdo->inTransaction()?ConfigurationException::class:StorageException::class,static function()use($s,$id){$s->claim($id,'worker');});Check::same(1,effectCount($e));$e->pdo->exec('ROLLBACK');Check::same(0,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');$calls=0;$batch=$s->pending('worker',1);Check::same([],$batch['receipt_ids']);Check::same($id,$batch['next_cursor']);Check::same(false,$batch['complete']);$end=$s->pending('worker',1,$batch['next_cursor']);Check::same([],$end['receipt_ids']);Check::same(true,$end['complete']);
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e,new ProcessingPolicy(['maximum_attempts'=>20,'maximum_manual_retries'=>8,'backoff'=>[1]]),null,null,static function(){return true;});$id=$e->receive()->id();
    for($total=1;$total<=100;++$total){$claim=$s->claim($id,'worker');Check::same($total,$claim->metadata()->toArray()['total_attempts']);$status=$s->fail('worker',$claim->token(),'provider.retry');
        if($status->status()==='dead'){if($total<100){Check::same('retry',$s->retry($id,'admin')->status());}else{Check::same(null,$s->retry($id,'admin'));}}
        else{$e->clock->time=$status->availableAt();}
    }
    Check::same(100,$s->status($id,'worker')->toArray()['total_attempts']);Check::same('dead',$s->status($id,'worker')->status());Check::same(null,$s->claim($id,'worker'));Check::same(0,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');
    Check::same('{}',json_encode($claim));Check::same(false,strpos(print_r($claim,true),$claim->token())!==false);Check::throws(ConfigurationException::class,static function()use($claim){serialize($claim);});
    Check::throws(StorageException::class,static function()use($s,$claim){$s->execute('worker',$claim->token(),static function(PDO $pdo):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$pdo->exec('DELETE FROM sosecurity_webhook_inbox');return true;});});Check::same(0,effectCount($e));Check::same(1,$e->count());Check::same('leased',$s->status($id,'worker')->status());
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$receipt=$e->receive();$claim=$s->claim($receipt->id(),'worker');$calls=0;Check::same('succeeded',$s->execute('worker',$claim->token(),effect($calls))->status());
    $e->pdo->exec('DELETE FROM sosecurity_webhook_inbox');$new=$e->receive();Check::same(false,$new->id()===$receipt->id());Check::throws(StorageException::class,static function()use($s,$new){$s->claim($new->id(),'worker');});Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());Check::same(1,effectCount($e));Check::same(1,$calls);
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$seen=[];$other=new SoSecurity\Webhook\Endpoint('different','other','other-account','https://other.example/events','standard-hmac');
    $mapper=static function(string &$payload,SoSecurity\Webhook\Endpoint &$endpoint,string &$receipt)use($other){$data=json_decode($payload,true);$payload='CHANGED-BY-REFERENCE';$endpoint=$other;$receipt=str_repeat('0',32);return new Message($data['id'],$data['type'],$data['resource'],['version'=>$data['version']]);};
    $association=static function(SoSecurity\Webhook\Endpoint &$endpoint,Message &$message,string &$phase,array &$provenance)use($other,&$seen):bool{$seen[]=[$endpoint->account(),$provenance];$endpoint=$other;$provenance['source_key']='changed';$message=new Message('different','other.event','other');$phase='changed';return true;};
    $worker=static function(string &$operation,SoSecurity\Webhook\Endpoint &$endpoint,string &$receipt,string &$name)use($other):bool{$endpoint=$other;$receipt=str_repeat('0',32);$name='different';$operation='changed';return true;};
    $s=new SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,$mapper,$association,$worker,null,$e->clock);$claim=$s->claim($id,'worker');
    $status=$s->execute('worker',$claim->token(),static function(PDO &$pdo,Message &$message,string &$payload,$status):bool{$q=$pdo->prepare('INSERT INTO webhook_test_effects VALUES(:receipt,:resource,:version)');$q->execute(['receipt'=>$status->receiptId(),'resource'=>$message->resource(),'version'=>$message->context()['version']]);$pdo=$pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'?new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only'):new PDO('sqlite::memory:');$message=new Message('different','other.event','other');$payload='CHANGED-BY-REFERENCE';return true;});
    Check::same('succeeded',$status->status());Check::same(1,effectCount($e));foreach($seen as $snapshot){Check::same('provider-account',$snapshot[0]);Check::same($id,$snapshot[1]['receipt_id']);Check::same('test',$snapshot[1]['source_key']);}
});
processingCase($mysql,static function(InboxEnvironment $e){
    $body=json_encode(['type'=>'document.changed','resource'=>'a','version'=>'1','account'=>'provider-account']);
    $receipt=$e->inbox->accept($e->request($body),static function($proof){$data=json_decode($proof->body(),true);return new Message($proof->messageId(),$data['type'],$data['resource'],['version'=>$data['version']]);});
    $metadataSeen=[];$mapper=static function(string $raw,$endpoint,string $receiptId,array &$metadata)use(&$metadataSeen){$data=json_decode($raw,true);$metadataSeen[]=$metadata;$id=$metadata['message_id'];$metadata['message_id']='changed';return new Message($id,$data['type'],$data['resource'],['version'=>$data['version']]);};
    $s=new SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,$mapper,static function(){return true;},static function(){return true;},null,$e->clock);$claim=$s->claim($receipt->id(),'worker');$calls=0;Check::same('succeeded',$s->execute('worker',$claim->token(),effect($calls))->status());Check::same(1,$calls);
    foreach($metadataSeen as $metadata){Check::same('msg_test',$metadata['message_id']);Check::same('document.changed',$metadata['type']);Check::same('a',$metadata['resource']);Check::same(100000,$metadata['received_at']);Check::same('test',$metadata['source_key']);Check::same(100000,$metadata['source_time']);}
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');
    Check::throws(StorageException::class,static function()use($s,$claim){$s->execute('worker',$claim->token(),static function(PDO $pdo):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$pdo->exec('COMMIT');return true;});});
    // The forbidden host COMMIT already happened. Stop this service instance; never claim it was rolled back.
    Check::same(1,effectCount($e));Check::same('leased',$e->pdo->query('SELECT status FROM sosecurity_webhook_processing')->fetchColumn());Check::throws(StorageException::class,static function()use($s,$id){$s->claim($id,'worker');});
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');
    Check::throws(StorageException::class,static function()use($s,$claim){$s->execute('worker',$claim->token(),static function(PDO $pdo):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$pdo->exec('COMMIT');$pdo->exec($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'?'START TRANSACTION':'BEGIN IMMEDIATE');$pdo->exec("INSERT INTO webhook_test_effects VALUES('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','a','1')");throw new RuntimeException('PRIVATE-TRANSACTION-CONTRACT-ERROR');});});
    Check::same(2,effectCount($e));$observer=$e->mysql?new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only'):new PDO('sqlite:'.$e->database);Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn());$observer=null;$e->pdo->exec('ROLLBACK');Check::same(1,effectCount($e));Check::same('leased',$e->pdo->query('SELECT status FROM sosecurity_webhook_processing')->fetchColumn());
});
processingCase($mysql,static function(InboxEnvironment $e){
    $id=$e->receive()->id();$mapper=static function(string $raw)use($e){$e->pdo->exec('COMMIT');$data=json_decode($raw,true);return new Message($data['id'],$data['type'],$data['resource'],['version'=>$data['version']]);};$s=new SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,$mapper,static function(){return true;},static function(){return true;},null,$e->clock);
    Check::throws(StorageException::class,static function()use($s,$id){$s->claim($id,'worker');});Check::same('ready',$e->pdo->query('SELECT status FROM sosecurity_webhook_processing')->fetchColumn());Check::same(0,effectCount($e));
});
processingCase($mysql,static function(InboxEnvironment $e){
    $s=processor($e);$id=$e->receive()->id();$claim=$s->claim($id,'worker');
    Check::throws(StorageException::class,static function()use($s,$claim){$s->execute('worker',$claim->token(),static function(PDO $pdo):bool{$pdo->exec("INSERT INTO webhook_test_effects VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','a','1')");$pdo->exec('ROLLBACK');return true;});});Check::same(0,effectCount($e));Check::same('leased',$e->pdo->query('SELECT status FROM sosecurity_webhook_processing')->fetchColumn());
});
echo 'PASS webhook SQL processing: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; local component stage, not a complete R4.3 gate\n";
