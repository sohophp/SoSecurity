<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Webhook\Message;
use SoSecurity\Webhook\Request;
$mysql=($argv[1] ?? '')==='mysql';
foreach([['','event','a'],['x','Event','a'],['x','event',''],['x','event',"bad\n"]] as $values){Check::throws(ValidationException::class,static function()use($values){new Message(...$values);});}
foreach([['bad'=>[]],['bad'=>1.2],['bad'=>str_repeat('x',257)],[0=>'x'],['x'=>"bad\x00"]] as $context){Check::throws(ValidationException::class,static function()use($context){new Message('x','event','a',$context);});}
$version='1';$message=new Message('x','event','a',['version'=>&$version]);$version='2';Check::same(['version'=>'1'],$message->context());Check::same((new Message('x','event','a',['b'=>1,'a'=>true]))->fingerprint(),(new Message('x','event','a',['a'=>true,'b'=>1]))->fingerprint());
inboxCase($mysql,static function(InboxEnvironment $e){
    $before=$e->pdo->queries;$service=$e->service();Check::same($before,$e->pdo->queries);$receipt=$e->receive();Check::same(false,$receipt->duplicate());Check::same(100000,$receipt->receivedAt());Check::same(1,$e->count());Check::same('msg_test',$receipt->messageId());Check::same(hash('sha256',$e->body()),$receipt->bodyDigest());
    $row=$e->snapshot()[0];Check::same($e->body(),$row['payload']);Check::same('test',$row['source_key']);Check::same(100000,(int)$row['source_time']);Check::same('{}',json_encode($receipt));Check::same(false,strpos(json_encode($receipt->toArray()),$e->body())!==false);Check::throws(ConfigurationException::class,static function()use($receipt){$receipt->id='changed';});
    $e->clock->time+=1;$again=$e->receive();Check::same(true,$again->duplicate());Check::same($receipt->id(),$again->id());Check::same(100000,$again->receivedAt());Check::same(1,$e->count());$next=$e->snapshot()[0];Check::same(100001,(int)$next['seen_at']);Check::same(100000,(int)$next['source_time']);Check::same(false,hash_equals($row['seal'],$next['seal']));
    foreach([$e->inbox] as $object){Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object){serialize($object);});Check::same(false,strpos(print_r($object,true),str_repeat('s',32))!==false);}
});
inboxCase($mysql,static function(InboxEnvironment $e){$e->receive();$before=$e->snapshot();Check::throws(SecurityException::class,static function()use($e){$e->receive($e->request($e->body(['resource'=>'b'])));});Check::same($before,$e->snapshot());Check::same(1,$e->count());});
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->pdo->exec('DROP TABLE sosecurity_webhook_inbox');$e->keyOnline=false;Check::same(null,$e->receive());Check::same(0,$e->mapCalls);Check::same(0,$e->associationCalls);$e->keyOnline=true;Check::throws($e->mysql?StorageException::class:ConfigurationException::class,static function()use($e){$e->receive();});$e->install();Check::same(false,$e->receive()->duplicate());
});
foreach([false,1,null] as $deny){inboxCase($mysql,static function(InboxEnvironment $e)use($deny){$e->association=$deny;Check::same(null,$e->receive());Check::same(0,$e->count());});}
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->onAssociation=static function(){throw new RuntimeException('PRIVATE-ASSOCIATION');};try{$e->receive();throw new LogicException('Expected association failure.');}catch(DependencyException $error){Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}Check::same(0,$e->count());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    foreach([static function(){return new stdClass();},static function(){throw new RuntimeException('PRIVATE-MAPPER');}] as $mapper){Check::throws(DependencyException::class,static function()use($e,$mapper){$e->inbox->accept($e->request(),$mapper);});}Check::same(0,$e->count());Check::same(null,$e->receive($e->request('{bad')));Check::same(null,$e->receive($e->request($e->body(['account'=>'another-account']))));Check::same(null,$e->receive($e->request($e->body(['resource'=>'missing']))));Check::same(0,$e->count());
});
inboxCase($mysql,static function(InboxEnvironment $e){Check::same(null,$e->inbox->accept($e->request(),static function(){return new Message('different','document.changed','a',['version'=>'1']);}));Check::same(0,$e->count());});
inboxCase($mysql,static function(InboxEnvironment $e){
    $first=$e->receive();Check::same(false,$first->duplicate());$second=$e->receive($e->request(null,null,['X-GitHub-Delivery'=>'changed-id','X-GitHub-Event'=>'changed-type']));Check::same(true,$second->duplicate());Check::same($first->id(),$second->id());Check::same('body:'.hash('sha256',$e->body()),$first->messageId());Check::same(null,$e->snapshot()[0]['source_time']);Check::same(null,$e->inbox->accept($e->request(),static function(){return new Message('forged-delivery-id','document.changed','a',['version'=>'1']);}));Check::same(1,$e->count());
},'github-sha256');
inboxCase($mysql,static function(InboxEnvironment $e){Check::same(false,$e->receive()->duplicate());Check::same(null,$e->inbox->accept($e->request(),static function(){return new Message('msg_test','another.type','a',['version'=>'1']);}));Check::same(null,$e->receive($e->request($e->body(['account'=>'another-account']))));Check::same(1,$e->count());},'stripe-v1');
inboxCase($mysql,static function(InboxEnvironment $e){$e->onKey=static function(int $calls)use($e){if($calls===5){$e->keyOnline=false;}};Check::same(null,$e->receive());Check::same(0,$e->count());$e->onKey=null;$e->keyOnline=true;Check::same(false,$e->receive()->duplicate());});
inboxCase($mysql,static function(InboxEnvironment $e){$e->onAssociation=static function(int $calls)use($e){if($calls===2){$e->association=false;}};Check::same(null,$e->receive());Check::same(0,$e->count());$e->onAssociation=null;$e->association=true;Check::same(false,$e->receive()->duplicate());});
inboxCase($mysql,static function(InboxEnvironment $e){$e->pdo->beginTransaction();try{Check::throws(ConfigurationException::class,static function()use($e){$e->receive();});Check::same(true,$e->pdo->inTransaction());Check::same(0,$e->count());}finally{$e->pdo->rollBack();}});
if(!$mysql){inboxCase(false,static function(InboxEnvironment $e){$e->pdo->exec('BEGIN');try{Check::throws($e->pdo->inTransaction()?ConfigurationException::class:StorageException::class,static function()use($e){$e->receive();});Check::same(0,$e->count());}finally{$e->pdo->exec('ROLLBACK');}});}
inboxCase($mysql,static function(InboxEnvironment $e){
    $old=$e->receive();$new=new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32),'old'=>str_repeat('s',32)]);$service=$e->service($new);Check::same(true,$service->accept($e->request(),$e->mapper())->duplicate());Check::same('new',$e->snapshot()[0]['seal_key']);$newOnly=$e->service(new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32)]));Check::same($old->id(),$newOnly->accept($e->request(),$e->mapper())->id());
});
inboxCase($mysql,static function(InboxEnvironment $e){$e->receive();$bad=$e->service(new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32)]));$before=$e->snapshot();Check::throws(StorageException::class,static function()use($e,$bad){$bad->accept($e->request(),$e->mapper());});Check::same($before,$e->snapshot());});
foreach(['resource_id'=>'b','descriptor'=>str_repeat('a',64),'body_digest'=>str_repeat('b',64),'source_key'=>'forged','source_time'=>'100001','seal'=>str_repeat('c',64)] as $column=>$value){inboxCase($mysql,static function(InboxEnvironment $e)use($column,$value){$e->receive();$query=$e->pdo->prepare('UPDATE sosecurity_webhook_inbox SET '.$column.'=:value');$query->execute(['value'=>$value]);$before=$e->snapshot();Check::throws(StorageException::class,static function()use($e){$e->receive();});Check::same($before,$e->snapshot());});}
inboxCase($mysql,static function(InboxEnvironment $e){$e->receive();$e->pdo->exec("UPDATE sosecurity_webhook_inbox SET payload='tampered'");Check::throws(SecurityException::class,static function()use($e){$e->receive();});Check::same(1,$e->count());});
inboxCase($mysql,static function(InboxEnvironment $e){$e->receive();$e->clock->time-=1;Check::throws(StorageException::class,static function()use($e){$e->receive();});Check::same(1,$e->count());});
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->pdo->afterStatement=function(string $sql)use($e){if(strpos($sql,'INSERT')===0){$e->pdo->afterStatement=null;$e->clock->time+=301;}};Check::same(null,$e->receive());Check::same(0,$e->count());$e->clock->time=100000;Check::same(false,$e->receive()->duplicate());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    $reached=false;$e->pdo->afterStatement=function(string $sql)use($e,&$reached){if(strpos($sql,'INSERT')===0){$e->pdo->afterStatement=null;$reached=true;usleep(250000);}};Check::throws(StorageException::class,static function()use($e){$e->receive();});Check::same(true,$reached);Check::same(0,$e->count());
},'standard-hmac',['io_milliseconds'=>200]);
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->pdo->afterCommit=function()use($e){$e->pdo->afterCommit=null;$e->clock->time+=301;};Check::throws(SecurityException::class,static function()use($e){$e->receive();});Check::same(1,$e->count());$again=$e->receive();Check::same(true,$again->duplicate());Check::same(1,$e->count());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->pdo->afterStatement=function(string $sql)use($e){if(strpos($sql,'INSERT')===0){$e->pdo->afterStatement=null;$e->clock->time+=301;$e->pdo->failRollback=true;}};Check::throws(StorageException::class,static function()use($e){$e->receive();});$e->pdo->failRollback=false;if($e->mysql){$e->pdo->rollBack();}else{$e->pdo->exec('ROLLBACK');}$before=$e->keyCalls;Check::throws(StorageException::class,static function()use($e){$e->receive();});Check::same($before,$e->keyCalls);Check::same(0,$e->count());
});
if(!$mysql){foreach(['OFF','NORMAL'] as $synchronous){inboxCase(false,static function(InboxEnvironment $e)use($synchronous){$e->pdo->exec('PRAGMA synchronous='.$synchronous);Check::throws(ConfigurationException::class,static function()use($e){$e->receive();});Check::same(0,$e->count());});}}
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->onKey=static function(int $calls)use($e){if($calls===3){$e->pdo->exec("UPDATE webhook_test_resources SET enabled=0 WHERE tenant='tenant' AND id='a'");}};Check::same(null,$e->receive());Check::same(0,$e->count());Check::same(0,(int)$e->pdo->query("SELECT enabled FROM webhook_test_resources WHERE tenant='tenant' AND id='a'")->fetchColumn());
});
if($mysql){inboxCase(true,static function(InboxEnvironment $e){
    $other=new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $e->onKey=static function(int $calls)use($other){if($calls===5){$other->exec("UPDATE webhook_test_resources SET enabled=0 WHERE tenant='tenant' AND id='a'");}};Check::same(null,$e->receive());Check::same(0,$e->count());Check::same(0,(int)$e->pdo->query("SELECT enabled FROM webhook_test_resources WHERE tenant='tenant' AND id='a'")->fetchColumn());
});}
inboxCase($mysql,static function(InboxEnvironment $e){
    $e->receive();$query=$e->pdo->prepare('UPDATE sosecurity_webhook_inbox SET payload=:payload');$query->bindValue(':payload',str_repeat('X',strlen($e->body())),PDO::PARAM_LOB);$query->execute();$before=$e->snapshot();Check::throws(StorageException::class,static function()use($e){$e->receive();});Check::same($before,$e->snapshot());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    $committed=false;$e->pdo->afterCommit=static function()use(&$committed){$committed=true;};$e->pdo->afterExec=static function(string $sql)use($e,&$committed){if($committed&&(strpos($sql,'PRAGMA busy_timeout=')===0||strpos($sql,'SET SESSION innodb_lock_wait_timeout=')===0)){$e->pdo->afterExec=null;$e->pdo->afterCommit=null;$e->clock->time+=301;}};
    Check::throws(SecurityException::class,static function()use($e){$e->receive();});Check::same(1,$e->count());Check::same(true,$e->receive()->duplicate());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    $query=$e->mysql?'SELECT @@SESSION.innodb_lock_wait_timeout':'PRAGMA busy_timeout';$before=$e->pdo->query($query)->fetchColumn();$e->receive();Check::same($before,$e->pdo->query($query)->fetchColumn());$e->receive();Check::same($before,$e->pdo->query($query)->fetchColumn());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    if($e->mysql){$e->pdo->exec('ALTER TABLE sosecurity_webhook_inbox DROP PRIMARY KEY');}
    else{$e->pdo->exec('DROP TABLE sosecurity_webhook_inbox');$sql=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-sqlite.sql');$sql=preg_replace('/,\s*PRIMARY KEY \(endpoint_key, event_key\)/','',$sql);$e->pdo->exec($sql);}
    Check::throws(ConfigurationException::class,static function()use($e){$e->receive();});Check::same(0,$e->count());
});
if($mysql){inboxCase(true,static function(InboxEnvironment $e){$e->pdo->exec('ALTER TABLE sosecurity_webhook_inbox ENGINE=MyISAM');Check::throws(ConfigurationException::class,static function()use($e){$e->receive();});Check::same(0,$e->count());});}
else{
    foreach(['OFF','MEMORY'] as $mode){inboxCase(false,static function(InboxEnvironment $e)use($mode){$e->pdo->exec('PRAGMA journal_mode='.$mode);Check::throws(ConfigurationException::class,static function()use($e){$e->receive();});Check::same(0,$e->count());});}
    inboxCase(false,static function(InboxEnvironment $e){$memory=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$memory->exec(file_get_contents(dirname(__DIR__).'/resources/sql/webhook-sqlite.sql'));$inbox=new SoSecurity\Webhook\SqlInbox($memory,'inbox-test-site',$e->verifier,$e->seals,static function(){return true;},$e->clock);Check::throws(ConfigurationException::class,static function()use($e,$inbox){$inbox->accept($e->request(),$e->mapper());});Check::same(0,(int)$memory->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn());});
}
inboxCase($mysql,static function(InboxEnvironment $e){
    $time=$e->clock->time;$body=$e->body();$message='msg_test.'.$time.'.'.$body;$signatures='v1,'.base64_encode(hash_hmac('sha256',$message,str_repeat('k',32),true)).' v1,'.base64_encode(hash_hmac('sha256',$message,str_repeat('n',32),true));
    $e->onKey=static function(int $calls)use($e){if($calls===5){$e->keys=new SoSecurity\Webhook\KeySet($e->endpoint,['new'=>str_repeat('n',32)]);}};$received=$e->receive($e->request($body,$time,['Webhook-Signature'=>$signatures]));Check::same(false,$received->duplicate());Check::same('new',$e->snapshot()[0]['source_key']);Check::same(true,$e->receive($e->request($body,$time,['Webhook-Signature'=>$signatures]))->duplicate());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    $first=$e->receive();$endpoint=new SoSecurity\Webhook\Endpoint('inbox','tenant','provider-account','https://hooks.example/moved','standard-hmac',['tolerance'=>299]);$keys=new SoSecurity\Webhook\KeySet($endpoint,['test'=>str_repeat('k',32)]);$verifier=new SoSecurity\Webhook\Verifier($endpoint,static function()use($keys){return $keys;},static function(){return true;},$e->clock);$service=$e->service(null,$verifier);Check::same($e->inbox->endpointKey(),$service->endpointKey());$request=$e->request();$moved=new Request('POST',$endpoint->url(),$request->body(),['Webhook-Id'=>$request->header('Webhook-Id'),'Webhook-Timestamp'=>$request->header('Webhook-Timestamp'),'Webhook-Signature'=>$request->header('Webhook-Signature')]);$again=$service->accept($moved,$e->mapper());Check::same(true,$again->duplicate());Check::same($first->id(),$again->id());
});
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
inboxCase($mysql,static function(InboxEnvironment $e){
    $first=$e->receive();$other=new SoSecurity\Webhook\SqlInbox($e->pdo,'another-site',$e->verifier,$e->seals,static function(){return true;},$e->clock);Check::same(false,hash_equals($e->inbox->endpointKey(),$other->endpointKey()));$second=$other->accept($e->request(),$e->mapper());Check::same(false,$second->duplicate());Check::same(false,hash_equals($first->id(),$second->id()));Check::same(2,$e->count());Check::same(true,$other->accept($e->request(),$e->mapper())->duplicate());
});
if(!$mysql){inboxCase(false,static function(InboxEnvironment $e){$e->pdo->exec('CREATE TEMP TABLE sosecurity_webhook_inbox (secret TEXT)');Check::same(false,$e->receive()->duplicate());Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM main.sosecurity_webhook_inbox')->fetchColumn());Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM temp.sosecurity_webhook_inbox')->fetchColumn());});}
if(extension_loaded('sodium')){inboxCase($mysql,static function(InboxEnvironment $e){
    Check::same(false,$e->receive()->duplicate());Check::same(true,$e->receive()->duplicate());$before=$e->snapshot();$pair=sodium_crypto_sign_seed_keypair(str_repeat('z',32));$e->keys=new SoSecurity\Webhook\KeySet($e->endpoint,['other'=>sodium_crypto_sign_publickey($pair)]);Check::same(null,$e->receive());Check::same($before,$e->snapshot());
},'standard-ed25519');}
elseif(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required sodium unavailable for webhook inbox.');}
if($mysql){inboxCase(true,static function(InboxEnvironment $e){
    $other=new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$prior=null;
    $e->pdo->beforeStatement=static function(string $sql)use($e,$other,&$prior){if(strpos($sql,'INSERT')===0){$e->pdo->beforeStatement=null;Check::same(0,$e->count());$service=new SoSecurity\Webhook\SqlInbox($other,'inbox-test-site',$e->verifier,$e->seals,static function(){return true;},$e->clock);$prior=$service->accept($e->request(),$e->mapper());Check::same(false,$prior->duplicate());}};
    $again=$e->receive();Check::same(true,$again->duplicate());Check::same($prior->id(),$again->id());Check::same(1,$e->count());
});}
inboxCase($mysql,static function(InboxEnvironment $e){
    $limit=65536;$policy=['maximum_body'=>&$limit];$definition=['scope'=>'tenant','account'=>'provider-account','url'=>'https://hooks.example/events','protocol'=>'standard-hmac','key_provider'=>'webhook_keys','request_guard'=>'webhook_guard','policy'=>&$policy,'inbox'=>['connection'=>'inbox_pdo','integrity_keys'=>'inbox_keys','association_guard'=>'association']];$endpoints=['inbox'=>&$definition];$calls=0;
    $services=['webhook_keys'=>static function(SoSecurity\Webhook\Endpoint $endpoint)use(&$calls){++$calls;return new SoSecurity\Webhook\KeySet($endpoint,['test'=>str_repeat('k',32)]);},'webhook_guard'=>static function()use(&$calls){++$calls;return true;},'inbox_pdo'=>$e->pdo,'inbox_keys'=>$e->seals,'association'=>static function(){return true;}];
    $before=$e->pdo->queries;$factory=SoSecurity\Security::fromArray(['site'=>'inbox-test-site','webhooks'=>&$endpoints],$services,$e->clock);$limit=0;$definition['scope']='mutated';$endpoints=[];
    Check::same(65536,$factory->config()->webhooks()['inbox']['policy']['maximum_body']);Check::same('tenant',$factory->config()->webhooks()['inbox']['scope']);$verifier=$factory->webhook('inbox');$inbox=$factory->webhookInbox('inbox');$diagnostic=json_encode($factory->diagnose());Check::same(0,$calls);Check::same($before,$e->pdo->queries);Check::same(true,strpos($diagnostic,'webhook.schema_durability_unverified')!==false);Check::same(false,strpos($diagnostic,str_repeat('s',32))!==false);Check::same(false,strpos($diagnostic,str_repeat('k',32))!==false);
    Check::same(true,$verifier->verify($e->request())!==null);Check::same(false,$inbox->accept($e->request(),$e->mapper())->duplicate());Check::same(true,$inbox->accept($e->request(),$e->mapper())->duplicate());Check::same(1,$e->count());
    $config=['site'=>'inbox-test-site','webhooks'=>$factory->config()->webhooks()];foreach(['webhook_keys','webhook_guard','inbox_pdo','inbox_keys','association'] as $name){$broken=$services;$broken[$name]=new stdClass();$bad=SoSecurity\Security::fromArray($config,$broken,$e->clock);$checks=array_column($bad->diagnose(),null,'check');Check::same(true,in_array('fail',array_column(array_values($checks),'status'),true));Check::throws(ConfigurationException::class,static function()use($bad){$bad->webhookInbox('inbox');});}
    Check::throws(ConfigurationException::class,static function()use($factory){$factory->webhook('missing');});Check::throws(ConfigurationException::class,static function(){SoSecurity\Security::fromArray(['site'=>'empty'])->webhook('inbox');});
});
$base=['scope'=>'tenant','account'=>'provider-account','url'=>'https://hooks.example/events','protocol'=>'standard-hmac','key_provider'=>'keys','request_guard'=>'guard'];
foreach([null,['bad id'=>$base],['inbox'=>[]],['inbox'=>$base+['extra'=>true]],['inbox'=>array_replace($base,['protocol'=>'unknown'])],['inbox'=>$base+['inbox'=>[]]],['inbox'=>$base+['policy'=>['tolerance'=>0]]]] as $definitions){Check::throws(ConfigurationException::class,static function()use($definitions){SoSecurity\Security::fromArray(['site'=>'test','webhooks'=>$definitions]);});}
Check::throws(ConfigurationException::class,static function()use($base){$definitions=[];for($i=0;$i<33;++$i){$definitions['endpoint'.$i]=$base;}SoSecurity\Security::fromArray(['site'=>'test','webhooks'=>$definitions]);});
inboxCase($mysql,static function(InboxEnvironment $e){
    $writes=0;$e->pdo->beforeStatement=static function(string $sql)use(&$writes){if(strpos($sql,'INSERT')===0){++$writes;}};
    $e->pdo->afterStatement=static function(string $sql)use($e){if(strpos($sql,'table_info')!==false||strpos($sql,'information_schema.COLUMNS')!==false){$e->pdo->afterStatement=null;$e->clock->time+=2;}};
    Check::same(null,$e->receive($e->request(null,99701)));Check::same(0,$writes);Check::same(0,$e->count());$e->pdo->beforeStatement=null;Check::same(false,$e->receive()->duplicate());
});
inboxCase($mysql,static function(InboxEnvironment $e){
    $updates=0;$e->pdo->beforeStatement=static function(string $sql)use(&$updates){if(strpos($sql,'UPDATE')===0){++$updates;}};$e->onAssociation=static function(int $calls)use($e){if($calls===2){$e->clock->time+=2;}};
    Check::same(null,$e->receive($e->request(null,99701)));Check::same(0,$updates);Check::same(0,$e->count());
});
if(!$mysql){inboxCase(false,static function(InboxEnvironment $e){
    $queries=[];$e->pdo->afterStatement=static function(string $sql)use(&$queries){$queries[]=$sql;if($sql==='PRAGMA database_list'){usleep(250000);}};Check::throws(StorageException::class,static function()use($e){$e->receive();});Check::same(true,in_array('PRAGMA database_list',$queries,true));Check::same(false,in_array('PRAGMA main.journal_mode',$queries,true));Check::same(4,$e->keyCalls);Check::same(0,$e->count());
},'standard-hmac',['io_milliseconds'=>200]);}
echo 'PASS webhook SQL inbox: '.Check::$assertions.' assertions on PHP '.PHP_VERSION.'; actual '.($mysql?'MySQL native prepares':'private-file SQLite')." authenticated receive, sealed provenance, duplicate/conflict, source/association withdrawal, rollback/late commit, timeout and explicit schema/durability; no business execution\n";
