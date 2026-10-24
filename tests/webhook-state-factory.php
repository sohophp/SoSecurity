<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Account as A;
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
inboxCase($mysql,static function(InboxEnvironment $e)use($mysql):void{
    $directory=privateDirectory();$installed=false;$effectsCreated=false;
    try{
        $ddl=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql');
        foreach(explode(';',$ddl) as $statement){if(trim($statement)!==''){$e->pdo->exec($statement);}}$installed=true;
        $e->pdo->exec('CREATE TABLE webhook_owned_effects(receipt_id VARCHAR(32) NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$effectsCreated=true;
        $calls=0;$guard=static function()use(&$calls):bool{++$calls;return true;};
        $mapper=static function(string $body):SoSecurity\Webhook\Message{$v=json_decode($body,true);return new SoSecurity\Webhook\Message($v['id'],$v['type'],$v['resource'],['version'=>$v['version']]);};
        $build=static function()use($e,$mapper,$guard):SoSecurity\Webhook\SqlProcessor{return new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,$mapper,$guard,$guard,null,$e->clock,$guard);};
        $old=$build();
        $inbox=['endpoint_key'=>'digest','event_key'=>'digest','receipt_id'=>'bytes:32','event_id'=>'bytes:256','event_type'=>'bytes:128','resource_id'=>'bytes:256','descriptor'=>'digest','body_digest'=>'digest','payload'=>'blob:1048576','created_at'=>'int','seen_at'=>'int','source_key'=>'bytes:64','source_time'=>'nullable_int','seal_key'=>'bytes:64','seal'=>'digest'];
        $processing=['endpoint_key'=>'digest','receipt_id'=>'bytes:32','event_key'=>'digest','body_digest'=>'digest','descriptor'=>'digest','policy'=>'digest','status'=>'bytes:16','attempt'=>'int','total_attempts'=>'int','manual_retries'=>'int','revision'=>'int','due_at'=>'int','lease_until'=>'int','claim_digest'=>'bytes:64','worker_digest'=>'bytes:64','error_code'=>'bytes:64','created_at'=>'int','updated_at'=>'int','seal_key'=>'bytes:64','seal'=>'digest'];
        $effects=['columns'=>['receipt_id'=>'bytes:32'],'primary'=>['receipt_id'],'where'=>[],'maximum_rows'=>100];if(!$mysql){$effects['sqlite_declarations']=['receipt_id'=>'VARCHAR(32)'];}
        $definitions=[
            'webhook_owned_effects'=>$effects,
            'sosecurity_webhook_inbox'=>['columns'=>$inbox,'primary'=>['endpoint_key','event_key'],'where'=>[],'maximum_rows'=>2],
            'sosecurity_webhook_processing'=>['columns'=>$processing,'primary'=>['endpoint_key','receipt_id'],'where'=>[],'maximum_rows'=>1],
        ];$source=new A\SqlStateSnapshot($e->pdo,'owned-webhook-sql',$definitions,30000);
        $sql=$source;$policy=new SoSecurity\Webhook\ProcessingPolicy();$configuration=new A\WebhookStateSnapshot($e->pdo,'owned-config',$e->endpoint,$e->keys,$e->seals,$policy);$source=new A\CompositeStateSnapshot($e->pdo,['sql'=>$sql,'configuration'=>$configuration]);
        $witnessKeys=new SoSecurity\Support\HmacKeys('witness',['witness'=>str_repeat('w',32)]);
        $witness=new A\LocalStateWitness($e->pdo,$directory,'inbox-test-site','tenant',str_repeat('e',64),$witnessKeys,$source,new A\LocalStatePersistence($directory,30000),30000,2);
        $witness->initialize($source->digest());$boundary=new A\StateBoundary($witness,static function():bool{return true;});
        $queries=$e->pdo->queries;
        foreach(['payload','processing','filter'] as $missing){
            $badDefinitions=$definitions;if($missing==='payload'){unset($badDefinitions['sosecurity_webhook_inbox']['columns']['payload']);}elseif($missing==='processing'){unset($badDefinitions['sosecurity_webhook_processing']);}else{$badDefinitions['sosecurity_webhook_inbox']['where']=['endpoint_key'=>str_repeat('a',64)];}
            $badSql=new A\SqlStateSnapshot($e->pdo,'owned-webhook-sql',$badDefinitions,30000);$badSource=new A\CompositeStateSnapshot($e->pdo,['sql'=>$badSql,'configuration'=>$configuration]);
            $badWitness=new A\LocalStateWitness($e->pdo,$directory,'inbox-test-site','tenant',str_repeat('e',64),$witnessKeys,$badSource,new A\LocalStatePersistence($directory,30000),30000,2);$badBoundary=new A\StateBoundary($badWitness,static function():bool{return true;});
            Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($badBoundary,$badWitness,$badSource,$badSql,$configuration,$e,$policy):void{new A\StateWebhookConnection($badBoundary,$badWitness,$badSource,$badSql,'sql',$configuration,'configuration','inbox-test-site',str_repeat('e',64),$e->endpoint,$e->keys,$e->seals,$policy);});
        }
        $declaration=new A\StateWebhookConnection($boundary,$witness,$source,$sql,'sql',$configuration,'configuration','inbox-test-site',str_repeat('e',64),$e->endpoint,$e->keys,$e->seals,$policy);
        $config=['site'=>'inbox-test-site','webhooks'=>['inbox'=>['scope'=>'tenant','account'=>'provider-account','url'=>$e->endpoint->url(),'protocol'=>'standard-hmac','key_provider'=>'fixed','request_guard'=>'request','state_connection'=>'state','inbox'=>['connection'=>'pdo','integrity_keys'=>'seals','association_guard'=>'association'],'processing'=>['connection'=>'pdo','integrity_keys'=>'seals','mapper'=>'mapper','association_guard'=>'association','worker_guard'=>'worker','management_guard'=>'management']]]];
        $requestAllowed=true;$associationAllowed=true;$workerAllowed=true;$managementAllowed=true;$associationTick=0;$onWorker=null;
        $services=['state'=>$declaration,'pdo'=>$e->pdo,'fixed'=>$e->keys,'seals'=>$e->seals,'request'=>static function()use(&$calls,&$requestAllowed):bool{++$calls;return $requestAllowed;},'association'=>static function()use($e,&$calls,&$associationAllowed,&$associationTick):bool{++$calls;$e->clock->time+=$associationTick;$associationTick=0;return $associationAllowed;},'worker'=>static function()use(&$calls,&$workerAllowed,&$onWorker):bool{++$calls;if($onWorker!==null){$onWorker();}return $workerAllowed;},'management'=>static function()use(&$calls,&$managementAllowed):bool{++$calls;return $managementAllowed;},'mapper'=>$mapper];
        $sdk=SoSecurity\Security::fromArray($config,$services,$e->clock);
        $legacyInbox=$e->inbox;$new=$sdk->webhookProcessor('inbox');$e->inbox=$sdk->webhookInbox('inbox');$verifier=$sdk->webhook('inbox');
        Check::same($queries,$e->pdo->queries);Check::same(0,$calls);Check::same(true,$declaration->boundTo($boundary));
        foreach([false,true] as $probe){$diagnostics=array_column($sdk->diagnose(null,$probe),null,'check');Check::same('manual',$diagnostics['webhooks.inbox.state_connection']['status']);Check::same('manual',$diagnostics['webhooks.inbox.key_provider']['status']);}Check::same($queries,$e->pdo->queries);Check::same(0,$calls);
        foreach(['fixed','seals','state'] as $name){
            $bad=$services;$bad[$name]=$name==='fixed'?new SoSecurity\Webhook\KeySet($e->endpoint,['one'=>str_repeat('x',32)]):($name==='seals'?new SoSecurity\Support\HmacKeys('wrong',['wrong'=>str_repeat('x',32)]):new stdClass());
            Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($config,$bad,$e):void{SoSecurity\Security::fromArray($config,$bad,$e->clock)->webhookInbox('inbox');});
            Check::same('fail',array_column(SoSecurity\Security::fromArray($config,$bad,$e->clock)->diagnose(),null,'check')['webhooks.inbox.state_connection']['status']);
        }
        foreach(['site','url'] as $field){$badConfig=$config;if($field==='site'){$badConfig['site']='other';}else{$badConfig['webhooks']['inbox']['url']='https://hooks.example/other';}
            Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($badConfig,$services,$e):void{SoSecurity\Security::fromArray($badConfig,$services,$e->clock)->webhookInbox('inbox');});
        }
        Check::throws(SoSecurity\Exception\DependencyException::class,static function()use($verifier,$e):void{$verifier->verify($e->request());});
        $badConfig=$config;$badConfig['webhooks']['inbox']['processing']['policy']=['lease_seconds'=>61];
        Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($badConfig,$services,$e):void{SoSecurity\Security::fromArray($badConfig,$services,$e->clock)->webhookProcessor('inbox');});
        Check::same($queries,$e->pdo->queries);Check::same(0,$calls);
        $receipt=str_repeat('a',32);$token='wc1.'.$receipt.'.1.'.str_repeat('b',64);
        $refuse=static function(callable $call)use($e,&$calls):void{
            $queries=$e->pdo->queries;$before=[$e->keyCalls,$e->mapCalls,$e->associationCalls,$calls];
            try{$call();throw new LogicException('Webhook entered a protected PDO outside its boundary.');}
            catch(SoSecurity\Storage\StorageException $error){Check::same('account.state_required',$error->reason());}
            Check::same($queries,$e->pdo->queries);Check::same($before,[$e->keyCalls,$e->mapCalls,$e->associationCalls,$calls]);
        };
        $refuse(static function()use($e,$legacyInbox):void{$legacyInbox->accept($e->request(),$e->mapper());});
        foreach([$old,$build()] as $service){
            $refuse(static function()use($service,$receipt):void{$service->claim($receipt,'worker');});
            $refuse(static function()use($service,$token):void{$service->execute('worker',$token,static function():bool{throw new LogicException('Handler must not execute');});});
            $refuse(static function()use($service,$token):void{$service->fail('worker',$token,'owned.failure');});
            $refuse(static function()use($service,$receipt):void{$service->retry($receipt,'operator');});
            $refuse(static function()use($service,$receipt):void{$service->status($receipt,'worker');});
            $refuse(static function()use($service):void{$service->pending('worker');});
        }
        $unchanged=static function()use($witness){return $witness->inspect(static function():bool{return true;});};$before=$unchanged();
        Check::same(null,$e->inbox->accept(new SoSecurity\Webhook\Request('POST',$e->endpoint->url(),'invalid',[]),$e->mapper()));Check::same($before,$unchanged());
        Check::same(null,$e->inbox->accept($e->request(),static function(){return null;}));Check::same($before,$unchanged());
        $requestAllowed=false;Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($e):void{$e->receive();});$requestAllowed=true;Check::same($before,$unchanged());
        $associationAllowed=false;Check::same(null,$e->receive());$associationAllowed=true;Check::same($before,$unchanged());Check::same(0,$e->count());
        $before=$unchanged();$at=$e->clock->time;$ordinary=$e->mapper();
        Check::same(null,$e->inbox->accept($e->request(),static function($proof)use($e,$ordinary){$e->clock->time+=1000;return $ordinary($proof);}));$e->clock->time=$at;Check::same($before,$unchanged());
        if(($GLOBALS['argv'][2]??'')==='completion-revoke'){
            $inserted=false;$revoked=false;
            $e->pdo->afterStatement=static function(string $sql)use(&$inserted):void{if(strpos($sql,'INSERT')===0&&strpos($sql,'sosecurity_webhook_inbox')!==false){$inserted=true;}};
            $e->pdo->afterCommit=static function()use(&$inserted,&$requestAllowed,&$revoked):void{if($inserted){$requestAllowed=false;$revoked=true;}};
            try{$e->receive();throw new LogicException('Native receive returned success after completion revocation');}
            catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
            Check::same(true,$revoked);Check::same(1,$e->count());Check::same(false,$e->pdo->inTransaction());Check::same('pending',$unchanged()['status']);return;
        }
        $received=$e->receive();Check::same(true,$received instanceof SoSecurity\Webhook\Receipt);
        $record=$unchanged();Check::same('webhook.receive',$record['intent']['action']);Check::same('authorized',$record['intent']['kind']);Check::same(false,strpos(json_encode($record),'msg_test')!==false);
        $duplicate=$e->receive();Check::same(true,$duplicate->duplicate());Check::same($received->id(),$duplicate->id());
        $before=$unchanged();
        try{$e->receive($e->request($e->body(['version'=>'2'])));throw new LogicException('Conflicting native event accepted');}catch(SoSecurity\Exception\SecurityException $error){Check::same('webhook.inbox_conflict',$error->reason());}Check::same($before,$unchanged());
        $body=$e->body(['id'=>'new-message']);$wire='new-message.'.$e->clock->time.'.'.$body;
        $full=new SoSecurity\Webhook\Request('POST',$e->endpoint->url(),$body,['Webhook-Id'=>'new-message','Webhook-Timestamp'=>(string)$e->clock->time,'Webhook-Signature'=>'v1,'.base64_encode(hash_hmac('sha256',$wire,$e->signingSecret,true))]);
        $extraReceived=$e->receive($full);Check::same(true,$extraReceived instanceof SoSecurity\Webhook\Receipt);
        $body=$e->body(['id'=>'overflow-message']);$wire='overflow-message.'.$e->clock->time.'.'.$body;
        $overflow=new SoSecurity\Webhook\Request('POST',$e->endpoint->url(),$body,['Webhook-Id'=>'overflow-message','Webhook-Timestamp'=>(string)$e->clock->time,'Webhook-Signature'=>'v1,'.base64_encode(hash_hmac('sha256',$wire,$e->signingSecret,true))]);
        $before=$unchanged();try{$e->receive($overflow);throw new LogicException('Native row capacity exceeded');}catch(SoSecurity\Exception\SecurityException $error){Check::same('webhook.inbox_capacity',$error->reason());}Check::same($before,$unchanged());Check::same(2,$e->count());Check::same(true,$e->receive()->duplicate());

        $id=$received->id();$before=$unchanged();$workerAllowed=false;
        Check::same(null,$new->claim($id,'worker'));Check::same(null,$new->status($id,'worker'));Check::same([],$new->pending('worker')['receipt_ids']);Check::same($before,$unchanged());$workerAllowed=true;
        Check::same(null,$new->claim(str_repeat('0',32),'worker'));Check::same($before,$unchanged());
        $associationAllowed=false;Check::same(null,$new->claim($id,'worker'));Check::same($before,$unchanged());$associationAllowed=true;
        $pending=$new->pending('worker');Check::same(true,in_array($id,$pending['receipt_ids'],true));Check::same(true,in_array($extraReceived->id(),$pending['receipt_ids'],true));Check::same($before,$unchanged());
        $observed=0;$onWorker=static function()use(&$observed,&$workerAllowed):void{if(++$observed===2){$workerAllowed=false;}};
        Check::same([],$new->pending('worker')['receipt_ids']);Check::same($before,$unchanged());$onWorker=null;$workerAllowed=true;
        if(($GLOBALS['argv'][2]??'')==='processing-race'){
            $jobs=[];$wins=0;$configuration=['mysql'=>$mysql,'database'=>$e->database,'socket'=>$mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):null,'directory'=>$directory,'definitions'=>$definitions,'receipt'=>$id];
            try{
                for($i=0;$i<4;++$i){$command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/webhook-native-processing-worker.php');$process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start owned processing worker');}$jobs[]=[$process,$pipes];$data=json_encode($configuration);if(fwrite($pipes[0],$data)!==strlen($data)){throw new RuntimeException('Cannot send processing test configuration');}fclose($pipes[0]);}
                foreach($jobs as &$job){list($process,$pipes)=$job;$output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);$job=null;if($exit!==0){throw new RuntimeException('Owned processing worker failed: '.$error);}$value=json_decode($output,true);Check::same(true,is_array($value));if($value['claimed']){++$wins;Check::same('succeeded',$value['status']);}else{Check::same(null,$value['status']);}}unset($job);
                Check::same(1,$wins);Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_owned_effects')->fetchColumn());Check::same('succeeded',$new->status($id,'worker')->status());Check::same('current',$unchanged()['status']);Check::same($source->digest(),$unchanged()['digest']);return;
            }finally{foreach($jobs as $job){if($job===null){continue;}list($process,$pipes)=$job;foreach($pipes as $pipe){if(is_resource($pipe)){fclose($pipe);}}if(is_resource($process)){proc_terminate($process);proc_close($process);}}}
        }
        $claim=$new->claim($id,'worker');Check::same(true,$claim instanceof SoSecurity\Webhook\ProcessingClaim);
        $record=$unchanged();Check::same('webhook.processing.claim',$record['intent']['action']);Check::same('authorized',$record['intent']['kind']);Check::same(false,strpos(json_encode($record),$claim->token())!==false);
        Check::same(null,$new->claim($id,'worker'));Check::same('leased',$new->status($id,'worker')->status());Check::same($record,$unchanged());
        try{$new->claim($extraReceived->id(),'worker');throw new LogicException('Native processing row capacity exceeded');}catch(SoSecurity\Exception\SecurityException $error){Check::same('webhook.processing_capacity',$error->reason());}Check::same($record,$unchanged());
        $handled=false;Check::same(null,$new->execute('other',$claim->token(),static function()use(&$handled):bool{$handled=true;return true;}));Check::same(false,$handled);Check::same(null,$new->fail('other',$claim->token(),'owned.failure'));Check::same($record,$unchanged());
        $at=$e->clock->time;$associationTick=$policy->leaseSeconds();
        Check::same(null,$new->execute('worker',$claim->token(),static function()use(&$handled):bool{$handled=true;return true;}));Check::same(false,$handled);Check::same($record,$unchanged());$e->clock->time=$at;
        Check::same('dead',$new->fail('worker',$claim->token(),'owned.failure',false)->status());$record=$unchanged();Check::same('webhook.processing.fail',$record['intent']['action']);
        $managementAllowed=false;Check::same(null,$new->retry($id,'operator'));Check::same($record,$unchanged());$managementAllowed=true;
        Check::same('retry',$new->retry($id,'operator')->status());Check::same('webhook.processing.retry',$unchanged()['intent']['action']);
        $claim=$new->claim($id,'worker');Check::same(true,$claim instanceof SoSecurity\Webhook\ProcessingClaim);
        if(in_array($GLOBALS['argv'][2]??'',['processing-failure','processing-late-revoke'],true)){
            $late=($GLOBALS['argv'][2]??'')==='processing-late-revoke';$wrote=false;
            if($late){$e->pdo->afterCommit=static function()use(&$wrote,&$workerAllowed):void{if($wrote){$workerAllowed=false;}};}
            try{$new->execute('worker',$claim->token(),static function(PDO $pdo)use($id,$late,&$wrote):bool{$q=$pdo->prepare('INSERT INTO webhook_owned_effects VALUES(?)');$q->execute([$id]);$wrote=true;return $late;});throw new LogicException('Failed native processing returned success');}
            catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
            Check::same($late?1:0,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_owned_effects')->fetchColumn());Check::same(false,$e->pdo->inTransaction());Check::same('pending',$unchanged()['status']);return;
        }
        $done=$new->execute('worker',$claim->token(),static function(PDO $pdo)use($id):bool{$q=$pdo->prepare('INSERT INTO webhook_owned_effects VALUES(?)');$q->execute([$id]);return true;});Check::same('succeeded',$done->status());
        Check::same($id,$e->pdo->query('SELECT receipt_id FROM webhook_owned_effects')->fetchColumn());
        Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
        Check::same('current',$witness->inspect(static function():bool{return true;})['status']);
        if(($GLOBALS['argv'][2]??'')==='mapping-change'){
            $beforeRows=$e->snapshot();$mapped=0;$normal=$e->mapper();
            try{$e->inbox->accept($e->request(),static function($proof)use(&$mapped,$normal){++$mapped;return $mapped===1?$normal($proof):new SoSecurity\Webhook\Message('msg_test','document.changed','other',['version'=>'1']);});throw new LogicException('Changed admitted target accepted');}
            catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
            Check::same(2,$mapped);Check::same($beforeRows,$e->snapshot());Check::same('pending',$unchanged()['status']);return;
        }
        $e->pdo->exec('DELETE FROM webhook_owned_effects');$before=$calls;
        try{$new->status($id,'worker');throw new LogicException('Changed covered SQL accepted');}
        catch(SoSecurity\Storage\StorageException $error){Check::same('account.witness_stale',$error->reason());}Check::same($before,$calls);
    }finally{if($mysql&&$effectsCreated){$e->pdo->exec('DROP TABLE webhook_owned_effects');}if($mysql&&$installed){$e->pdo->exec('DROP TABLE sosecurity_webhook_processing');}cleanDirectory($directory);}
});
echo 'PASS declared Webhook state factory: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;
