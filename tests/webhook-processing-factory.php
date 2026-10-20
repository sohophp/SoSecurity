<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';

use SoSecurity\Security;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Webhook\Message;
use SoSecurity\Webhook\ProcessingPolicy;
use SoSecurity\Webhook\SqlProcessor;

// The connection and all business data belong to this private test environment.
$e=new InboxEnvironment();
try{
    foreach(explode(';',file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-sqlite.sql')) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
    $e->pdo->exec('CREATE TABLE factory_effects(receipt_id CHAR(32) NOT NULL PRIMARY KEY,resource_id VARCHAR(64) NOT NULL)');
    $definition=['scope'=>'tenant','account'=>'provider-account','url'=>'https://hooks.example/events','protocol'=>'standard-hmac',
        'processing'=>['connection'=>'worker_db','integrity_keys'=>'receipt_keys','mapper'=>'historical_mapper','association_guard'=>'current_business','worker_guard'=>'current_worker']];
    $configuration=['site'=>'inbox-test-site','webhooks'=>['inbox'=>$definition]];
    $calls=['mapper'=>0,'association'=>0,'worker'=>0,'management'=>0];$allowed=true;$manage=false;$phases=[];$metadata=[];
    $secret='SYNTHETIC-PRIVATE-PROCESSING-SERVICE-SECRET';
    $services=['worker_db'=>$e->pdo,'receipt_keys'=>$e->seals,
        'historical_mapper'=>static function(string $raw,$endpoint,string $receipt,array $context)use(&$calls,&$metadata,$secret){
            ++$calls['mapper'];$metadata=$context;$data=json_decode($raw,true);
            if(!is_array($data)||($data['account'] ?? null)!==$endpoint->account()||($data['id'] ?? null)!==($context['message_id'] ?? null)){return null;}
            return new Message($data['id'],$data['type'],$data['resource'],['version'=>$data['version']]);
        },
        'current_business'=>static function($endpoint,Message $message,string $phase,array $provenance)use($e,&$calls,&$phases):bool{
            ++$calls['association'];$phases[]=$phase;
            $query=$e->pdo->prepare('SELECT account,enabled,version FROM webhook_test_resources WHERE tenant=:tenant AND id=:id');
            $query->execute(['tenant'=>$endpoint->scope(),'id'=>$message->resource()]);$row=$query->fetch(PDO::FETCH_ASSOC);
            return is_array($row)&&$row['account']===$endpoint->account()&&(int)$row['enabled']===1&&$row['version']===($message->context()['version'] ?? null)&&isset($provenance['receipt_id']);
        },
        'current_worker'=>static function(string $operation,$endpoint,string $receipt,string $worker)use(&$calls,&$allowed):bool{++$calls['worker'];return $allowed&&$worker==='trusted-worker';},
        'current_manager'=>static function(string $operation,$endpoint,string $receipt,string $operator)use(&$calls,&$manage):bool{++$calls['management'];return $manage&&$operation==='retry'&&$operator==='trusted-operator';},
    ];
    $queries=$e->pdo->queries;$factory=Security::fromArray($configuration,$services,$e->clock);$processor=$factory->webhookProcessor('inbox');
    Check::same(true,$processor instanceof SqlProcessor);Check::same($queries,$e->pdo->queries);Check::same([0,0,0,0],array_values($calls));
    Check::same(5,$factory->config()->webhooks()['inbox']['processing']['policy']['maximum_attempts']);
    Check::same(null,$factory->config()->webhooks()['inbox']['key_provider']);
    Check::throws(ConfigurationException::class,static function()use($factory){$factory->webhook('inbox');});
    Check::throws(ConfigurationException::class,static function()use($factory){$factory->webhookInbox('inbox');});
    Check::throws(ConfigurationException::class,static function()use($factory){$factory->webhookProcessor('unknown');});
    Check::throws(ConfigurationException::class,static function(){Security::fromArray(['site'=>'none'])->webhookProcessor('inbox');});
    foreach([false,true] as $probe){
        $checks=$factory->diagnose(null,$probe);$byName=array_column($checks,null,'check');
        Check::same('not_configured',$byName['webhooks.inbox.receive']['status']);
        Check::same('not_configured',$byName['webhooks.inbox.processing.management_guard']['status']);
        foreach(['connection','integrity_keys','mapper','association_guard','worker_guard','history_provenance','schema_durability','current_business','transactional_handler','worker_identity','recovery_retention','transport_timeout'] as $name){Check::same('manual',$byName['webhooks.inbox.processing.'.$name]['status']);}
        Check::same($queries,$e->pdo->queries);Check::same([0,0,0,0],array_values($calls));
        Check::same(false,strpos(json_encode($checks),$secret)!==false);
    }
    Check::same(false,strpos(print_r($factory,true),$secret)!==false);ob_start();var_dump($factory);$dump=ob_get_clean();Check::same(false,strpos($dump,$secret)!==false);Check::same('{}',json_encode($factory));
    Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());

    // No verifier or publisher secret is available to this independent worker factory.
    $id=$e->receive()->id();$e->keyOnline=false;$keyCalls=$e->keyCalls;$e->clock->time+=3600;
    Check::same([$id],$processor->pending('trusted-worker')['receipt_ids']);
    $allowed=false;Check::same(null,$processor->claim($id,'trusted-worker'));$allowed=true;
    Check::same(null,$processor->claim($id,'untrusted-worker'));
    $claim=$processor->claim($id,'trusted-worker');Check::same('leased',$claim->metadata()->status());Check::same('msg_test',$metadata['message_id']);
    $handlerCalls=0;$handler=static function(PDO $pdo,Message $message,string $raw,$status)use(&$handlerCalls):bool{
        ++$handlerCalls;$statement=$pdo->prepare('INSERT INTO factory_effects VALUES(:receipt,:resource)');$statement->execute(['receipt'=>$status->receiptId(),'resource'=>$message->resource()]);return true;
    };
    Check::same('succeeded',$processor->execute('trusted-worker',$claim->token(),$handler)->status());
    Check::same(1,$handlerCalls);Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM factory_effects')->fetchColumn());
    Check::same(null,$processor->execute('trusted-worker',$claim->token(),$handler));Check::same(1,$handlerCalls);
    Check::same('succeeded',$factory->webhookProcessor('inbox')->status($id,'trusted-worker')->status());
    Check::same($keyCalls,$e->keyCalls);Check::same(true,in_array('execute',$phases,true));Check::same(true,in_array('commit',$phases,true));
    $other=$configuration;$other['site']='other-site';Check::same(null,Security::fromArray($other,$services,$e->clock)->webhookProcessor('inbox')->claim($id,'trusted-worker'));
    $other=$configuration;$other['webhooks']['inbox']['account']='other-account';Check::same(null,Security::fromArray($other,$services,$e->clock)->webhookProcessor('inbox')->claim($id,'trusted-worker'));

    // A sealed source never supersedes current business authority.
    $e->pdo->exec('DELETE FROM sosecurity_webhook_processing');$e->pdo->exec('DELETE FROM sosecurity_webhook_inbox');$e->keyOnline=true;$id=$e->receive()->id();$e->keyOnline=false;
    $e->pdo->exec("UPDATE webhook_test_resources SET enabled=0 WHERE tenant='tenant' AND id='a'");
    Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($processor,$id){$processor->claim($id,'trusted-worker');});
    $e->pdo->exec("UPDATE webhook_test_resources SET enabled=1 WHERE tenant='tenant' AND id='a'");
    $retryConfiguration=$configuration;$retryConfiguration['webhooks']['inbox']['processing']['policy']=['maximum_attempts'=>1,'maximum_manual_retries'=>1];
    $retryFactory=Security::fromArray($retryConfiguration,$services,$e->clock);$retryProcessor=$retryFactory->webhookProcessor('inbox');$claim=$retryProcessor->claim($id,'trusted-worker');
    Check::same('dead',$retryProcessor->fail('trusted-worker',$claim->token(),'business.unavailable')->status());
    Check::same(null,$retryProcessor->retry($id,'trusted-operator'));Check::same(0,$calls['management']);
    $retryConfiguration['webhooks']['inbox']['processing']['management_guard']='current_manager';$managed=Security::fromArray($retryConfiguration,$services,$e->clock)->webhookProcessor('inbox');
    Check::same(null,$managed->retry($id,'trusted-operator'));$manage=true;Check::same(null,$managed->retry($id,'untrusted-operator'));
    Check::same('retry',$managed->retry($id,'trusted-operator')->status());$claim=$managed->claim($id,'trusted-worker');
    Check::same(1,$claim->metadata()->toArray()['manual_retries']);Check::same(2,$claim->metadata()->toArray()['total_attempts']);
    Check::same('dead',$managed->fail('trusted-worker',$claim->token(),'business.unavailable')->status());Check::same(null,$managed->retry($id,'trusted-operator'));

    // Configuration names and nested policy values are copied out of external references.
    $serviceName='current_worker';$delay=2;$attempts=2;$references=$definition;$references['processing']['worker_guard']=&$serviceName;
    $references['processing']['policy']=['maximum_attempts'=>&$attempts,'backoff'=>[&$delay]];$isolated=Security::fromArray(['site'=>'inbox-test-site','webhooks'=>['inbox'=>$references]],$services,$e->clock);
    $serviceName='missing';$attempts=20;$delay=90000;$saved=$isolated->config()->webhooks()['inbox']['processing'];
    Check::same('current_worker',$saved['worker_guard']);Check::same(2,$saved['policy']['maximum_attempts']);Check::same([2],$saved['policy']['backoff']);
    $saved['policy']['backoff'][0]=86400;Check::same([2],$isolated->config()->webhooks()['inbox']['processing']['policy']['backoff']);
    $policy=new ProcessingPolicy(['backoff'=>[2]]);$options=$policy->options();$options['backoff'][0]=86400;Check::same(2,$policy->retryDelay(1));

    foreach(['connection','integrity_keys','mapper','association_guard','worker_guard'] as $field){
        $bad=$configuration;unset($bad['webhooks']['inbox']['processing'][$field]);Check::throws(ConfigurationException::class,static function()use($bad){Security::fromArray($bad);});
        $badServices=$services;$badServices[$definition['processing'][$field]]='PRIVATE-INVALID-SERVICE';$badFactory=Security::fromArray($configuration,$badServices,$e->clock);
        Check::throws(ConfigurationException::class,static function()use($badFactory){$badFactory->webhookProcessor('inbox');});
        $checks=array_column($badFactory->diagnose(null,true),null,'check');Check::same('fail',$checks['webhooks.inbox.processing.'.$field]['status']);
        Check::same(false,strpos(json_encode($checks),'PRIVATE-INVALID-SERVICE')!==false);
    }
    $bad=$configuration;$bad['webhooks']['inbox']['processing']['management_guard']='missing-manager';$badFactory=Security::fromArray($bad,$services,$e->clock);
    Check::throws(ConfigurationException::class,static function()use($badFactory){$badFactory->webhookProcessor('inbox');});
    Check::same('fail',array_column($badFactory->diagnose(),null,'check')['webhooks.inbox.processing.management_guard']['status']);
    foreach([['unexpected'=>true],['policy'=>null],['policy'=>['maximum_attempts'=>0]],['policy'=>['backoff'=>[5,1]]],['management_guard'=>false]] as $change){
        $bad=$configuration;$bad['webhooks']['inbox']['processing']=array_replace($definition['processing'],$change);Check::throws(ConfigurationException::class,static function()use($bad){Security::fromArray($bad);});
    }
    foreach([['key_provider'=>'publisher'],['request_guard'=>'ingress'],['inbox'=>['connection'=>'worker_db','integrity_keys'=>'receipt_keys','association_guard'=>'current_business']],['processing'=>null]] as $change){
        $bad=$configuration;$bad['webhooks']['inbox']=array_replace($definition,$change);Check::throws(ConfigurationException::class,static function()use($bad){Security::fromArray($bad);});
    }
    $receive=$configuration;$receive['webhooks']['inbox']['key_provider']='publisher';$receive['webhooks']['inbox']['request_guard']='ingress';$receive['webhooks']['inbox']['processing']=null;
    $receiveFactory=Security::fromArray($receive,$services+['publisher'=>static function(){throw new RuntimeException('MUST-NOT-FETCH');},'ingress'=>static function(){throw new RuntimeException('MUST-NOT-CALL');}],$e->clock);
    Check::same(true,$receiveFactory->webhook('inbox') instanceof SoSecurity\Webhook\Verifier);
    Check::throws(ConfigurationException::class,static function()use($receiveFactory){$receiveFactory->webhookProcessor('inbox');});

    // Historical Ed25519 processing has no receiving dependency on sodium or online publisher keys.
    $historical=$configuration;$historical['webhooks']['inbox']['protocol']='standard-ed25519';$historicalFactory=Security::fromArray($historical,$services,$e->clock);
    Check::same(true,$historicalFactory->webhookProcessor('inbox') instanceof SqlProcessor);
    Check::same(false,array_key_exists('webhooks.inbox.ed25519',array_column($historicalFactory->diagnose(null,true),null,'check')));

    // Configuration and construction never install an absent processing schema, even during diagnostics.
    $e->pdo->exec('DROP TABLE sosecurity_webhook_processing');$queries=$e->pdo->queries;$empty=Security::fromArray($configuration,$services,$e->clock);
    $emptyProcessor=$empty->webhookProcessor('inbox');$empty->diagnose(null,true);Check::same($queries,$e->pdo->queries);
    Check::throws(ConfigurationException::class,static function()use($emptyProcessor){$emptyProcessor->pending('trusted-worker');});
    Check::same(0,(int)$e->pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sosecurity_webhook_processing'")->fetchColumn());
    Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
}finally{$e->close();}
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." webhook processing factory/diagnostic assertions passed\n";
