<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Security;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

outboxCase(false,static function(OutboxEnvironment $e):void{
    $config=['site'=>'outbox-test','outbox'=>['connection'=>'db','epoch'=>$e->epoch,'integrity_keys'=>'keys','authority'=>'current','management_guard'=>'manager','policy'=>['maximum_entries'=>5]]];
    $calls=0;$allowed=true;$services=['db'=>$e->pdo,'keys'=>$e->keys,'current'=>static function()use(&$calls,&$allowed):bool{++$calls;return $allowed;},'manager'=>static function()use(&$calls):bool{++$calls;return true;}];
    $queries=$e->pdo->queries;$headers=headers_list();$session=function_exists('session_status')?session_status():null;
    $factory=Security::fromArray($config,$services,$e->clock);$service=$factory->outbox();$checks=array_column($factory->diagnose(null,true),null,'check');
    Check::same($queries,$e->pdo->queries);Check::same(0,$calls);Check::same($headers,headers_list());Check::same($session,function_exists('session_status')?session_status():null);
    foreach(['connection','integrity_keys','authority','management_guard','schema_durability','host_transaction','business_event_identity','current_business','worker_identity','destination_contract','receiver_deduplication','key_separation','recovery_retention','capacity_maintenance','transport_timeout'] as $item){Check::same('manual',$checks['outbox.'.$item]['status']);}
    Check::same(5,$factory->config()->outbox()['policy']['maximum_entries']);Check::same(65536,$factory->config()->outbox()['policy']['maximum_payload_bytes']);Check::same(true,$service->initialize('tenant','orders','admin'));
    $message=$e->message();$first=$e->append($service,$message);$again=$e->append($service,$message);Check::same($first->deliveryId(),$again->deliveryId());Check::same(1,$e->count(true));
    $e->append($service,$e->message('rolled-back'),false);Check::same(1,$e->count(true));
    $allowed=false;outboxRefused('outbox.denied',static function()use($e,$service):void{$e->append($service,$e->message('denied'));});Check::same(1,$e->count(true));Check::same(null,$service->claim('tenant','orders','worker'));$allowed=true;
    $name='db';$maximum=5;$epoch=$e->epoch;$copy=$config;$copy['outbox']['connection']=&$name;$copy['outbox']['epoch']=&$epoch;$copy['outbox']['policy']['maximum_entries']=&$maximum;
    $immutable=Security::fromArray($copy,$services,$e->clock);$name='missing';$maximum=0;$epoch='invalid';$saved=$immutable->config()->outbox();Check::same('db',$saved['connection']);Check::same($e->epoch,$saved['epoch']);Check::same(5,$saved['policy']['maximum_entries']);
    $saved['policy']['lease_seconds']=0;Check::same(60,$immutable->config()->outbox()['policy']['lease_seconds']);Check::same($first->deliveryId(),$immutable->outbox()->status('tenant','orders',$message->id(),'alice')->deliveryId());
    foreach(['connection','integrity_keys','authority'] as $field){
        $bad=$config;unset($bad['outbox'][$field]);Check::throws(ConfigurationException::class,static function()use($bad):void{Security::fromArray($bad);});
        foreach(['missing','wrong'] as $serviceName){
            $bad=$config;$bad['outbox'][$field]=$serviceName;$wrong=$services;$wrong['wrong']=new stdClass();$broken=Security::fromArray($bad,$wrong,$e->clock);
            Check::throws(ConfigurationException::class,static function()use($broken):void{$broken->outbox();});Check::same('fail',array_column($broken->diagnose(),null,'check')['outbox.'.$field]['status']);
        }
    }
    foreach([['epoch'=>'bad'],['epoch'=>null],['unknown'=>1],['policy'=>['maximum_entries'=>0]],['policy'=>['unknown'=>1]],['policy'=>false],['management_guard'=>false]] as $change){
        $bad=$config;$bad['outbox']=array_replace($bad['outbox'],$change);Check::throws(ConfigurationException::class,static function()use($bad):void{Security::fromArray($bad);});
    }
    foreach(['missing','wrong'] as $name){$bad=$config;$bad['outbox']['management_guard']=$name;$wrong=$services;$wrong['wrong']=new stdClass();$broken=Security::fromArray($bad,$wrong,$e->clock);Check::throws(ConfigurationException::class,static function()use($broken):void{$broken->outbox();});Check::same('fail',array_column($broken->diagnose(),null,'check')['outbox.management_guard']['status']);}
    $config['outbox']['management_guard']=null;$normal=Security::fromArray($config,$services,$e->clock);Check::same('not_configured',array_column($normal->diagnose(),null,'check')['outbox.management_guard']['status']);
    $decisionCalls=0;$e->pdo->exec('BEGIN IMMEDIATE');
    try{outboxRefused('outbox.denied',static function()use($normal,$message,&$decisionCalls):void{$normal->outbox()->reconcile($message,'admin','received',str_repeat('a',64),static function()use(&$decisionCalls):bool{++$decisionCalls;return true;});});Check::same(0,$decisionCalls);}
    finally{$e->pdo->exec('ROLLBACK');}
    foreach(['reconciliation_evidence','resolution_audit','format_rollout'] as $name){Check::same('manual',array_column($normal->diagnose(),null,'check')['outbox.'.$name]['status']);}
    Check::same(false,$normal->outbox()->initialize('tenant','other','admin'));Check::same(null,$normal->outbox()->maintain('tenant','orders','admin'));Check::same(false,$normal->outbox()->retry('tenant','orders',$message->id(),'admin'));
    $claim=$normal->outbox()->claim('tenant','orders','worker');Check::same($message->body(),$claim->message()->body());Check::same(true,$normal->outbox()->acknowledge('tenant','orders','worker',$claim->token()));
    // Installing and probing schemas remains a host operation, including when diagnostics are explicitly requested.
    $e->pdo->exec('DROP TABLE sosecurity_outbox_records');$queries=$e->pdo->queries;$callsBefore=$calls;$uninstalled=Security::fromArray($config,$services,$e->clock);$uninstalled->diagnose(null,true);$missing=$uninstalled->outbox();
    Check::same($queries,$e->pdo->queries);Check::same($callsBefore,$calls);Check::throws(StorageException::class,static function()use($missing,$message):void{$missing->status('tenant','orders',$message->id(),'alice');});
    Check::same(0,(int)$e->pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sosecurity_outbox_records'")->fetchColumn());
});
$bare=Security::fromArray(['site'=>'unconfigured']);Check::same(null,$bare->config()->outbox());Check::throws(ConfigurationException::class,static function()use($bare):void{$bare->outbox();});
echo 'PASS SQL outbox factory: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; explicit services, no constructor/diagnostic SQL or authority calls\n";
