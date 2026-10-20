#!/usr/bin/env python3
"""Install the package through a fresh Composer path repository and execute its public API."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
composer = sys.argv[2] if len(sys.argv) > 2 else '/usr/local/bin/composer'
with tempfile.TemporaryDirectory(prefix='sosecurity-install-') as directory:
    manifest = {
        'name': 'sosecurity/integration-consumer',
        'repositories': [{'type': 'path', 'url': str(root), 'options': {'symlink': False}}],
        'require': {'sohophp/sosecurity': '@dev'},
        'config': {'allow-plugins': False}
    }
    Path(directory, 'composer.json').write_text(json.dumps(manifest))
    result = subprocess.run([runtime, composer, 'install', '--working-dir=' + directory,
                             '--no-interaction', '--no-progress'], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    Path(directory, 'verify.php').write_text('''<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';
$presets = require __DIR__ . '/vendor/sohophp/sosecurity/examples/configuration-presets.php';
if (SoSecurity\\Security::fromArray($presets['form_session'])->config()->tokenStorage()['driver'] !== 'session') { exit(13); }
$policy = SoSecurity\\Security::fromArray(['site'=>'password-consumer'])->passwordPolicy();
if ($policy->errors('passwordpassword') !== ['password.weak']) { exit(30); }
$checker = new SoSecurity\\Password\\PwnedPasswords(function () { return str_repeat('0',35).':0'; });
if ($checker('Public test phrase 39!') !== false) { exit(31); }
require __DIR__ . '/vendor/sohophp/sosecurity/examples/password-calibrate.php';
if (defined('PASSWORD_ARGON2ID')) {
    $argonPolicy = SoSecurity\\Security::fromArray(['site'=>'password-consumer','password'=>['profile'=>'argon2id']])->passwordPolicy();
    if ($argonPolicy->errors(str_repeat('A unique long phrase. ',5))) { exit(32); }
}
$store = new SoSecurity\\Storage\\MemoryStore();
$metricDirectory=__DIR__.'/audit-metrics';mkdir($metricDirectory,0700);
$metricStore=new SoSecurity\\Storage\\FileStore($metricDirectory,'consumer-audit');$metricWritten=0;
$metricSink=new SoSecurity\\Audit\\MetricsSink($metricStore,'consumer',
    ['login.failed'=>'authentication'],['authentication'=>1],2,60,
    static function(array $record)use(&$metricWritten):void{++$metricWritten;});
(new SoSecurity\\Audit\\AuditLogger($metricSink,str_repeat('K',32)))->record('login.failed','consumer','actor');
if($metricWritten!==1||$metricSink->inspect()['total']!==1||$metricSink->inspect()['alerts']!==['authentication']){exit(71);}
$metricBudget=new SoSecurity\\Audit\\BudgetedSink($metricStore,'consumer',2,60,$metricSink);
$diagnostics=new SoSecurity\\Audit\\Diagnostics($metricSink,$metricBudget,static function():bool{return true;});
if($diagnostics->inspect()['total']!==1||$diagnostics->inspect()['budget']['remaining']!==2){exit(126);}
$recent=new SoSecurity\\Audit\\RecentEvents($metricStore,'consumer',str_repeat('r',32),2,60,
    static function(array $record):void{},static function():bool{return true;});
(new SoSecurity\\Audit\\AuditLogger($recent,str_repeat('K',32)))->record('login.failed','consumer','actor');
if(count($recent->recent(2,'login.failed','consumer'))!==1){exit(128);}
$leases = new SoSecurity\\Concurrency\\LeaseManager($store);
if ($leases->inspect('consumer','resource')->initialized()) { exit(36); }
$leaseEpoch = $leases->initialize('consumer','resource');$lease = $leases->acquire('consumer','resource','worker');
if ($lease===null || $lease->epoch()!==$leaseEpoch || $leases->acquire('consumer','resource','other')!==null
    || !$leases->release('consumer','resource','worker',$lease->token()) || $leases->renew('consumer','resource','worker',$lease->token())!==null) { exit(37); }
require __DIR__ . '/vendor/sohophp/sosecurity/examples/leased-work.php';
$budget = new SoSecurity\\RateLimit\\BudgetLimiter($store,new SoSecurity\\RateLimit\\BudgetPolicy('token_bucket',5,60));
if (!$budget->consume('consumer','subject',3)->allowed() || $budget->consume('consumer','subject',3)->allowed()) { exit(34); }
$budgetGroup = new SoSecurity\\RateLimit\\BudgetGroup($store,['one'=>new SoSecurity\\RateLimit\\BudgetPolicy('fixed_window',1,60),'work'=>new SoSecurity\\RateLimit\\BudgetPolicy('sliding_window',5,60)]);
if (!$budgetGroup->consume('consumer','subject',['one'=>1,'work'=>3])->allowed() || $budgetGroup->consume('consumer','subject')->allowed()
    || $budgetGroup->inspect('consumer','subject')->decisions()['work']->remaining()!==2) { exit(35); }
require __DIR__ . '/vendor/sohophp/sosecurity/examples/request-budgets.php';
$authorizationActor = new SoSecurity\\Auth\\Account('consumer','actor','1',true,['editor']);
$authorizationSource = new SoSecurity\\Auth\\CallbackIdentityProvider(function () { return null; }, function () use ($authorizationActor) { return $authorizationActor; });
$authorizationResource = new SoSecurity\\Authorization\\Resource('consumer','document','one','1',['owner'=>'actor']);
$authorizationPolicy = new SoSecurity\\Authorization\\RolePolicy(['document.update'=>['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner']]);
$authorizer = new SoSecurity\\Authorization\\Authorizer($authorizationSource,$authorizationPolicy);
if (!$authorizer->decide('consumer',$authorizationActor,'document.update',$authorizationResource,['title'])->allowed()
    || $authorizer->decide('consumer',$authorizationActor,'document.update',$authorizationResource,['owner'])->allowed()) { exit(33); }
require __DIR__ . '/vendor/sohophp/sosecurity/examples/authorization.php';
require __DIR__ . '/vendor/sohophp/sosecurity/examples/operation-work.php';
$linkTarget=new SoSecurity\\Link\\Target('document.read',$authorizationResource,'/document',['id'=>'one']);
$linkService=new SoSecurity\\Link\\Links($store,new SoSecurity\\Support\\HmacKeys('consumer',['consumer'=>random_bytes(32)]),'consumer',new SoSecurity\\Link\\Policy('https://files.example'),function () {return true;});
$signedLink=$linkService->issue($linkTarget,true);
if ($linkService->verify($linkTarget,$signedLink->url(),'HEAD')!==null || $linkService->verify($linkTarget,$signedLink->url())===null || $linkService->verify($linkTarget,$signedLink->url())!==null) {exit(41);}
$signedLink=$linkService->issue($linkTarget);
if (!$linkService->revoke($linkTarget,$signedLink->id()) || $linkService->verify($linkTarget,$signedLink->url())!==null) {exit(42);}
$operationHasher=new SoSecurity\\Auth\\PasswordRecord(new SoSecurity\\Auth\\Account('consumer-operation','account','1',true,['editor']),password_hash('Consumer-test-password',PASSWORD_BCRYPT,['cost'=>10]));
$operationProvider=new SoSecurity\\Auth\\PasswordIdentityProvider(function () use ($operationHasher) {return $operationHasher;},function () use ($operationHasher) {return $operationHasher;},new SoSecurity\\Password\\PasswordHasher('bcrypt',['cost'=>10]),password_hash('Consumer-dummy-password',PASSWORD_BCRYPT,['cost'=>10]));
if ($operationProvider->find('consumer-operation','account')->fingerprint()!==$operationHasher->identity()->fingerprint() || $operationHasher->account()->version()!=='1') {exit(38);}
$operationSessions=new SoSecurity\\Auth\\SessionRegistry($store,$operationProvider);
$operationFlow=new SoSecurity\\Auth\\AuthenticationFlow($store,$operationProvider,$operationSessions,function () {return true;});
$operationAuthority=new SoSecurity\\Authorization\\Authorizer($operationProvider,$authorizationPolicy);
$operations=new SoSecurity\\Operation\\Grants($store,$operationSessions,$operationAuthority,function () {return true;},new SoSecurity\\Operation\\Policy(120,8,300,1,['password']));
$operationLogin=$operationFlow->password('consumer-operation','browser','account','Consumer-test-password');
$operationIntent=new SoSecurity\\Operation\\Intent('document.update',new SoSecurity\\Authorization\\Resource('consumer-operation','document','a','1',['owner'=>'account']),['title'=>'Consumer reviewed title'],['title']);
$operationPending=$operations->begin('consumer-operation','account',$operationLogin->credential()->token(),$operationIntent);
if ($operations->confirm('consumer-operation','account',$operationLogin->credential()->token(),$operationIntent,$operationPending->token())!==null) {exit(39);}
$operationLogin=$operationFlow->password('consumer-operation','browser','account','Consumer-test-password','',$operationLogin->credential()->token());
$operationGrant=$operations->confirm('consumer-operation','account',$operationLogin->credential()->token(),$operationIntent,$operationPending->token());
if ($operationGrant===null || $operations->consume('consumer-operation','account',$operationLogin->credential()->token(),$operationIntent,$operationGrant->token())===null || $operations->consume('consumer-operation','account',$operationLogin->credential()->token(),$operationIntent,$operationGrant->token())!==null) {exit(40);}
$credentials=new SoSecurity\\Api\\CredentialRegistry($store,$operationSessions,$operationProvider,new SoSecurity\\Support\\HmacKeys('consumer',['consumer'=>random_bytes(32)]),'consumer-api',function () {return true;},function () {return ['documents:read'];},new SoSecurity\\Api\\CredentialPolicy(['allowed_scopes'=>['documents:read']]));
$apiCredential=$credentials->issue('consumer-operation','account',$operationLogin->credential()->token(),'Consumer tool',['documents:read']);
if ($credentials->fromAuthorization('consumer-operation','Bearer '.$apiCredential->token(),'documents:read')===null || count($credentials->all('consumer-operation','account',$operationLogin->credential()->token()))!==1) {exit(48);}
$apiRotated=$credentials->rotate('consumer-operation','account',$operationLogin->credential()->token(),$apiCredential->metadata()->id(),1);
if ($apiRotated===null || $apiRotated->metadata()->generation()!==2 || $credentials->authenticate('consumer-operation',$apiCredential->token(),'documents:read')!==null || $credentials->authenticate('consumer-operation',$apiRotated->token(),'documents:read')===null || $credentials->revokeAll('consumer-operation','account',$operationLogin->credential()->token())!==1 || $credentials->authenticate('consumer-operation',$apiRotated->token(),'documents:read')!==null) {exit(49);}
$webhookConfig=['site'=>'consumer-webhook','webhooks'=>['events'=>['scope'=>'consumer','account'=>'provider','url'=>'https://hooks.example/events','protocol'=>'standard-hmac','key_provider'=>'endpoint_keys','request_guard'=>'boundary']]];
$webhookServices=['endpoint_keys'=>function ($endpoint) {return SoSecurity\\Webhook\\KeySet::fromEncoded($endpoint,['test'=>'whsec_'.base64_encode(str_repeat('w',32))]);},'boundary'=>function () {return true;}];
$webhookSecurity=SoSecurity\\Security::fromArray($webhookConfig,$webhookServices);$webhookTime=time();$webhookBody='{"type":"document.changed"}';$webhookSignature=base64_encode(hash_hmac('sha256','consumer_msg.'.$webhookTime.'.'.$webhookBody,str_repeat('w',32),true));
$webhookRequest=new SoSecurity\\Webhook\\Request('POST','https://hooks.example/events',$webhookBody,['Webhook-Id'=>'consumer_msg','Webhook-Timestamp'=>(string)$webhookTime,'Webhook-Signature'=>'v1,'.$webhookSignature]);
if ($webhookSecurity->webhook('events')->verify($webhookRequest)===null || $webhookSecurity->config()->webhooks()['events']['policy']['maximum_body']!==65536) {exit(50);}
try {$webhookSecurity->webhookInbox('events');exit(51);}catch(SoSecurity\\Exception\\ConfigurationException $error) {}
if (extension_loaded('pdo_sqlite')) {
    $webhookDatabase=__DIR__.'/receive.sqlite';$webhookPdo=new PDO('sqlite:'.$webhookDatabase,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($webhookDatabase,0600);
    $webhookPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/webhook-sqlite.sql'));
    $webhookConfig['webhooks']['events']['inbox']=['connection'=>'receive_db','integrity_keys'=>'seals','association_guard'=>'association'];$webhookServices['receive_db']=$webhookPdo;$webhookServices['seals']=new SoSecurity\\Support\\HmacKeys('consumer',['consumer'=>random_bytes(32)]);$webhookServices['association']=function () {return true;};
    $webhookInbox=SoSecurity\\Security::fromArray($webhookConfig,$webhookServices)->webhookInbox('events');$map=function ($proof) {return new SoSecurity\\Webhook\\Message($proof->messageId(),'document.changed','resource',['version'=>'1']);};
    $webhookReceived=$webhookInbox->accept($webhookRequest,$map);$webhookAgain=$webhookInbox->accept($webhookRequest,$map);
    if ($webhookReceived===null || $webhookReceived->duplicate() || $webhookAgain===null || !$webhookAgain->duplicate() || $webhookAgain->id()!==$webhookReceived->id() || (int)$webhookPdo->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn()!==1) {exit(52);}
    $webhookPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/webhook-processing-sqlite.sql'));
    $webhookPdo->exec('CREATE TABLE consumer_effects(message_id TEXT NOT NULL PRIMARY KEY,resource TEXT NOT NULL)');
    $processingMapper=function ($body,$endpoint,$receiptId,$metadata) {return new SoSecurity\\Webhook\\Message($metadata['message_id'],'document.changed','resource',['version'=>'1']);};
    $workerConfig=$webhookConfig;unset($workerConfig['webhooks']['events']['inbox'],$workerConfig['webhooks']['events']['key_provider'],$workerConfig['webhooks']['events']['request_guard']);
    $workerConfig['webhooks']['events']['processing']=['connection'=>'db','integrity_keys'=>'seals','mapper'=>'map','association_guard'=>'association','worker_guard'=>'worker'];
    $workerSecurity=SoSecurity\\Security::fromArray($workerConfig,['db'=>$webhookPdo,'seals'=>$webhookServices['seals'],'map'=>$processingMapper,'association'=>function () {return true;},'worker'=>function () {return true;}]);
    $processor=$workerSecurity->webhookProcessor('events');
    if ($workerSecurity->config()->webhooks()['events']['processing']['policy']['maximum_attempts']!==5) {exit(56);}
    try {$workerSecurity->webhook('events');exit(57);}catch(SoSecurity\\Exception\\ConfigurationException $error) {}
    $claim=$processor->claim($webhookReceived->id(),'consumer');
    if ($claim===null || $processor->claim($webhookReceived->id(),'consumer')!==null) {exit(54);}
    $business=function ($pdo,$message) {$statement=$pdo->prepare('INSERT INTO consumer_effects VALUES(:id,:resource)');$statement->execute(['id'=>$message->id(),'resource'=>$message->resource()]);return true;};
    $finished=$processor->execute('consumer',$claim->token(),$business);
    if ($finished===null || $finished->status()!=='succeeded' || $processor->execute('consumer',$claim->token(),$business)!==null || $processor->claim($webhookReceived->id(),'consumer')!==null || (int)$webhookPdo->query('SELECT COUNT(*) FROM consumer_effects')->fetchColumn()!==1) {exit(55);}
    $webhookPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/idempotency-sqlite.sql'));
    $idempotentConfig=['site'=>'consumer-idempotency','idempotency'=>['connection'=>'db','epoch'=>str_repeat('e',64),'integrity_keys'=>'seals','authority'=>'current','management_guard'=>'manager']];
    $idempotentSecurity=SoSecurity\\Idempotency\\SqlExecutor::class;
    $idempotentFactory=SoSecurity\\Security::fromArray($idempotentConfig,['db'=>$webhookPdo,'seals'=>new SoSecurity\\Support\\HmacKeys('consumer',['consumer'=>random_bytes(32)]),'current'=>function () {return true;},'manager'=>function () {return true;}]);
    $idempotent=$idempotentFactory->idempotency();
    if (!$idempotent instanceof $idempotentSecurity || !$idempotent->initialize('consumer','account','orders.create')) {exit(70);}
    $idempotentRequest=new SoSecurity\\Idempotency\\Request('consumer','account','orders.create','consumer-request-0001','POST','/orders','{"reference":"consumer-order"}');
    $idempotentCalls=0;$idempotentHandler=function ($pdo,$request,$execution) use (&$idempotentCalls) {++$idempotentCalls;$statement=$pdo->prepare('INSERT INTO consumer_effects VALUES(:id,:resource)');$statement->execute(['id'=>'consumer-order','resource'=>$execution]);return new SoSecurity\\Idempotency\\Response(201,'{"created":true}');};
    $idempotentFirst=$idempotent->execute($idempotentRequest,$idempotentHandler);$idempotentAgain=$idempotent->execute($idempotentRequest,$idempotentHandler);
    if ($idempotentFirst===null || $idempotentFirst->replayed() || $idempotentAgain===null || !$idempotentAgain->replayed() || $idempotentFirst->executionId()!==$idempotentAgain->executionId() || $idempotentAgain->response()->body()!=='{"created":true}' || $idempotentCalls!==1) {exit(71);}
    require __DIR__.'/vendor/sohophp/sosecurity/examples/idempotency-business.php';
    $webhookPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/idempotency-example-sqlite.sql'));
    $webhookPdo->exec("INSERT INTO idempotency_example_accounts VALUES('idempotency-example','consumer','1',1,'[\\"orders_writer\\"]')");
    $nativeApi=new SoSecurity\\Api\\ApiKeys($store);$nativeCredential=$nativeApi->issue('consumer@1',['orders:create']);$nativeHeader='Bearer '.$nativeCredential->token();
    $nativeIdentity=SoSecurity\\Examples\\Idempotency\\authenticated($webhookPdo,$nativeApi,$nativeHeader);if ($nativeIdentity===null) {exit(72);}
    $nativeSettings=['pdo'=>$webhookPdo,'keys'=>new SoSecurity\\Support\\HmacKeys('consumer',['consumer'=>random_bytes(32)]),'epoch'=>str_repeat('e',64),'policy'=>[]];
    $nativeFactory=SoSecurity\\Examples\\Idempotency\\factory($nativeSettings,SoSecurity\\Examples\\Idempotency\\authority($webhookPdo,$nativeApi,$nativeHeader,$nativeIdentity[0],$nativeIdentity[1]),function () {return true;});
    $nativeExecutor=$nativeFactory->idempotency();$nativeExecutor->initialize('idempotency-example','consumer','orders.create');
    $nativeServer=['REQUEST_METHOD'=>'POST','REQUEST_URI'=>'/idempotency.php','HTTP_IDEMPOTENCY_KEY'=>'consumer-native-request-01'];$nativeBody='{"reference":"native-order","amount":500}';
    $nativeRequest=SoSecurity\\Examples\\Idempotency\\request($nativeIdentity[0],$nativeIdentity[1],$nativeServer,$nativeBody);$nativeFirst=$nativeExecutor->execute($nativeRequest,'SoSecurity\\\\Examples\\\\Idempotency\\\\createOrder');
    $nativeServer['HTTP_IDEMPOTENCY_KEY']='consumer-native-request-02';$nativeRequest=SoSecurity\\Examples\\Idempotency\\request($nativeIdentity[0],$nativeIdentity[1],$nativeServer,$nativeBody);$nativeAgain=$nativeExecutor->execute($nativeRequest,'SoSecurity\\\\Examples\\\\Idempotency\\\\createOrder');
    if ($nativeFirst===null || $nativeAgain===null || $nativeFirst->response()->body()!==$nativeAgain->response()->body() || (int)$webhookPdo->query('SELECT COUNT(*) FROM idempotency_example_orders')->fetchColumn()!==1 || (int)$webhookPdo->query('SELECT COUNT(*) FROM idempotency_example_executions')->fetchColumn()!==2) {exit(73);}
    $webhookPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/outbox-sqlite.sql'));
    $outboxAuditClock=new class implements SoSecurity\\Support\\Clock {public $time=100000;public function now():int {return $this->time;}};
    $outboxConfig=['site'=>'consumer-outbox','outbox'=>['connection'=>'db','epoch'=>str_repeat('e',64),'integrity_keys'=>'seals','authority'=>'current','management_guard'=>'manager','policy'=>['message_age'=>3,'recovery_age'=>6,'retention_seconds'=>0]]];
    $outboxFactory=SoSecurity\\Security::fromArray($outboxConfig,['db'=>$webhookPdo,'seals'=>new SoSecurity\\Support\\HmacKeys('consumer',['consumer'=>random_bytes(32)]),'current'=>function () {return true;},'manager'=>function () {return true;}],$outboxAuditClock);
    $outbox=$outboxFactory->outbox();$outboxChecks=array_column($outboxFactory->diagnose(),null,'check');
    if (!$outbox->initialize('consumer','orders','administrator') || $outboxFactory->config()->outbox()['policy']['maximum_payload_bytes']!==65536 || $outboxChecks['outbox.receiver_deduplication']['status']!=='manual') {exit(74);}
    $outboxBody='consumer'.chr(0).chr(255).'outbox';$outboxMessage=new SoSecurity\\Outbox\\Message('consumer','orders',SoSecurity\\Outbox\\Message::identifier('consumer-business-event',$outboxAuditClock->time),'receiver','order.created','consumer-order',$outboxBody);
    $webhookPdo->beginTransaction();$webhookPdo->exec("INSERT INTO consumer_effects VALUES('consumer-outbox-business','v1')");$outbox->enqueue($outboxMessage,'consumer');$webhookPdo->rollBack();
    if ((int)$webhookPdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn()!==0 || (int)$webhookPdo->query("SELECT COUNT(*) FROM consumer_effects WHERE message_id='consumer-outbox-business'")->fetchColumn()!==0) {exit(75);}
    $webhookPdo->beginTransaction();$webhookPdo->exec("INSERT INTO consumer_effects VALUES('consumer-outbox-business','v1')");$outboxQueued=$outbox->enqueue($outboxMessage,'consumer');$webhookPdo->commit();
    $webhookPdo->beginTransaction();$outboxRepeated=$outbox->enqueue($outboxMessage,'consumer');$webhookPdo->commit();
    if ($outboxQueued->order()!==1 || $outboxRepeated->deliveryId()!==$outboxQueued->deliveryId() || (int)$webhookPdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn()!==1 || (int)$webhookPdo->query("SELECT COUNT(*) FROM consumer_effects WHERE message_id='consumer-outbox-business'")->fetchColumn()!==1) {exit(76);}
    $outboxClaim=$outbox->claim('consumer','orders','consumer-worker');
    if ($outboxClaim===null || $outboxClaim->message()->body()!==$outboxBody || !$outbox->acknowledge('consumer','orders','consumer-worker',$outboxClaim->token()) || !$outbox->acknowledge('consumer','orders','consumer-worker',$outboxClaim->token()) || $outbox->claim('consumer','orders','consumer-worker')!==null) {exit(77);}
    $expiredMessage=new SoSecurity\\Outbox\\Message('consumer','orders',SoSecurity\\Outbox\\Message::identifier('consumer-expired-event',$outboxAuditClock->time),'receiver','order.created','consumer-order',$outboxBody);
    $webhookPdo->beginTransaction();$outbox->enqueue($expiredMessage,'consumer');$webhookPdo->commit();$outboxAuditClock->time+=6;$outbox->maintain('consumer','orders','consumer-admin');
    $webhookPdo->exec('CREATE TABLE consumer_outbox_decisions(event_id TEXT NOT NULL PRIMARY KEY,fingerprint TEXT NOT NULL,evidence TEXT NOT NULL)');$evidenceDigest=hash('sha256','consumer-synthetic-decision');
    $recordDecision=function () use($webhookPdo,$expiredMessage,$evidenceDigest) {$q=$webhookPdo->prepare('INSERT INTO consumer_outbox_decisions VALUES(?,?,?)');$q->execute([$expiredMessage->id(),$expiredMessage->fingerprint(),$evidenceDigest]);$q->closeCursor();};
    $currentDecision=function ($phase,$metadata) use($webhookPdo,$expiredMessage,$evidenceDigest) {
        if ($metadata['outcome']!=='cancelled' || $metadata['id']!==$expiredMessage->id() || $metadata['fingerprint']!==$expiredMessage->fingerprint() || $metadata['evidence_digest']!==$evidenceDigest) {return false;}
        $q=$webhookPdo->prepare('SELECT 1 FROM consumer_outbox_decisions WHERE event_id=? AND fingerprint=? AND evidence=?');$q->execute([$metadata['id'],$metadata['fingerprint'],$metadata['evidence_digest']]);$found=$q->fetchColumn()!==false;$q->closeCursor();return $found;
    };
    $webhookPdo->beginTransaction();$recordDecision();$outbox->reconcile($expiredMessage,'consumer-admin','cancelled',$evidenceDigest,$currentDecision);$webhookPdo->rollBack();
    if ($outbox->status('consumer','orders',$expiredMessage->id(),'consumer')->state()!=='dead' || (int)$webhookPdo->query('SELECT COUNT(*) FROM consumer_outbox_decisions')->fetchColumn()!==0) {exit(116);}
    $webhookPdo->beginTransaction();$recordDecision();$changed=$outbox->reconcile($expiredMessage,'consumer-admin','cancelled',$evidenceDigest,$currentDecision);$webhookPdo->commit();$resolved=$outbox->status('consumer','orders',$expiredMessage->id(),'consumer');
    if (!$changed || $resolved->state()!=='resolved' || $resolved->resolution()!=='cancelled' || $resolved->sentAt()!==0 || $outbox->maintain('consumer','orders','consumer-admin')['purged']!==1 || (int)$webhookPdo->query('SELECT COUNT(*) FROM consumer_outbox_decisions')->fetchColumn()!==1) {exit(117);}
    require __DIR__.'/vendor/sohophp/sosecurity/examples/outbox-business.php';
    foreach (['outbox-producer','outbox-worker','outbox-admin','outbox-receiver','outbox-receiver-admin'] as $entry) {require __DIR__.'/vendor/sohophp/sosecurity/examples/'.$entry.'.php';}
    foreach (['outbox-web','outbox-sender-state','outbox-receiver-state'] as $part) {mkdir(__DIR__.'/'.$part,0700);}
    $outboxNativeSettings=[];$outboxNativeAdapters=[];
    foreach (['sender','receiver'] as $role) {
        $database=__DIR__.'/outbox-'.$role.'.sqlite';$connection=new PDO('sqlite:'.$database,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($database,0600);
        $schemas=$role==='sender'?['outbox-sqlite','idempotency-sqlite','outbox-example-sender-sqlite']:['webhook-sqlite','webhook-processing-sqlite','outbox-example-receiver-sqlite'];
        foreach ($schemas as $schema) {$connection->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/'.$schema.'.sql'));}
        if ($role==='sender') {$connection->exec("INSERT INTO outbox_example_actors VALUES('consumer','1',1,'[\\"orders_writer\\",\\"outbox_worker\\",\\"outbox_admin\\"]')");$nativeSenderPdo=$connection;}
        else {$connection->exec("INSERT INTO outbox_example_actors VALUES('consumer','1',1,'[\\"receiver_worker\\",\\"receiver_admin\\"]')");$connection->exec("INSERT INTO outbox_example_routes VALUES('outbox-publisher','outbox-example',1)");$connection->exec("INSERT INTO outbox_example_owners VALUES('consumer',1)");$nativeReceiverPdo=$connection;}
        $outboxNativeSettings[$role]=['role'=>$role,'document_root'=>__DIR__.'/outbox-web','database'=>$database,'storage'=>__DIR__.'/outbox-'.$role.'-state','actor'=>'consumer','version'=>'1','epoch'=>str_repeat('e',64),'url'=>'https://receiver.example.com/outbox-receiver.php','seals'=>__DIR__.'/outbox-'.$role.'-seals.json','wire_keys'=>__DIR__.'/outbox-wire.json'];
    }
    foreach (['sender-seals','receiver-seals','wire','idem'] as $purpose) {$keyfile=__DIR__.'/outbox-'.$purpose.'.json';file_put_contents($keyfile,json_encode(['current'=>'consumer','keys'=>['consumer'=>base64_encode(random_bytes(32))]]));chmod($keyfile,0600);}
    $outboxNativeSettings['sender']['idempotency_keys']=__DIR__.'/outbox-idem.json';
    $checkpointPdo=new PDO('sqlite:'.__DIR__.'/outbox-checkpoint.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod(__DIR__.'/outbox-checkpoint.sqlite',0600);$checkpointPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/outbox-example-checkpoint-sqlite.sql'));file_put_contents(__DIR__.'/outbox-checkpoint.lock','');chmod(__DIR__.'/outbox-checkpoint.lock',0600);$outboxNativeSettings['receiver']['checkpoint_database']=__DIR__.'/outbox-checkpoint.sqlite';$outboxNativeSettings['receiver']['checkpoint_lock']=__DIR__.'/outbox-checkpoint.lock';
    foreach ($outboxNativeSettings as $role=>$configuration) {$file=__DIR__.'/outbox-'.$role.'.json';file_put_contents($file,json_encode($configuration));chmod($file,0600);putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$file);$outboxNativeAdapters[$role]=SoSecurity\\Examples\\Outbox\\settings($role);}
    putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');$senderAdapter=$outboxNativeAdapters['sender'];$receiverAdapter=$outboxNativeAdapters['receiver'];
    SoSecurity\\Examples\\Outbox\\receiverInitialize($receiverAdapter);
    SoSecurity\\Examples\\Outbox\\outbox($senderAdapter)->initialize(SoSecurity\\Examples\\Outbox\\SCOPE,SoSecurity\\Examples\\Outbox\\PRODUCER,'consumer');SoSecurity\\Examples\\Outbox\\idempotency($senderAdapter)->initialize(SoSecurity\\Examples\\Outbox\\SCOPE,'consumer','orders.create');
    $nativeOrder=SoSecurity\\Examples\\Outbox\\produce($senderAdapter,'installed-outbox-key-001','installed-order',500);$nativeDuplicate=SoSecurity\\Examples\\Outbox\\produce($senderAdapter,'installed-outbox-key-001','installed-order',500);
    if (!$nativeDuplicate['replayed'] || $nativeOrder['result']!==$nativeDuplicate['result'] || (int)$nativeSenderPdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn()!==1) {exit(78);}
    $nativeClaim=SoSecurity\\Examples\\Outbox\\outbox($senderAdapter)->claim(SoSecurity\\Examples\\Outbox\\SCOPE,SoSecurity\\Examples\\Outbox\\PRODUCER,'consumer');$nativeBody=$nativeClaim->message()->body();$nativeId=$nativeClaim->status()->deliveryId();$nativeTime=(string)time();$wire=SoSecurity\\Examples\\Outbox\\keyData(__DIR__.'/outbox-wire.json');
    $nativeRequest=new SoSecurity\\Webhook\\Request('POST',$receiverAdapter['url'],$nativeBody,['Webhook-Id'=>$nativeId,'Webhook-Timestamp'=>$nativeTime,'Webhook-Signature'=>'v1,'.base64_encode(hash_hmac('sha256',$nativeId.'.'.$nativeTime.'.'.$nativeBody,$wire['keys'][$wire['current']],true))]);
    $nativeConfirmation=SoSecurity\\Examples\\Outbox\\receive($receiverAdapter,$nativeRequest,function () {return true;});$nativeReceiverPdo->exec('DELETE FROM sosecurity_webhook_processing');$nativeReceiverPdo->exec('DELETE FROM sosecurity_webhook_inbox');$nativeRecovered=SoSecurity\\Examples\\Outbox\\receive($receiverAdapter,$nativeRequest,function () {return true;});
    if ($nativeConfirmation!==$nativeRecovered || !$nativeConfirmation['committed'] || (int)$nativeReceiverPdo->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn()!==1 || !SoSecurity\\Examples\\Outbox\\outbox($senderAdapter)->acknowledge(SoSecurity\\Examples\\Outbox\\SCOPE,SoSecurity\\Examples\\Outbox\\PRODUCER,'consumer',$nativeClaim->token())) {exit(79);}
    $receiverStatus=SoSecurity\\Examples\\Outbox\\receiverInspect($receiverAdapter);$outboxNativeSettings['receiver']['epoch']=str_repeat('f',64);file_put_contents(__DIR__.'/outbox-receiver.json',json_encode($outboxNativeSettings['receiver']));
    putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.__DIR__.'/outbox-receiver.json');$receiverAdapter=SoSecurity\\Examples\\Outbox\\settings('receiver');putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');
    if (!SoSecurity\\Examples\\Outbox\\receiverRotateEpoch($receiverAdapter,$receiverStatus['epoch'],$receiverStatus['root_hash']) || SoSecurity\\Examples\\Outbox\\receiverRecover($receiverAdapter) || SoSecurity\\Examples\\Outbox\\receive($receiverAdapter,$nativeRequest,function () {return true;})!==$nativeConfirmation || (int)$nativeReceiverPdo->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn()!==1) {exit(80);}
    if (function_exists('sodium_crypto_sign_seed_keypair')) {
        $nativeSenderPdo->prepare('UPDATE outbox_example_actors SET roles=?')->execute([json_encode(['orders_writer','outbox_worker','outbox_admin','outbox_reconciler'])]);
        $nativeReceiverPdo->prepare('UPDATE outbox_example_actors SET roles=?')->execute([json_encode(['receiver_worker','receiver_admin','receiver_reconciler'])]);
        $seedFile=__DIR__.'/outbox-resolution-seeds.json';file_put_contents($seedFile,json_encode(['current'=>'consumer','keys'=>['consumer'=>base64_encode(random_bytes(32))]]));chmod($seedFile,0600);$outboxNativeSettings['receiver']['resolution_keys']=$seedFile;
        file_put_contents(__DIR__.'/outbox-receiver.json',json_encode($outboxNativeSettings['receiver']));putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.__DIR__.'/outbox-receiver.json');$receiverAdapter=SoSecurity\\Examples\\Outbox\\settings('receiver');
        $public=SoSecurity\\Examples\\Outbox\\resolutionPublicKeys($receiverAdapter);$publicFile=__DIR__.'/outbox-resolution-public.json';file_put_contents($publicFile,json_encode($public));chmod($publicFile,0600);
        $outboxNativeSettings['sender']['resolution_keys']=$publicFile;$outboxNativeSettings['sender']['receiver_epoch']=$receiverAdapter['epoch'];file_put_contents(__DIR__.'/outbox-sender.json',json_encode($outboxNativeSettings['sender']));putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.__DIR__.'/outbox-sender.json');$senderAdapter=SoSecurity\\Examples\\Outbox\\settings('sender');putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');
        $request=json_encode(['format'=>1,'challenge'=>bin2hex(random_bytes(32)),'body'=>base64_encode($nativeBody),'delivery_id'=>$nativeId]);$proof=SoSecurity\\Examples\\Outbox\\resolutionTerminal($receiverAdapter,$request);$verified=SoSecurity\\Examples\\Outbox\\resolutionReceipt($proof,base64_decode($public['keys'][$public['current']],true));
        if ($verified['outcome']!=='received' || $verified['delivery_id']!==$nativeId || $verified['body_digest']!==hash('sha256',$nativeBody) || !SoSecurity\\Examples\\Outbox\\resolutionInitialize($senderAdapter)) {exit(118);}
        $archiveBaseline=SoSecurity\\Examples\\Outbox\\resolutionAuditStatus($senderAdapter)['root_hash'];
        $outboxNativeSettings['sender']['resolution_archive']=true;file_put_contents(__DIR__.'/outbox-sender.json',json_encode($outboxNativeSettings['sender']));putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.__DIR__.'/outbox-sender.json');$senderAdapter=SoSecurity\\Examples\\Outbox\\settings('sender');putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');
        if (!SoSecurity\\Examples\\Outbox\\resolutionArchiveInitialize($senderAdapter,$archiveBaseline) || SoSecurity\\Examples\\Outbox\\resolutionArchive($senderAdapter)['archived']!==0 || SoSecurity\\Examples\\Outbox\\resolutionRekey($senderAdapter,true)['rekeyed']!==0) {exit(119);}

    }
    if (class_exists('SQLite3',false)) {
        foreach (['sender','receiver'] as $role) {
            $authorityFile=__DIR__.'/outbox-'.$role.'-authority.sqlite';$authorityPdo=new PDO('sqlite:'.$authorityFile,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($authorityFile,0600);$authorityPdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/outbox-example-authority-sqlite.sql'));
            $roles=$role==='sender'?['orders_writer','outbox_worker','outbox_admin','outbox_reconciler']:['receiver_worker','receiver_admin','receiver_reconciler'];
            $authorityPdo->prepare("INSERT INTO outbox_example_actors VALUES('consumer','1',1,?)")->execute([json_encode($roles)]);$authorityPdo->exec("INSERT INTO outbox_example_routes VALUES('outbox-publisher','outbox-example',1)");$authorityPdo->exec("INSERT INTO outbox_example_owners VALUES('consumer',1)");
            $outboxNativeSettings[$role]['authority_database']=$authorityFile;file_put_contents(__DIR__.'/outbox-'.$role.'.json',json_encode($outboxNativeSettings[$role]));putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.__DIR__.'/outbox-'.$role.'.json');$authorityAdapter=SoSecurity\\Examples\\Outbox\\settings($role);putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');
            if (!SoSecurity\\Examples\\Outbox\\principal($authorityAdapter,$role==='sender'?'outbox_admin':'receiver_admin')) {exit(120);}
            $authorityPdo->exec('UPDATE outbox_example_actors SET enabled=0');
            if (SoSecurity\\Examples\\Outbox\\principal($authorityAdapter,$role==='sender'?'outbox_admin':'receiver_admin')) {exit(121);}
            $authorityPdo->exec('UPDATE outbox_example_actors SET enabled=1');
            if ($role==='receiver') {
                foreach (['actors','routes','owners'] as $table) {$nativeReceiverPdo->exec('DELETE FROM outbox_example_'.$table);}
                if (SoSecurity\\Examples\\Outbox\\receive($authorityAdapter,$nativeRequest,function () {return true;})!==$nativeConfirmation) {exit(122);}
            }
        }
    } elseif (getenv('SOSECURITY_REQUIRE_AUTHORITY')==='1') {exit(123);}
    unlink($webhookDatabase);
} elseif (getenv('SOSECURITY_REQUIRE_RESET')==='1') {exit(53);}
$privateRoot=__DIR__.'/download-source';$privateTemporary=__DIR__.'/download-temporary';$privateWeb=__DIR__.'/public';foreach ([$privateRoot,$privateTemporary,$privateWeb] as $part) {mkdir($part,0700);}
$binary='Consumer'.chr(0).chr(255).'file';file_put_contents($privateRoot.'/a.bin',$binary);chmod($privateRoot.'/a.bin',0600);
try {
    $downloadFile=new SoSecurity\\Download\\File(new SoSecurity\\Authorization\\Resource('consumer-operation','file','a','1',['owner'=>'account']),'a.bin','consumer.bin',strlen($binary),hash('sha256',$binary));
    $downloadAuthority=new SoSecurity\\Authorization\\Authorizer($operationProvider,new SoSecurity\\Authorization\\RolePolicy(['file.download'=>['type'=>'file','roles'=>['editor'],'fields'=>[],'owner_attribute'=>'owner']]));
    $downloads=new SoSecurity\\Download\\Downloads($privateRoot,$privateTemporary,$privateWeb);
    $downloadAccess=new SoSecurity\\Download\\SessionAccess($operationSessions,$downloadAuthority,'consumer-operation','account',$operationLogin->credential()->token(),function () {return true;});
    $reload=function () use ($downloadFile) {return $downloadFile;};$transfer=$downloads->prepare($downloadFile,new SoSecurity\\Download\\Request(),$downloadAccess,$reload);
    file_put_contents($privateRoot.'/a.bin',str_repeat('X',strlen($binary)));$received='';$transfer->send(function ($chunk) use (&$received) {$received.=$chunk;return strlen($chunk);});
    if ($received!==$binary || !$transfer->complete() || glob($privateTemporary.'/.download-*')!==[]) {exit(43);}
    file_put_contents($privateRoot.'/a.bin',$binary);
    $transfer=$downloads->prepare($downloadFile,new SoSecurity\\Download\\Request('GET',['Range'=>'bytes=1-3']),$downloadAccess,$reload);
    if ($transfer->status()!==206 || $transfer->read()!==substr($binary,1,3)) {exit(44);}
    $targetFactory=function ($file) {return new SoSecurity\\Link\\Target('file.download',$file->resource(),'/download',['id'=>'a']);};
    $signed=$linkService->issue($targetFactory($downloadFile),true);$signedAccess=new SoSecurity\\Download\\LinkAccess($linkService,$targetFactory,$signed->url());
    try {$downloads->prepare($downloadFile,new SoSecurity\\Download\\Request('HEAD'),$signedAccess,$reload);exit(45);} catch (SoSecurity\\Exception\\SecurityException $error) {}
    $transfer=$downloads->prepare($downloadFile,new SoSecurity\\Download\\Request(),$signedAccess,$reload);if ($transfer->read()!==$binary) {exit(46);}
    try {$downloads->prepare($downloadFile,new SoSecurity\\Download\\Request(),$signedAccess,$reload);exit(47);} catch (SoSecurity\\Exception\\SecurityException $error) {}
} finally {unlink($privateRoot.'/a.bin');foreach ([$privateRoot,$privateTemporary,$privateWeb] as $part) {rmdir($part);}}
$captcha = new SoSecurity\\Captcha\\Captcha($store);
$math = $captcha->arithmetic('installed', 'binding', 'divide');
preg_match('/^(\\d+) \\/ (\\d+)/', $math->prompt, $parts);
if (!$captcha->verify('installed', 'binding', $math->id, (string) intdiv((int) $parts[1], (int) $parts[2]))) { exit(14); }
if (extension_loaded('gd')) {
    foreach (['imageDigits', 'imageLetters', 'imageArithmetic', 'slider', 'click'] as $method) {
        if (substr($captcha->$method('installed', 'binding')->image, 0, 4) !== "\\x89PNG") { exit(15); }
    }
}
$hcaptcha = new SoSecurity\\Captcha\\HCaptcha('installed-test-secret-only', 'expected-sitekey', function () { return '{"success":true}'; });
$recaptcha = new SoSecurity\\Captcha\\Recaptcha('installed-test-secret-only', 'site.example', 'login', 0.5,
    function () { return '{"success":true,"hostname":"site.example","action":"login","score":0.7}'; });
if (!$hcaptcha->verify('test-token') || !$recaptcha->verify('test-token')) { exit(16); }
require __DIR__ . '/vendor/sohophp/sosecurity/examples/captcha-types.php';
if (SoSecurity\\Examples\\createCaptchaChallenge($captcha, 'multiply', 'installed', 'binding')->image !== null) { exit(17); }
$csrf = new SoSecurity\\Csrf\\CsrfTokens($store);
$token = $csrf->issue('form', 'session-binding');
if (!$csrf->verify('form', 'session-binding', $token, true)
    || $csrf->verify('form', 'session-binding', $token, true)) { exit(1); }
if (!(new SoSecurity\\Validation\\Validator(['age' => ['type' => 'integer', 'min' => 18]]))->validate(['age' => 20])->valid()) { exit(3); }
if (strpos(SoSecurity\\Storage\\MySqlStore::schema(), 'ENGINE=InnoDB') === false) { exit(4); }
if ((new SoSecurity\\Upload\\Policy())->maximumBytes() !== 5242880) { exit(5); }
if (!(new SoSecurity\\Http\\Redirects('https://site.example'))->allows('/home')) { exit(6); }
$rate = new SoSecurity\\RateLimit\\RateLimiter($store);
if (!$rate->consume('login', 'ip-account')->allowed) { exit(2); }
$keys = new SoSecurity\\Api\\ApiKeys($store);
$credential = $keys->issue('installed-client', ['read']);
if ($keys->authenticate($credential->token(), 'read')->subject() !== 'installed-client') { exit(7); }
$key = SoSecurity\\Api\\SigningKey::generate('installed-client', ['read']);
$policy = new SoSecurity\\Api\\SignaturePolicy(['origin'=>'https://api.example.com']);
$headers = (new SoSecurity\\Api\\HmacSigner($policy, $key))->sign('POST','https://api.example.com/a','{}');
$verifier = new SoSecurity\\Api\\HmacVerifier($policy,new SoSecurity\\Api\\KeyRing([$key]),new SoSecurity\\Api\\NonceStore($store));
if ($verifier->verify('POST','https://api.example.com/a','{}',$headers,'read') === null || $verifier->verify('POST','https://api.example.com/a','{}',$headers) !== null) { exit(8); }
$signedCsrf = new SoSecurity\\Csrf\\SignedTokens(new SoSecurity\\Support\\HmacKeys('install',['install'=>random_bytes(32)]),'consumer');
$signedToken = $signedCsrf->issue('form','current-login');
if (!$signedCsrf->verifyDoubleSubmit('form','current-login',$signedToken,$signedToken) || $signedCsrf->verify('form','another-login',$signedToken)) { exit(9); }
if (!(new SoSecurity\\Csrf\\RequestPolicy())->requiresToken('POST','/form')) { exit(10); }
$totp = new SoSecurity\\Mfa\\Totp('sha1', 8);
$seed = SoSecurity\\Mfa\\Totp::encodeSecret('12345678901234567890');
if ($totp->codeAt($seed, 59) !== '94287082') { exit(18); }
require __DIR__ . '/vendor/sohophp/sosecurity/examples/mfa-account.php';
require __DIR__ . '/vendor/sohophp/sosecurity/examples/identity-providers.php';
$provider = new SoSecurity\\Auth\\CallbackIdentityProvider(
    function () { return new SoSecurity\\Auth\\Account('consumer','account','1'); },
    function () { return new SoSecurity\\Auth\\Account('consumer','account','1'); });
$sessions = new SoSecurity\\Auth\\SessionRegistry($store, $provider);
$flow = new SoSecurity\\Auth\\AuthenticationFlow($store, $provider, $sessions, function () { return true; });
$login = $flow->password('consumer', 'browser', 'account', 'test-only-password');
if ($login->status() !== 'authenticated' || $login->account()->subject() !== 'account') { exit(23); }
$renewed = $flow->password('consumer','browser','account','test-only-password','',$login->credential()->token());
if ($renewed->credential()->id() !== $login->credential()->id() || $sessions->verify('consumer','account',$login->credential()->token()) !== null) { exit(24); }
$remember = new SoSecurity\\Auth\\RememberedLogin($store, $provider, $sessions,
    new SoSecurity\\Support\\HmacKeys('consumer', ['consumer'=>random_bytes(32)]), function () { return true; });
$persistent = $remember->issue('consumer', 'account', $renewed->credential()->token());
if ($persistent === null || strpos($remember->cookieHeader($persistent), '__Host-SoSecurityRemember=') !== 0) { exit(26); }
$restored = $remember->resume('consumer', $persistent->token());
if ($restored->status() !== 'authenticated' || $restored->session()->id() !== $renewed->credential()->id()) { exit(27); }
$verified = $sessions->verify('consumer', 'account', $restored->session()->token());
if (!$verified->resumed() || $verified->recent(300, time(), 1) || !$remember->forget('consumer', $restored->nextCredential()->token())) { exit(28); }
if ($sessions->verify('consumer', 'account', $restored->session()->token()) !== null) { exit(29); }
$sessions->revokeAll('consumer','account');
if ($sessions->verify('consumer','account',$renewed->credential()->token()) !== null) { exit(25); }
if (extension_loaded('sodium')) {
    if (extension_loaded('pdo_sqlite')) {
        // Synthetic consumer-only authorities with real shared request budgets; no application or mail service is contacted.
        require __DIR__.'/vendor/sohophp/sosecurity/examples/SqlAccounts.php';
        $lifeDb=new PDO('sqlite:'.__DIR__.'/account-consumer.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod(__DIR__.'/account-consumer.sqlite',0600);
        foreach (['account','account-example','outbox'] as $name) {$lifeDb->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/'.$name.'-sqlite.sql'));}
        $lifeClock=new class implements SoSecurity\\Support\\Clock {public $time=100000;public function now():int {return $this->time;}};
        $lifeAccounts=new SoSecurity\\Account\\Example\\SqlAccounts($lifeDb);$lifeHasher=new SoSecurity\\Password\\PasswordHasher('bcrypt',['cost'=>10]);
        $lifeKeys=new SoSecurity\\Support\\HmacKeys('ledger',['ledger'=>random_bytes(32)]);$lifeOutboxKeys=new SoSecurity\\Support\\HmacKeys('queue',['queue'=>random_bytes(32)]);$lifeNotices=new SoSecurity\\Account\\Notifications('mail',['mail'=>random_bytes(32)],$lifeClock);$lifeGuard=function ():bool{return true;};
        $lifeDirectory=__DIR__.'/account-state';mkdir($lifeDirectory,0700);$lifeBudgetPolicies=[];foreach(['site','source','target','subject'] as $name){$lifeBudgetPolicies[$name]=new SoSecurity\\RateLimit\\BudgetPolicy('fixed_window',1000,60);}
        $lifeBudget=new SoSecurity\\Account\\RequestBudgets(new SoSecurity\\Storage\\FileStore($lifeDirectory,'installed-account-budget',$lifeClock),'installed-account',random_bytes(32),$lifeBudgetPolicies,$lifeClock);
        $lifeConfig=['site'=>'installed-account','password'=>['profile'=>'bcrypt','options'=>['cost'=>10]],'accounts'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'ledger','outbox_keys'=>'queue','notifications'=>'notices','request_budget'=>'budget','registration_authority'=>'public','management_guard'=>'manager','delivery_guard'=>'worker']];
        $lifeServices=['db'=>$lifeDb,'accounts'=>$lifeAccounts,'ledger'=>$lifeKeys,'queue'=>$lifeOutboxKeys,'notices'=>$lifeNotices,'budget'=>$lifeBudget,'public'=>$lifeGuard,'manager'=>$lifeGuard,'worker'=>$lifeGuard];
        $lifeSecurity=SoSecurity\\Security::fromArray($lifeConfig,$lifeServices,$lifeClock);$registration=$lifeSecurity->registration();
        $registration->initialize();$registration->request('Consumer+tag@EXAMPLE.COM','local-consumer');
        $pending=$lifeDb->query('SELECT status,password FROM account_example')->fetch(PDO::FETCH_ASSOC);$mailId=$lifeDb->query('SELECT payload_body FROM sosecurity_outbox_records')->fetchColumn();$activation=$registration->notification($mailId);$lifePassword='Consumer owner chosen password. 49!';
        if ($pending['status']!=='pending' || $pending['password']!==null || $activation===null || !$registration->confirm($activation->selector(),$activation->notice()->token(),$lifePassword,'local-consumer') || $registration->confirm($activation->selector(),$activation->notice()->token(),$lifePassword,'local-consumer')) {throw new RuntimeException('Installed registration ownership/atomicity failed.');}
        $lifeRoles=$lifeDb->prepare('UPDATE account_example SET roles=:roles,credential_version=:version');$lifeRoles->execute(['roles'=>json_encode(['member']),'version'=>'consumer-address-start']);$lifeRoles->closeCursor();$lifeInitial=$lifeDb->query('SELECT * FROM account_example')->fetch(PDO::FETCH_ASSOC);$lifeSubject=$lifeInitial['subject'];
        $lifeCurrent=function (string $scope,string $subject)use($lifeAccounts){$record=$lifeAccounts->find($scope,$subject);return $record===null?null:$lifeAccounts->passwordRecord($record);};
        $lifeProvider=new SoSecurity\\Auth\\PasswordIdentityProvider(function (string $scope,string $address)use($lifeAccounts){$record=$lifeAccounts->findAddress($scope,new SoSecurity\\Account\\Address($address));return $record===null?null:$lifeAccounts->passwordRecord($record);},$lifeCurrent,$lifeHasher,$lifeHasher->hash('Consumer dummy lifecycle 49!'));
        $lifeRule=['type'=>'account','roles'=>['member'],'fields'=>['address'],'owner_attribute'=>'owner'];
        $lifeConfig['storage']=['driver'=>'file','directory'=>$lifeDirectory,'lock_timeout_ms'=>5000];$lifeConfig['accounts']['request_guard']='request';$lifeConfig['authentication']=['identity_provider'=>'identity','request_guard'=>'request'];$lifeConfig['authorization']=['policy'=>'roles'];$lifeConfig['operations']=['request_guard'=>'request','minimum_strength'=>1,'methods'=>['password']];
        $lifeServices['request']=$lifeGuard;$lifeServices['identity']=$lifeProvider;$lifeServices['roles']=new SoSecurity\\Authorization\\RolePolicy(['account.address.request'=>$lifeRule,'account.address.complete'=>$lifeRule]);
        $lifeSecurity=SoSecurity\\Security::fromArray($lifeConfig,$lifeServices,$lifeClock);$lifeSessions=$lifeSecurity->sessions();$lifeAuth=$lifeSecurity->authentication();$lifeGrants=$lifeSecurity->operations();
        $lifeLogin=$lifeAuth->password('tenant','local-consumer','Consumer+tag@example.com',$lifePassword);$lifeSession=$lifeLogin->credential()->token();
        $change=$lifeSecurity->addressChange();$change->initialize();
        $lifeApprove=function ($intent)use($lifeGrants,$lifeAuth,$lifeSubject,$lifePassword,$lifeClock,&$lifeSession):string{
            $pending=$lifeGrants->begin('tenant',$lifeSubject,$lifeSession,$intent);++$lifeClock->time;$login=$lifeAuth->password('tenant','local-consumer','Consumer+tag@example.com',$lifePassword,'Consumer change',$lifeSession);$lifeSession=$login->credential()->token();$grant=$lifeGrants->confirm('tenant',$lifeSubject,$lifeSession,$intent,$pending->token());if ($grant===null) {throw new RuntimeException('Installed fresh operation approval failed.');}return $grant->token();
        };
        $lifeBeforeIds=$lifeDb->query('SELECT payload_body FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_COLUMN);$lifeIntent=$change->proposal($lifeSubject,'new.consumer@example.com',$lifeSession,'local-consumer');$lifeGrant=$lifeApprove($lifeIntent);$change->request($lifeSubject,'new.consumer@example.com',$lifeSession,$lifeGrant,'local-consumer');
        $lifeNewIds=array_diff($lifeDb->query('SELECT payload_body FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_COLUMN),$lifeBeforeIds);$lifeSelector=null;$lifeConfirmed=0;
        foreach ($lifeNewIds as $id) {$delivery=$change->notification($id);$side=$delivery->notice()->type()==='verify_address_old'?'old':($delivery->notice()->type()==='verify_address_new'?'new':null);if ($side!==null) {$lifeSelector=$delivery->selector();if (!$change->confirm($lifeSelector,$side,$delivery->notice()->token(),'local-consumer')) {throw new RuntimeException('Installed mailbox proof failed.');}++$lifeConfirmed;}}
        $lifeIntent=$change->completionProposal($lifeSubject,$lifeSelector,$lifeSession,'local-consumer');$lifeGrant=$lifeApprove($lifeIntent);$lifeOldSession=$lifeSession;
        if (count($lifeNewIds)!==3 || $lifeConfirmed!==2 || !$change->complete($lifeSubject,$lifeSelector,$lifeSession,$lifeGrant,'local-consumer')) {throw new RuntimeException('Installed address completion failed.');}
        $lifeFinal=$lifeDb->query('SELECT * FROM account_example')->fetch(PDO::FETCH_ASSOC);
        if ($lifeFinal['address']!=='new.consumer@example.com' || $lifeFinal['password']!==$lifeInitial['password'] || $lifeFinal['roles']!==$lifeInitial['roles'] || $lifeFinal['mfa_required']!==$lifeInitial['mfa_required'] || $lifeFinal['credential_version']===$lifeInitial['credential_version'] || $lifeFinal['address_version']===$lifeInitial['address_version'] || $lifeSessions->verify('tenant',$lifeSubject,$lifeOldSession)!==null || (int)$lifeDb->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn()!==7) {throw new RuntimeException('Installed account/notification/session invariants failed.');}
        $lifeLogin=$lifeAuth->password('tenant','consumer-recovery','new.consumer@example.com',$lifePassword);$lifeRecoverySession=$lifeLogin->credential()->token();
        $lifeConfig['accounts']['recovery_authority']='public';$lifeSecurity=SoSecurity\\Security::fromArray($lifeConfig,$lifeServices,$lifeClock);$lifeRecovery=$lifeSecurity->recovery();$lifeRecovery->initialize();
        $lifeBeforeIds=$lifeDb->query('SELECT payload_body FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_COLUMN);$lifeRecovery->request('new.consumer@example.com','local-consumer');$lifeRecoveryIds=array_values(array_diff($lifeDb->query('SELECT payload_body FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_COLUMN),$lifeBeforeIds));
        if(count($lifeRecoveryIds)!==1){throw new RuntimeException('Installed recovery intent failed.');}$lifeRecoveryDelivery=$lifeRecovery->notification($lifeRecoveryIds[0]);$lifeRecoveredPassword='Consumer recovered owner password 49!';
        $lifeSendPolicies=[];foreach(['site','transport','target','subject'] as $name){$lifeSendPolicies[$name]=new SoSecurity\\RateLimit\\BudgetPolicy('fixed_window',1000,60);}
        $lifeSendBudgets=new SoSecurity\\Account\\SendBudgets(new SoSecurity\\Storage\\FileStore($lifeDirectory,'installed-send-budget',$lifeClock),'installed-account',str_repeat('s',32),$lifeSendPolicies,$lifeClock);
        $lifeMailUrls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $name){$lifeMailUrls[$name]='https://consumer.example.test/'.$name;}
        $lifeTemplates=new SoSecurity\\Account\\MailTemplates('installed-account',new SoSecurity\\Account\\Address('security@example.test'),$lifeMailUrls);
        $lifeMailTransport=new class implements SoSecurity\\Account\\MailTransport {public $messages=[];public function name():string{return 'consumer';}public function send(SoSecurity\\Account\\MailMessage $message,int $milliseconds,callable $gate):SoSecurity\\Account\\MailResult {if($gate()!==true){throw new RuntimeException('Installed worker guard refused.');}$this->messages[]=$message;return new SoSecurity\\Account\\MailResult('accepted','smtp.accepted');}};
        $lifeDispatcher=$lifeRecovery->dispatcher('installed-worker',$lifeSendBudgets,$lifeTemplates,$lifeMailTransport,$lifeGuard);
        if($lifeDispatcher->sendNext()!==['state'=>'submitted','code'=>'smtp.accepted']||count($lifeMailTransport->messages)!==1||$lifeMailTransport->messages[0]->recipient()->value()!=='new.consumer@example.com'||$lifeDispatcher->sendNext()['state']!=='idle'){throw new RuntimeException('Installed lease/budget/mail composition failed.');}
        if($lifeRecoveryDelivery===null||!$lifeRecovery->confirm($lifeRecoveryDelivery->selector(),$lifeRecoveryDelivery->notice()->token(),$lifeRecoveredPassword,'local-consumer')){throw new RuntimeException('Installed recovery owner confirmation failed.');}
        $lifeRecovered=$lifeDb->query('SELECT * FROM account_example')->fetch(PDO::FETCH_ASSOC);
        if(!$lifeHasher->verify($lifeRecoveredPassword,$lifeRecovered['password'])||$lifeRecovered['address']!==$lifeFinal['address']||$lifeRecovered['address_version']!==$lifeFinal['address_version']||$lifeRecovered['roles']!==$lifeFinal['roles']||$lifeRecovered['mfa_required']!==$lifeFinal['mfa_required']||$lifeRecovered['credential_version']===$lifeFinal['credential_version']||$lifeSessions->verify('tenant',$lifeSubject,$lifeRecoverySession)!==null||$lifeRecovery->confirm($lifeRecoveryDelivery->selector(),$lifeRecoveryDelivery->notice()->token(),$lifeRecoveredPassword,'local-consumer')){throw new RuntimeException('Installed recovery state/session/replay invariants failed.');}
    }

    if (isset($lifeRecovered)) {
        $lifeMailboxCalls=[];$lifeMailboxContext=null;
        $lifeServices['mailbox_approval']=function(string $phase,SoSecurity\\Account\\RecoveryApproval $request,array $proof)use(&$lifeMailboxCalls,&$lifeMailboxContext,$lifeSubject):bool{
            if($request->purpose()!=='recover_address'||$request->record()->account()->subject()!==$lifeSubject||$request->target()->value()!=='rescued.consumer@example.com'||$proof['code']!=='installed-mailbox-approval'){return false;}
            if($phase==='verify'){if($lifeMailboxContext!==null){return false;}$lifeMailboxContext=$request->context();}$lifeMailboxCalls[]=$phase;return $lifeMailboxContext===$request->context();
        };
        $lifeConfig['accounts']['mailbox_authority']='public';$lifeConfig['accounts']['mailbox_approval']='mailbox_approval';$lifeSecurity=SoSecurity\\Security::fromArray($lifeConfig,$lifeServices,$lifeClock);$lifeMailbox=$lifeSecurity->mailboxRecovery();$lifeMailbox->initialize();$lifeMailbox->request('new.consumer@example.com','rescued.consumer@example.com','installed-mailbox');
        $lifeMailboxQuery=$lifeDb->prepare('SELECT payload_body FROM sosecurity_outbox_records WHERE namespace=:namespace ORDER BY order_no');$lifeMailboxQuery->execute(['namespace'=>SoSecurity\\Outbox\\State::namespace('installed-account','tenant','account-mailbox-recovery')]);$lifeMailboxProof=null;foreach($lifeMailboxQuery->fetchAll(PDO::FETCH_COLUMN) as $id){$delivery=$lifeMailbox->notification($id);if($delivery!==null&&$delivery->notice()->type()==='recover_address'){$lifeMailboxProof=$delivery;}}
        if($lifeMailboxProof===null||!$lifeMailbox->confirm($lifeMailboxProof->selector(),$lifeMailboxProof->notice()->token(),'installed-mailbox',['type'=>'approved','code'=>'installed-mailbox-approval'])){throw new RuntimeException('Installed new-mailbox/approval recovery failed.');}
        $lifeRescued=$lifeDb->query('SELECT * FROM account_example')->fetch(PDO::FETCH_ASSOC);foreach(['password','roles','mfa_required','status','verified'] as $field){if($lifeRescued[$field]!==$lifeRecovered[$field]){throw new RuntimeException('Installed mailbox recovery changed preserved data.');}}
        if($lifeRescued['address']!=='rescued.consumer@example.com'||$lifeRescued['credential_version']===$lifeRecovered['credential_version']||$lifeRescued['address_version']===$lifeRecovered['address_version']||$lifeMailboxCalls!==['verify','current','commit','complete']){throw new RuntimeException('Installed mailbox recovery versions/approval phases failed.');}
    }
    $mailAddress=new SoSecurity\\Account\\Address('Consumer+tag@EXAMPLE.COM');
    $mailPolicy=new SoSecurity\\Account\\Policy();$mailId=bin2hex(random_bytes(32));$mailNow=time();
    $mailNotice=new SoSecurity\\Account\\Notice('consumer',$mailId,'verify_registration',$mailAddress,bin2hex(random_bytes(32)),$mailNow,$mailNow+$mailPolicy->lifetime('verify_registration'));
    $mailKeys=['old'=>random_bytes(32),'new'=>random_bytes(32)];$mailCodec=new SoSecurity\\Account\\Notifications('old',$mailKeys);
    $mailEnvelope=$mailCodec->seal($mailNotice);$newMailCodec=new SoSecurity\\Account\\Notifications('new',$mailKeys);
    $newMailEnvelope=$newMailCodec->reencrypt($mailEnvelope,'consumer',$mailId,'verify_registration');
    $retiredMailCodec=new SoSecurity\\Account\\Notifications('new',['new'=>$mailKeys['new']]);
    if ($mailAddress->value()!=='Consumer+tag@example.com' || $mailAddress->equals(new SoSecurity\\Account\\Address('consumer+tag@example.com'))
        || $retiredMailCodec->open($newMailEnvelope,'consumer',$mailId,'verify_registration')->encode()!==$mailNotice->encode()
        || strpos(var_export($mailNotice,true),$mailNotice->token())!==false || strpos(var_export($mailCodec,true),$mailKeys['old'])!==false) {throw new RuntimeException('Installed account notification foundation failed.');}
    try {$mailCodec->open($mailEnvelope,'other',$mailId,'verify_registration');throw new RuntimeException('Installed notice context was not checked.');}
    catch (SoSecurity\\Exception\\ValidationException $error) {}
    $cipher = new SoSecurity\\Crypto\\Cipher('test', ['test'=>random_bytes(32)], 'consumer-mfa');
    if ($cipher->decrypt($cipher->encrypt('secret', 'consumer'), 'consumer') !== 'secret') { exit(19); }
    $factors = new SoSecurity\\Mfa\\TotpFactors($store, $cipher, 'Consumer');
    $pending = $factors->begin('consumer', 'account', 'demo@example.test');
    parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $provision);
    foreach ([var_export($pending,true),print_r($pending,true),json_encode($pending)] as $dump) {
        if (strpos($dump,$provision['secret'])!==false || strpos($dump,$pending->provisioningUri())!==false) {
            throw new RuntimeException('Installed MFA enrollment export exposed provisioning data.');
        }
    }
    $proof = (new SoSecurity\\Mfa\\Totp())->codeAt($provision['secret'], time());
    $codes = $factors->confirm('consumer', 'account', $pending->id(), $proof);
    if (count($codes) !== 10 || !$factors->verifyRecovery('consumer', 'account', $codes[0])
        || $factors->verifyRecovery('consumer', 'account', $codes[0])) { exit(20); }
} else {
    try { new SoSecurity\\Crypto\\Cipher('test', ['test'=>str_repeat('k',32)], 'consumer-mfa'); exit(21); }
    catch (SoSecurity\\Exception\\DependencyException $e) { if ($e->reason() !== 'dependency.sodium') { exit(22); } }
}
try { SoSecurity\\Security::fromArray(['site'=>'consumer','html'=>[]])->htmlCleaner(); exit(11); }
catch (SoSecurity\\Exception\\DependencyException $e) { if ($e->reason()!=='dependency.htmlpurifier') { exit(12); } }
foreach (['SoSecurity\\Account\\FactorRegistry','SoSecurity\\Account\\FactorWorkerAuthority','SoSecurity\\Account\\FactorOperations','SoSecurity\\Account\\FactorMigration','SoSecurity\\Account\\FactorIntentMaintenance','SoSecurity\\Account\\FactorOperationResolution','SoSecurity\\Account\\FactorRevocation','SoSecurity\\Account\\FactorRestoration','SoSecurity\\Account\\ManagedSecondFactor'] as $managedClass) {
    if (!class_exists($managedClass)) { throw new RuntimeException('Installed managed factor API missing.'); }
}
$factorConfig=['site'=>'installed-factor','account_factors'=>['connection'=>'db','scope'=>'consumer','epoch'=>str_repeat('e',64),'repository'=>'repo','integrity_keys'=>'keys','totp'=>'totp','fence'=>'fence','worker_guard'=>'worker','read_guard'=>'read','management_guard'=>'manager']];
$factorSdk=SoSecurity\\Security::fromArray($factorConfig);
if($factorSdk->config()->accountFactors()['policy']['maximum_entries']!==1000){throw new RuntimeException('Installed managed factor config missing.');}
try {$factorSdk->accountFactors();throw new RuntimeException('Installed factor factory accepted absent explicit services.');}
catch (SoSecurity\\Exception\\ConfigurationException $expected) {}
$uploadPrivate='Owned installed confidential upload 49!';
$uploadPrivatePath=__DIR__.'/private-installed-uploads/11111111111111111111111111111111.txt';
$uploadCandidate=new SoSecurity\\Upload\\Candidate($uploadPrivate,'text/plain','txt',strlen($uploadPrivate));
$uploadFile=new SoSecurity\\Upload\\StoredFile($uploadPrivatePath,$uploadCandidate,true);
if($uploadCandidate->contents()!==$uploadPrivate || $uploadFile->path()!==$uploadPrivatePath){throw new RuntimeException('Installed explicit upload access changed.');}
foreach([var_export([$uploadCandidate,$uploadFile],true),print_r([$uploadCandidate,$uploadFile],true),json_encode([$uploadCandidate,$uploadFile])] as $dump){
    if(strpos($dump,$uploadPrivate)!==false || strpos($dump,$uploadPrivatePath)!==false){throw new RuntimeException('Installed upload object export exposed private data.');}
}
foreach([$uploadCandidate,$uploadFile] as $uploadObject){
    try{serialize($uploadObject);throw new RuntimeException('Installed upload serialization was accepted.');}
    catch(SoSecurity\\Exception\\ConfigurationException $expected){if($expected->reason()!=='configuration.upload_serialization'){throw $expected;}}
}
echo "PASS Composer: fresh consumer installation, PSR-4, fixed audit metrics, password safeguards, authentication/revocation, persistent login, operation authorization, signed links, private downloads, account API credentials, webhook verification/opt-in SQL receive/transactional processing, SQL idempotent result replay/native bearer-business adapter, transactional Outbox and installed native producer/independent receiver ledger, account registration/dual-address/recovery lifecycle and notification encryption/rotation, MFA capability checks and private upload exports on PHP " . PHP_VERSION . "\\n";
''')
    subprocess.run([runtime, str(Path(directory, 'verify.php'))], check=True)
    calibration = subprocess.run([runtime, str(Path(directory, 'vendor/sohophp/sosecurity/examples/password-calibrate.php')),
        '--budget-ms=100', '--samples=1'], capture_output=True, text=True, check=True, timeout=3)
    if calibration.stderr or json.loads(calibration.stdout)['writes_configuration'] is not False:
        raise RuntimeError('Installed CLI calibration bootstrap failed')
    Path(directory, 'verify-example.php').write_text('''<?php
$_SERVER['HTTP_ACCEPT']='application/json';
require __DIR__.'/vendor/sohophp/sosecurity/examples/authentication.php';
''')
    # Unconfigured standalone entry must bootstrap through the consumer autoloader and refuse safely.
    probe_env = {key: value for key, value in os.environ.items() if not key.startswith('SOSECURITY_AUTH_EXAMPLE_')}
    probe = subprocess.run([runtime, str(Path(directory, 'verify-example.php'))], capture_output=True, text=True, check=True, env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != {'error': 'auth.unavailable'}:
        raise RuntimeError('Installed standalone authentication bootstrap did not refuse safely')
    Path(directory, 'verify-operation-example.php').write_text('''<?php
$_SERVER['HTTP_ACCEPT']='application/json';
require __DIR__.'/vendor/sohophp/sosecurity/examples/operation-authorization.php';
''')
    probe_env = {key:value for key,value in os.environ.items() if not key.startswith('SOSECURITY_OPERATION_EXAMPLE_')}
    probe = subprocess.run([runtime,str(Path(directory,'verify-operation-example.php'))],capture_output=True,text=True,check=True,env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != {'error':'operation.unavailable'}:
        raise RuntimeError('Installed standalone operation bootstrap did not refuse safely')
    Path(directory,'verify-link-example.php').write_text('''<?php
$_SERVER['HTTP_ACCEPT']='application/json';
require __DIR__.'/vendor/sohophp/sosecurity/examples/signed-links.php';
''')
    probe_env = {key:value for key,value in os.environ.items() if not key.startswith('SOSECURITY_LINK_EXAMPLE_')}
    probe = subprocess.run([runtime,str(Path(directory,'verify-link-example.php'))],capture_output=True,text=True,check=True,env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != {'error':'link.unavailable'}:
        raise RuntimeError('Installed standalone signed-link bootstrap did not refuse safely')
    Path(directory,'verify-download-example.php').write_text('''<?php
$_SERVER['HTTP_ACCEPT']='application/json';
require __DIR__.'/vendor/sohophp/sosecurity/examples/authorized-download.php';
''')
    probe_env = {key:value for key,value in os.environ.items() if not key.startswith('SOSECURITY_DOWNLOAD_EXAMPLE_')}
    probe = subprocess.run([runtime,str(Path(directory,'verify-download-example.php'))],capture_output=True,text=True,check=True,env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != {'error':'download.unavailable'}:
        raise RuntimeError('Installed standalone authorized-download bootstrap did not refuse safely')
    Path(directory,'verify-credential-example.php').write_text('''<?php
$_SERVER['HTTP_ACCEPT']='application/json';
require __DIR__.'/vendor/sohophp/sosecurity/examples/api-credentials.php';
''')
    probe_env = {key:value for key,value in os.environ.items() if not key.startswith('SOSECURITY_CREDENTIAL_EXAMPLE_')}
    probe = subprocess.run([runtime,str(Path(directory,'verify-credential-example.php'))],capture_output=True,text=True,check=True,env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != {'error':'credentials.unavailable'}:
        raise RuntimeError('Installed standalone API-credential bootstrap did not refuse safely')
    Path(directory,'verify-webhook-example.php').write_text('''<?php
$_SERVER['HTTP_ACCEPT']='application/json';
require __DIR__.'/vendor/sohophp/sosecurity/examples/webhooks.php';
''')
    probe_env = {key:value for key,value in os.environ.items() if not key.startswith('SOSECURITY_WEBHOOK_EXAMPLE_')}
    probe = subprocess.run([runtime,str(Path(directory,'verify-webhook-example.php'))],capture_output=True,text=True,check=True,env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != {'error':'webhook_example.unavailable'}:
        raise RuntimeError('Installed standalone webhook bootstrap did not refuse safely')
    Path(directory,'verify-webhook-worker-import.php').write_text('''<?php
require __DIR__.'/vendor/autoload.php';
ob_start();
require __DIR__.'/vendor/sohophp/sosecurity/examples/webhook-business.php';
require __DIR__.'/vendor/sohophp/sosecurity/examples/webhook-worker.php';
$out=ob_get_clean();echo json_encode([$out,session_status(),headers_sent()]);
''')
    probe = subprocess.run([runtime,str(Path(directory,'verify-webhook-worker-import.php'))],capture_output=True,text=True,check=True,env=probe_env)
    if probe.stderr or json.loads(probe.stdout) != ['',1,False]:
        raise RuntimeError('Installed webhook worker import performed initialization or output')

    Path(directory,'verify-clamav-import.php').write_text(r'''<?php
require __DIR__.'/vendor/autoload.php';
$path='/tmp/private-unconfigured-clamav.sock';$scanner=new SoSecurity\Upload\ClamAvScanner($path);
$reflection=new ReflectionClass($scanner);$package=realpath(__DIR__.'/vendor/sohophp/sosecurity');
if(strpos(realpath($reflection->getFileName()),$package.DIRECTORY_SEPARATOR)!==0){exit(80);}
if(strpos(var_export($scanner,true),$path)!==false){exit(81);}
ob_start();$builder=require $package.'/examples/clamav-scanner.php';$out=ob_get_clean();
echo json_encode([$out,is_callable($builder),$scanner instanceof SoSecurity\Upload\Scanner,session_status(),headers_sent()]);
''')
    probe=subprocess.run([runtime,str(Path(directory,'verify-clamav-import.php'))],capture_output=True,text=True,check=True)
    if probe.stderr or json.loads(probe.stdout)!=['',True,True,1,False]:
        raise RuntimeError('Installed ClamAV adapter import performed initialization or leaked configuration')
    print('PASS installed ClamAV adapter and inert builder')

    Path(directory,'verify-quarantine-consumer.php').write_text(r'''<?php
require __DIR__.'/vendor/autoload.php';
$package=realpath(__DIR__.'/vendor/sohophp/sosecurity');
$reflection=new ReflectionClass(SoSecurity\Upload\Quarantine::class);
if(strpos(realpath($reflection->getFileName()),$package.DIRECTORY_SEPARATOR)!==0){exit(90);}
ob_start();$builder=require $package.'/examples/upload-quarantine.php';$output=ob_get_clean();
if($output!==''||!is_callable($builder)||session_status()!==PHP_SESSION_NONE||headers_sent()){exit(91);}
$base=sys_get_temp_dir().'/sosecurity-consumer-quarantine-'.bin2hex(random_bytes(8));mkdir($base,0700);
foreach(['spool','state','web'] as $name){mkdir($base.'/'.$name,0700);}
try{
    file_put_contents($base.'/source',"consumer\n");
    $scanner=new class implements SoSecurity\Upload\Scanner{
        public function scan(SoSecurity\Upload\Candidate $candidate):bool{return $candidate->contents()==="consumer\n";}
    };
    $queue=new SoSecurity\Upload\Quarantine(new SoSecurity\Storage\FileStore($base.'/state','consumer'),
        new SoSecurity\Upload\Policy(['extensions'=>['txt'],'maximum_bytes'=>1024]),$scanner,$base.'/spool',$base.'/web','uploads');
    $id=$queue->enqueueFile($base.'/source','file.txt')->id();
    if($queue->inspect($id)->state()!=='pending'||$queue->process($id)->state()!=='available'||$queue->readAvailable($id)->contents()!=="consumer\n"){exit(92);}
    $queue->rescan($id);$denied=false;
    try{$queue->readAvailable($id);}catch(SoSecurity\Exception\SecurityException $error){$denied=true;}
    if(!$denied||$queue->reject($id)->state()!=='rejected'||!$queue->remove($id)||$queue->inspect($id)!==null||file_get_contents($base.'/source')!=="consumer\n"){exit(93);}
    $factory=SoSecurity\Security::fromArray(['site'=>'consumer-factory','storage'=>['driver'=>'file','directory'=>$base.'/state'],
        'upload_quarantine'=>['directory'=>$base.'/spool','document_root'=>$base.'/web','scanner'=>'scanner',
            'policy'=>['extensions'=>['txt'],'maximum_bytes'=>1024]]],['scanner'=>$scanner]);
    $before=[scandir($base.'/state'),scandir($base.'/spool')];
    $queue=$factory->quarantine();$checks=$factory->diagnose($base.'/web');$byName=array_column($checks,null,'check');
    if($before!==[scandir($base.'/state'),scandir($base.'/spool')]||$byName['quarantine.scanner']['status']!=='manual'||$byName['quarantine.workflow']['status']!=='manual'){exit(94);}
    $id=$queue->enqueueFile($base.'/source','factory.txt')->id();
    if($queue->process($id)->state()!=='available'||$queue->readAvailable($id)->contents()!=="consumer\n"){exit(95);}
    $queue->reject($id);if(!$queue->remove($id)){exit(96);}
    echo "PASS installed persistent quarantine and lazy factory, private storage, scan, read, rescan and cleanup\n";
}finally{
    foreach(['spool','state','web'] as $name){foreach(new DirectoryIterator($base.'/'.$name) as $entry){if(!$entry->isDot()){unlink($entry->getPathname());}}rmdir($base.'/'.$name);}
    unlink($base.'/source');rmdir($base);
}
''')
    probe=subprocess.run([runtime,str(Path(directory,'verify-quarantine-consumer.php'))],capture_output=True,text=True,check=True)
    if probe.stderr or 'PASS installed persistent quarantine' not in probe.stdout:
        raise RuntimeError('Installed quarantine consumer failed: '+probe.stdout+probe.stderr)
    print(probe.stdout.strip())

    Path(directory,'verify-native-quarantine-import.php').write_text(r'''<?php
require __DIR__.'/vendor/autoload.php';$package=realpath(__DIR__.'/vendor/sohophp/sosecurity');
ob_start();require $package.'/examples/upload-quarantine-business.php';require $package.'/examples/upload-quarantine-worker.php';$out=ob_get_clean();
foreach(['configuration','services','worker'] as $name){$reflection=new ReflectionFunction('SoSecurity\\Examples\\QuarantineHttp\\'.$name);if(strpos(realpath($reflection->getFileName()),$package.DIRECTORY_SEPARATOR)!==0){exit(98);}}
if($out!==''||session_status()!==PHP_SESSION_NONE||headers_sent()){exit(99);}echo 'PASS installed native quarantine inert host/worker imports';
''')
    probe=subprocess.run([runtime,str(Path(directory,'verify-native-quarantine-import.php'))],capture_output=True,text=True,check=True)
    if probe.stderr or 'PASS installed native quarantine inert host/worker imports' not in probe.stdout:
        raise RuntimeError('Native quarantine import performed work')
    print(probe.stdout.strip())
    if os.environ.get('SOSECURITY_TEST_NATIVE_QUARANTINE') == '1':
        subprocess.run(['python3',str(root/'tests/upload_quarantine_http.py'),runtime,'--owner-check','--package',str(Path(directory,'vendor/sohophp/sosecurity'))],cwd=root,check=True)

    Path(directory,'verify-archive-consumer.php').write_text(r'''<?php
declare(strict_types=1);
require __DIR__.'/vendor/autoload.php';
require __DIR__.'/vendor/sohophp/sosecurity/examples/archive-inspection.php';
$inspector=new SoSecurity\Upload\ArchiveInspector();
if(!class_exists(ZipArchive::class)){
    try{$inspector->inspect(__DIR__.'/missing.zip');}catch(SoSecurity\Exception\DependencyException $e){echo 'PASS installed ZIP dependency refusal';exit(0);}
    exit(100);
}
$file=__DIR__.'/consumer.zip';$zip=new ZipArchive();
if($zip->open($file,ZipArchive::CREATE|ZipArchive::OVERWRITE)!==true){exit(101);}
$zip->addFromString('folder/file.bin',"a\0bcd");$zip->close();
try{
    $result=SoSecurity\Examples\inspectPrivateZip($file);
    if($result['uncompressed_bytes']!==5||count($result['entries'])!==1||$result['entries'][0]['path']!=='folder/file.bin'){exit(102);}
    echo 'PASS installed ZIP read-only inspector';
}finally{unlink($file);}
''')
    probe=subprocess.run([runtime,str(Path(directory,'verify-archive-consumer.php'))],capture_output=True,text=True,check=True)
    if probe.stderr or 'PASS installed ZIP' not in probe.stdout:
        raise RuntimeError('Installed ZIP inspector failed: '+probe.stdout+probe.stderr)
    print(probe.stdout.strip())

    Path(directory,'verify-alert-outbox-consumer.php').write_text(r'''<?php
declare(strict_types=1);
require __DIR__.'/vendor/autoload.php';
$state=__DIR__.'/alert-state';mkdir($state,0700);
$clock=new class implements SoSecurity\Support\Clock {public function now():int{return 100000;}};
$pdo=new PDO('sqlite:'.__DIR__.'/alert.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$pdo->exec(file_get_contents(__DIR__.'/vendor/sohophp/sosecurity/resources/sql/outbox-sqlite.sql'));
$outbox=new SoSecurity\Outbox\SqlOutbox($pdo,'consumer-alert',str_repeat('e',64),
    new SoSecurity\Support\HmacKeys('current',['current'=>str_repeat('k',32)]),
    static function():bool{return true;},null,$clock,static function():bool{return true;});
$outbox->initialize('consumer',SoSecurity\Audit\AlertOutboxPublisher::producer(),'admin');
$metrics=new SoSecurity\Audit\MetricsSink(new SoSecurity\Storage\FileStore($state,'consumer-alert',$clock),
    'consumer',['login.failed'=>'authentication'],['authentication'=>1],2,60,
    static function(array $record):void{},$clock,2);
(new SoSecurity\Audit\AuditLogger($metrics,str_repeat('p',32)))->record('login.failed','consumer','actor');
if($metrics->inspectRetained()[0]['alerts']!==['authentication']){exit(127);}
$publisher=new SoSecurity\Audit\AlertOutboxPublisher($metrics,$outbox,'consumer','operator');
$pdo->beginTransaction();$first=$publisher->publish();$pdo->commit();
$pdo->beginTransaction();$again=$publisher->publish();$pdo->commit();
if(count($first)!==1||count($again)!==1||$first[0]->id()!==$again[0]->id()
    ||(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn()!==1){exit(124);}
$delivered=[];
$worker=new SoSecurity\Audit\AlertOutboxWorker($metrics,$outbox,'consumer','worker',
    static function(string $deliveryId,array $alert)use(&$delivered):bool{
        $delivered[]=$deliveryId;
        return $alert['class']==='authentication';
    });
if(!$worker->runOne()||$worker->runOne()||count($delivered)!==1
    ||$outbox->status('consumer',SoSecurity\Audit\AlertOutboxPublisher::producer(),$first[0]->id(),'operator')->state()!=='sent'){exit(125);}
echo 'PASS installed audit alert Outbox publisher and worker';
''')
    probe=subprocess.run([runtime,str(Path(directory,'verify-alert-outbox-consumer.php'))],capture_output=True,text=True,check=True)
    if probe.stderr or 'PASS installed audit alert Outbox publisher and worker' not in probe.stdout:
        raise RuntimeError('Installed audit alert Outbox flow failed: '+probe.stdout+probe.stderr)
    print(probe.stdout.strip())
