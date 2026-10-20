<?php
declare(strict_types=1);
if(($argv[1] ?? '')==='mysql'){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
require __DIR__.'/account-dispatch-support.php';
use SoSecurity\Account\MailResult;use SoSecurity\Account\MailMessage;
registrationCase(static function(RegistrationEnvironment $e):void{
    $service=$e->service();$service->initialize();$service->request('owner@example.com','owned-source');$d=$service->notification($e->notices()[0]);$context=$service->notificationForDispatch($e->notices()[0]);Check::same($e->account()['subject'],$context->subject());Check::same($d->notice()->encode(),$context->notice()->encode());
    $transport=new TestMailTransport();$sender=dispatcher($e,$service,$transport);Check::same(['state'=>'submitted','code'=>'smtp.accepted'],$sender->sendNext());Check::same(1,$transport->calls);Check::same('owner@example.com',$transport->messages[0]->recipient()->value());Check::same('sent',$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same('idle',$sender->sendNext()['state']);Check::same(1,$transport->calls);
});
// Authenticate the actual token, actor and lifetime; descriptive/fabricated claims cannot grant a send.
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','owned-source');$q=dispatchQueue($e);$claim=$q->claim('tenant','account-registration','mail-worker');$queries=$e->pdo->queries;Check::same(null,$q->currentClaim('tenant','account-registration','mail-worker','invalid'));Check::same($queries,$e->pdo->queries);Check::same(null,$q->currentClaim('tenant','account-registration','other-worker',$claim->token()));$wrong=substr($claim->token(),0,-1).(substr($claim->token(),-1)==='0'?'1':'0');Check::same(null,$q->currentClaim('tenant','account-registration','mail-worker',$wrong));$fresh=$q->currentClaim('tenant','account-registration','mail-worker',$claim->token());Check::same($claim->message()->fingerprint(),$fresh->message()->fingerprint());Check::same(1,$fresh->status()->attempts());$e->clock->time+=60;Check::same(null,$q->currentClaim('tenant','account-registration','mail-worker',$claim->token()));Check::same(1,(int)$e->pdo->query('SELECT attempts FROM sosecurity_outbox_records')->fetchColumn());
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','owned-source');$transport=new TestMailTransport();$sender=dispatcher($e,$s,$transport);$e->onDelivery=static function():bool{return false;};Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($sender):void{$sender->sendNext();});Check::same(0,$transport->calls);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','owned-source');$transport=new TestMailTransport();$transport->before=static function()use($e):void{$e->onDelivery=static function():bool{return false;};};$sender=dispatcher($e,$s,$transport);Check::throws(SoSecurity\Exception\DependencyException::class,static function()use($sender):void{$sender->sendNext();});Check::same([],$transport->messages);Check::same('dead',$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());
    $e->onDelivery=null;$transport->before=null;$id=$e->pdo->query('SELECT message_id FROM sosecurity_outbox_records')->fetchColumn();Check::same(true,dispatchQueue($e)->retry('tenant','account-registration',$id,'manager'));Check::same('deferred',$sender->sendNext()['state']);Check::same(1,$transport->calls);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','owned-source');$transport=new TestMailTransport();$transport->after=static function()use($e):void{$e->clock->time+=61;};$sender=dispatcher($e,$s,$transport);
    try{$sender->sendNext();throw new RuntimeException('Expected uncertain SMTP submission');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.delivery_unknown',$error->reason());}Check::same(1,count($transport->messages));$transport->after=null;Check::same('deferred',$sender->sendNext()['state']);Check::same(1,$transport->calls);Check::same(2,(int)$e->pdo->query('SELECT attempts FROM sosecurity_outbox_records')->fetchColumn());
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','owned-source');$transport=new TestMailTransport();$transport->result=new MailResult('rejected','smtp.temporary',true);$sender=dispatcher($e,$s,$transport);Check::same('rejected',$sender->sendNext()['state']);$e->clock->time+=5;$transport->result=null;Check::same('submitted',$sender->sendNext()['state']);Check::same(2,$transport->calls);Check::same($transport->messages[0]->messageId(),$transport->messages[1]->messageId());Check::same($transport->messages[0]->wire(),$transport->messages[1]->wire());
});
// Obsolete and failed notices must not block independent current/security notifications.
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','owned-source');$e->clock->time+=60;$s->request('owner@example.com','owned-source');$transport=new TestMailTransport();$sender=dispatcher($e,$s,$transport);Check::same('discarded',$sender->sendNext()['state']);Check::same('submitted',$sender->sendNext()['state']);Check::same(1,$transport->calls);Check::same(['dead','sent'],$e->pdo->query('SELECT status FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_COLUMN));
});
changeCase(static function(ChangeEnvironment $t):void{
    $t->request();$transport=new TestMailTransport();$transport->before=static function(MailMessage $m)use($transport):void{$transport->result=$m->recipient()->value()==='new@example.com'?new MailResult('rejected','smtp.recipient_refused'):null;};$sender=dispatcher($t->e,$t->service,$transport);Check::same('submitted',$sender->sendNext()['state']);Check::same('rejected',$sender->sendNext()['state']);Check::same('submitted',$sender->sendNext()['state']);Check::same(3,$transport->calls);
});
echo 'PASS isolated mail dispatcher: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; real SQL claim secrets/worker/expiry, current account readers, rejection/unknown handling and independent notices; transport is a test double\n";
