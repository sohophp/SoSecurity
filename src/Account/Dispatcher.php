<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Outbox\Claim;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;

/** One current account notification, one bounded submission, then an independently authorized queue settlement. */
final class Dispatcher
{
    private $dependencies;
    private $observed=0;
    public function __construct(string $site,string $scope,string $worker,SqlOutbox $queue,$source,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,?Clock $clock=null,int $budgetMilliseconds=10000,int $transportMilliseconds=3000)
    {
        foreach([$site,$scope,$worker] as $label){Guard::label($label);if(preg_match('//u',$label)!==1){throw new ConfigurationException('Use fixed UTF-8 dispatcher labels.','configuration.account_dispatch');}}
        $producer=$source instanceof Registration?'account-registration':($source instanceof AddressChange?'account-address-change':($source instanceof Recovery?'account-recovery':($source instanceof MailboxRecovery?'account-mailbox-recovery':($source instanceof FactorNotices?'account-factor-notice':null))));
        if($producer===null||$budgetMilliseconds<100||$budgetMilliseconds>30000||$transportMilliseconds<1||$transportMilliseconds>10000||$transportMilliseconds>=$budgetMilliseconds){throw new ConfigurationException('Configure an actual account notification service and bounded dispatcher/transport budgets.','configuration.account_dispatch');}
        $clock=$clock ?? new SystemClock();$budgets->validateConfiguration($site,$clock);$templates->validateConfiguration($site);if($source instanceof MailboxRecovery&&!$templates->supportsAction('recover_address')){throw new ConfigurationException('Configure an explicit mailbox recovery action URL.','configuration.account_dispatch');}
        $this->dependencies=static function()use($scope,$worker,$queue,$source,$budgets,$templates,$transport,$clock,$producer,$budgetMilliseconds,$transportMilliseconds):array{return [$scope,$worker,$queue,$source,$budgets,$templates,$transport,$clock,$producer,$budgetMilliseconds,$transportMilliseconds];};
    }
    private function now(Deadline $deadline):int
    {
        $deadline->check('account.dispatch_timeout');try{$now=($this->dependencies)()[7]->now();}catch(\Throwable $error){throw new StorageException('Dispatcher clock unavailable.','account.dispatch_clock');}
        if($now<0||$now>PHP_INT_MAX-31536001||$now<$this->observed){throw new StorageException('Invalid dispatcher clock.','account.dispatch_clock');}$this->observed=$now;return $now;
    }
    private function current(Claim $original,Deadline $deadline):Claim
    {
        list($scope,$worker,$queue,,,,,,$producer)=($this->dependencies)();$this->now($deadline);$fresh=$queue->currentClaim($scope,$producer,$worker,$original->token());$now=$this->now($deadline);
        if($fresh===null||$fresh->message()->fingerprint()!==$original->message()->fingerprint()||$fresh->status()->attempts()!==$original->status()->attempts()||min($fresh->status()->leaseUntil(),$fresh->status()->deliverUntil())<=$now){throw new SecurityException('Current original delivery lease required.','account.dispatch_lease');}return $fresh;
    }
    private function notice(Claim $claim,Deadline $deadline):?DispatchNotice
    {
        list($scope,,,$source)=($this->dependencies)();$message=$claim->message();$id=$message->body();
        if($message->scope()!==$scope||$message->destination()!=='mail'||$message->topic()!=='account.notice'||!preg_match('/\A[a-f0-9]{64}\z/D',$id)){throw new StorageException('Queue message differs from the account notification protocol.','account.dispatch_message');}
        $delivery=$source->notificationForDispatch($id);$now=$this->now($deadline);
        if($delivery===null){return null;}$prefix=$source instanceof AddressChange?'account-change-notice-':'account-notice-';if($message->id()!==\SoSecurity\Outbox\Message::identifier($prefix.$id,$delivery->notice()->issuedAt())){throw new StorageException('Message identity differs from its authenticated notice.','account.dispatch_message');}if($delivery->notice()->scope()!==$scope||$delivery->notice()->id()!==$id||$delivery->notice()->issuedAt()>$now||$delivery->notice()->expiresAt()<=$now){throw new StorageException('Notification context changed.','account.dispatch_notice');}return $delivery;
    }
    public function sendNext(int $afterOrder=0):array
    {
        list($scope,$worker,$queue,,$budgets,$templates,$transport,,$producer,$maximum,$transportMaximum)=($this->dependencies)();$deadline=new Deadline($maximum);$this->now($deadline);
        $claim=$queue->claim($scope,$producer,$worker,$afterOrder);$this->now($deadline);if($claim===null){return ['state'=>'idle','code'=>'account.no_notification'];}
        $claim=$this->current($claim,$deadline);$delivery=$this->notice($claim,$deadline);
        if($delivery===null){if(!$queue->fail($scope,$producer,$worker,$claim->token(),'account.notice_inactive',false)){throw new StorageException('Inactive notice settlement unknown.','account.delivery_unknown');}return ['state'=>'discarded','code'=>'account.notice_inactive'];}
        $mail=$templates->render($delivery);$claim=$this->current($claim,$deadline);$provider=$transport->name();Guard::label($provider);$this->now($deadline);
        $until=$budgets->reserve($delivery,$mail,$provider,$claim->status()->deliveryId(),$claim->status()->attempts());$this->now($deadline);
        if($until===null){if(!$queue->fail($scope,$producer,$worker,$claim->token(),'account.send_budget',true)){throw new StorageException('Send quota refusal settlement unknown.','account.delivery_unknown');}return ['state'=>'deferred','code'=>'account.send_budget'];}
        $until=min($until,$delivery->notice()->expiresAt(),$claim->status()->leaseUntil(),$claim->status()->deliverUntil());$started=false;
        $check=function()use($claim,$delivery,$until,$deadline):void{
            $this->current($claim,$deadline);$fresh=$this->notice($claim,$deadline);if($fresh===null||!hash_equals($delivery->fingerprint(),$fresh->fingerprint())){throw new SecurityException('Notice authority changed before upload.','account.dispatch_notice');}
            $this->current($claim,$deadline);if($this->now($deadline)>=$until){throw new SecurityException('Send admission expired.','account.dispatch_expired');}
        };
        $gate=function()use($check,$claim,$delivery,$mail,$budgets,$until,$deadline,&$started):bool{
            $check();if(!$started){if(!$budgets->started($delivery,$mail,$claim->status()->deliveryId(),$claim->status()->attempts())){throw new SecurityException('Original send reservation required.','account.dispatch_budget');}$started=true;}
            $this->current($claim,$deadline);return $this->now($deadline)<$until;
        };
        $check();$current=$this->now($deadline);$milliseconds=min($transportMaximum,(int)floor(($until-$current-1)*1000),(int)floor(($deadline->remaining()-.1)*1000));
        if($milliseconds<1){throw new SecurityException('No bounded submission time remains.','account.dispatch_expired');}
        $failure=null;
        try{$result=$transport->send($mail,$milliseconds,$gate);}catch(\Throwable $error){$failure=$error;$result=new MailResult('unknown','smtp.transport_failure');}
        if($result->state()==='accepted'&&!$started){$result=new MailResult('unknown','smtp.guard_not_called');$failure=new DependencyException('Transport did not use the current content gate.','account.dispatch_transport');}
        // Persist accepted/unknown before queue settlement; a crash cannot silently turn it into another send admission.
        try{if(!$budgets->settle($delivery,$mail,$claim->status()->deliveryId(),$claim->status()->attempts(),$result)){throw new StorageException('Send outcome rejected.');}}catch(\Throwable $error){throw new StorageException('Submission outcome could not be committed.','account.delivery_unknown');}
        if($result->state()==='accepted'){
            try{$check();if(!$queue->acknowledge($scope,$producer,$worker,$claim->token())){throw new StorageException('Queue acknowledgement refused.');}$this->now($deadline);}
            catch(\Throwable $error){throw new StorageException('SMTP accepted but final authority/acknowledgement unknown.','account.delivery_unknown');}return ['state'=>'submitted','code'=>'smtp.accepted'];
        }
        if(!$queue->fail($scope,$producer,$worker,$claim->token(),$result->code(),$result->state()==='rejected'&&$result->retryable())){throw new StorageException('Submission failure settlement unknown.','account.delivery_unknown');}$this->now($deadline);
        if($failure!==null){throw new DependencyException('Transport submission unknown; inspect the original event.','account.delivery_unknown');}
        return ['state'=>$result->state(),'code'=>$result->code()];
    }
    public function __debugInfo():array {return ['account_dispatcher'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize worker authority.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Rebuild private worker dependencies.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Dispatcher configuration is immutable.','configuration.immutable');}
}
