<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy as OutboxPolicy;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Isolated candidate. Public, management and delivery authority are independent. No SMTP, automatic login or factor removal. */
final class MailboxRecovery
{
    private $scope;
    private $maintenanceState;
    private $stateGuard;
    private $native;
    private $context;
    private $dependencies;
    private $dispatchFactory;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $integrityKeys,HmacKeys $outboxKeys,
        IdentityRepository $accounts,Notifications $notifications,callable $authority,callable $budget,callable $strongApproval,
        ?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null,?callable $deliveryGuard=null,?\SoSecurity\Auth\SecondFactor $recoveryFactors=null,?StateAccountConnection $state=null,?StateRequestGuard $requests=null)
    {
        $policy=$policy ?? new Policy();$clock=$clock ?? new SystemClock();if($requests!==null&&$state===null){throw new ConfigurationException('Native lifecycle admission requires an exact protected connection.','configuration.state_request');}$this->native=$requests===null?null:$state->requestHandler('mailbox_recovery',$requests);$this->maintenanceState=$state;$this->stateGuard=\SoSecurity\Support\SqlStateAccess::entryGuard($connection,$accounts,$site,$scope,$epoch,$clock,$policy,$state);$notifications->validateConfiguration($clock,$policy->allowsSmtpUtf8());$unit=new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        try{$same=$accounts->connection()===$connection;}catch(\Throwable $error){$same=false;}
        if(!$same){throw new ConfigurationException('Use exactly the host account transaction connection.','configuration.account_connection');}
        $ledger=new Ledger($unit,'account-mailbox-recovery:'.hash('sha256',$site),$scope,$epoch,$integrityKeys,$policy);$this->scope=$scope;$this->context=hash('sha256',self::json(['SoSecurity.Account.MailboxRecovery.Context.1',$site,$scope,$epoch]));
        $queueAuthority=static function(string $action,string $phase,string $queueScope,string $producer,string $actor,array $metadata)use($authority,$scope):bool{
            return $action==='enqueue'&&$queueScope===$scope&&$producer==='account-mailbox-recovery'&&$actor==='account-system'&&self::queueGuard($authority,'outbox.enqueue',$phase,$scope);
        };
        $queueManagement=static function(string $action,string $phase,string $queueScope,string $producer,string $actor,array $metadata)use($managementGuard,$scope):bool{
            if($action!=='initialize'||$queueScope!==$scope||$producer!=='account-mailbox-recovery'||$actor!=='account-system'){return false;}
            // SqlOutbox.initialize() also returns false for an existing root. A denied preflight
            // must abort here, so Recovery cannot mistake denial for successful setup.
            if($managementGuard===null||!self::queueGuard($managementGuard,'outbox.initialize',$phase,$scope)){throw new SecurityException('Current account management authority required.','account.denied');}return true;
        };
        $age=max($policy->lifetime('recover_address'),$policy->lifetime('address_recovered'));
        $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$queueAuthority,new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]),$clock,$queueManagement);
        $this->dispatchFactory=function(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds,int $transportMilliseconds)use($connection,$site,$scope,$epoch,$outboxKeys,$policy,$clock,$deliveryGuard):Dispatcher{
            if($deliveryGuard===null){throw new ConfigurationException('Explicit current notification authority is required for dispatch.','configuration.account_dispatch');}
            $producer='account-mailbox-recovery';$age=max($policy->lifetime('recover_address'),$policy->lifetime('address_recovered'));
            $authority=static function(string $action,string $phase,string $currentScope,string $currentProducer,string $actor,array $metadata)use($scope,$producer,$worker,$workerAuthority):bool{
                return $currentScope===$scope&&$currentProducer===$producer&&$actor===$worker&&in_array($action,['claim','claim_initial','claim_rejected','current_claim','acknowledge','fail'],true)&&$workerAuthority($action,$phase,$currentScope,$currentProducer,$actor,$metadata)===true;
            };
            $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$authority,new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]),$clock,null,$this->maintenanceState);
            return new Dispatcher($site,$scope,$worker,$queue,$this,$budgets,$templates,$transport,$clock,$budgetMilliseconds,$transportMilliseconds);
        };
        $this->dependencies=static function()use($unit,$ledger,$queue,$accounts,$notifications,$authority,$budget,$policy,$managementGuard,$deliveryGuard,$recoveryFactors,$strongApproval,$clock):array{return [$unit,$ledger,$queue,$accounts,$notifications,$authority,$budget,$policy,$managementGuard,$deliveryGuard,$recoveryFactors,$strongApproval,$clock];};
    }
    private function unit():SqlTransaction {return ($this->dependencies)()[0];}
    private function ledger():Ledger {return ($this->dependencies)()[1];}
    private function queue():SqlOutbox {return ($this->dependencies)()[2];}
    private function accounts():Repository {return ($this->dependencies)()[3];}
    private function notifications():Notifications {return ($this->dependencies)()[4];}
    /** Arguments are local copies even when a trusted callback declares reference parameters. */
    private static function queueGuard(callable $callback,string $action,string $phase,string $scope):bool
    {
        $record=null;return $callback($action,$phase,$scope,$record)===true;
    }
    private function authority(string $action):callable
    {
        $dependencies=($this->dependencies)();
        if(in_array($action,['request','confirm','cancel'],true)){$callback=$dependencies[5];}
        elseif(in_array($action,['initialize','maintain','rotate','review'],true)){$callback=$dependencies[8];}
        elseif($action==='notification'){$callback=$dependencies[9];}
        else{throw new ConfigurationException('Unknown account authority purpose.','configuration.account_authority');}
        if($callback===null){throw new SecurityException('Current account operation authority required.','account.denied');}return $callback;
    }
    private function budgets():callable {return ($this->dependencies)()[6];}
    private function policy():Policy {return ($this->dependencies)()[7];}
    private static function id(string $id):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$id)){throw new ValidationException('Invalid recovery proof.','account.proof');}}
    private static function source(string $source):void {Guard::label($source);if(preg_match('//u',$source)!==1){throw new ValidationException('Use a bounded server-derived request source.','account.source');}}
    private function authorize(string $action,string $phase,?AccountRecord $record=null):void
    {
        if($this->unit()->invoke($this->authority($action),[$action,$phase,$this->scope,$record],'account.authority')!==true){throw new SecurityException('Current account operation authority required.','account.denied');}
    }
    private function charge(string $action,string $phase,string $source,?Address $address=null,?string $subject=null,string $operation=''):void
    {
        $arguments=[$action,$phase,$this->scope,$source,$address,$subject,$operation];
        if($phase==='public'){
            try{$result=call_user_func_array($this->budgets(),$arguments);}catch(\Throwable $error){throw new DependencyException('Account request budget unavailable.','account.budget');}
        }else{$result=$this->unit()->invoke($this->budgets(),$arguments,'account.budget');}
        if($result!==true){$refusal=$phase==='public'?null:StateBudgetRefusal::fromTransaction($this->unit());throw $refusal??new SecurityException('Account request budget refused.','account.budget');}
    }
    private function host(string $method,array $arguments):?AccountRecord
    {
        $result=$this->unit()->invoke([$this->accounts(),$method],$arguments,'account.repository');
        if($result!==null&&(!$result instanceof AccountRecord||$result->account()->scope()!==$this->scope)){throw new ConfigurationException('Host account scope differs from the operation.','configuration.account_repository');}return $result;
    }
    private function current(string $subject):?AccountRecord
    {
        $record=$this->host('find',[$this->scope,$subject]);if($record!==null&&$record->account()->subject()!==$subject){throw new ConfigurationException('Host returned another account.','configuration.account_repository');}return $record;
    }
    private function byAddress(Address $address):?AccountRecord
    {
        $record=$this->host('findAddress',[$this->scope,$address]);if($record!==null&&!$record->address()->equals($address)){throw new ConfigurationException('Host returned another address.','configuration.account_repository');}return $record;
    }
    private function owner(string $subject):string {return hash('sha256',self::json(['SoSecurity.Account.MailboxRecovery.Owner.1',$this->scope,$subject]));}
    private function cursor(string $subject):string {return hash('sha256','SoSecurity.Account.MailboxRecovery.Cursor.1.'.$this->owner($subject));}
    private static function json(array $data):string {return json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    /** @return never */
    private static function corrupt():void {throw new StorageException('Recovery state cannot be authenticated.','account.corrupt');}
    private function pointer(?array $row,string $subject):?string
    {
        if($row===null){return null;}$data=json_decode($row['payload'],true,3);
        if($row['kind']!=='budget'||$row['owner']!==$this->owner($subject)||!is_array($data)||array_keys($data)!==['format','subject','flow_id']||$data['format']!==1||$data['subject']!==$subject||!is_string($data['flow_id'])||!preg_match('/\A[a-f0-9]{64}\z/D',$data['flow_id'])||self::json($data)!==$row['payload']){self::corrupt();}return $data['flow_id'];
    }
    private function flow(array $row):array
    {
        $f=json_decode($row['payload'],true,3);$fields=['format','purpose','subject','account','identity','factor_binding','address_tag','token_digest','issued_at','valid_until','attempts','resends','state','notice_id','resend_at','alert_id','completion_notices','completed_account'];
        if($row['kind']!=='recover'||!is_array($f)||array_keys($f)!==$fields||$f['format']!==1||$f['purpose']!=='mailbox_recovery'){self::corrupt();}
        foreach(['subject','factor_binding'] as $key){if(!is_string($f[$key])||strlen($f[$key])>256||($key==='subject'&&$f[$key]==='')||preg_match('/[\x00-\x1f\x7f]/',$f[$key])||preg_match('//u',$f[$key])!==1){self::corrupt();}}
        foreach(['account','identity','address_tag','token_digest','notice_id','alert_id'] as $key){if(!is_string($f[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$f[$key])){self::corrupt();}}
        if(!is_array($f['completion_notices'])||array_values($f['completion_notices'])!==$f['completion_notices']||count($f['completion_notices'])!==($f['state']==='consumed'?2:0)){self::corrupt();}foreach($f['completion_notices'] as $id){if(!is_string($id)||!preg_match('/\A[a-f0-9]{64}\z/D',$id)){self::corrupt();}}if(count(array_unique($f['completion_notices']))!==count($f['completion_notices'])||array_intersect($f['completion_notices'],[$f['notice_id'],$f['alert_id']])){self::corrupt();}
        foreach(['issued_at','valid_until','attempts','resends','resend_at'] as $key){if(!is_int($f[$key])||$f[$key]<0){self::corrupt();}}
        if($f['issued_at']<$row['created_at']||$f['valid_until']<=$f['issued_at']||$f['valid_until']-$f['issued_at']>$this->policy()->lifetime('recover_address')||$f['attempts']>$this->policy()->maximumAttempts()||$f['resends']>$this->policy()->maximumResends()||$f['resend_at']<$f['issued_at']||$f['resend_at']>$f['valid_until']||$row['retire_at']<$f['valid_until']||!in_array($f['state'],['pending','consumed','locked','cancelled'],true)||$row['owner']!==$this->owner($f['subject'])||!is_string($f['completed_account'])||($f['state']==='consumed'?!preg_match('/\A[a-f0-9]{64}\z/D',$f['completed_account']):$f['completed_account']!=='')||self::json($f)!==$row['payload']){self::corrupt();}return $f;
    }
    private function facts(AccountRecord $record):array
    {
        $identity=$this->unit()->invoke([$this->accounts(),'identity'],[$record],'account.repository');
        if(!$identity instanceof \SoSecurity\Auth\Account||$identity->scope()!==$this->scope||$identity->subject()!==$record->account()->subject()||$identity->enabled()!==$record->account()->enabled()||$identity->roles()!==$record->account()->roles()||$identity->mfaRequired()!==$record->account()->mfaRequired()){self::corrupt();}
        $factor=($this->dependencies)()[10];$binding=$factor===null?null:$this->unit()->invoke([$factor,'binding'],[$this->scope,$record->account()->subject()],'account.recovery_factor');
        if($binding!==null&&(!is_string($binding)||$binding===''||strlen($binding)>256||preg_match('/[\x00-\x1f\x7f]/',$binding)||preg_match('//u',$binding)!==1)){self::corrupt();}
        return ['record'=>$record,'identity'=>$identity,'factor_binding'=>$binding ?? ''];
    }
    private function bound(array $f,array $facts):bool {return hash_equals($f['account'],$facts['record']->fingerprint())&&hash_equals($f['identity'],$facts['identity']->fingerprint())&&$f['factor_binding']===$facts['factor_binding'];}
    private function binding(AccountRecord $record,Address $target,string $token):string
    {
        return hash_hmac('sha256',self::json(['SoSecurity.Account.MailboxRecovery.Proof.1',$this->context,$this->scope,$record->fingerprint(),$target->value()]),hex2bin($token));
    }
    private function eligible(AccountRecord $record):bool {return $record->status()==='active'&&$record->verified()&&$record->account()->enabled();}
    private function target(array $flow):Notice
    {
        $row=$this->ledger()->read($flow['notice_id']);if($row===null){self::corrupt();}$data=$this->noticeData($row);
        if($data['type']!=='recover_address'){self::corrupt();}$notice=$this->notifications()->open($data['envelope'],$this->scope,$flow['notice_id'],'recover_address');
        if($this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$row['owner']||$notice->expiresAt()!==$flow['valid_until']||!hash_equals($flow['token_digest'],hash('sha256',$notice->token()))){self::corrupt();}return $notice;
    }
    private function matches(array $flow,AccountRecord $record,string $token):bool
    {
        if(!$this->eligible($record)||!$this->bound($flow,$this->facts($record))||!hash_equals($flow['token_digest'],hash('sha256',$token))){return false;}
        $notice=$this->target($flow);return !$notice->recipient()->equals($record->address())&&hash_equals($flow['address_tag'],$this->binding($record,$notice->recipient(),$token));
    }
    private function saveFlow(array $row,array $flow,int $retireAt):void {$this->ledger()->put($row['record_id'],$row['owner'],'recover',self::json($flow),$retireAt,$row['revision']);}
    private function notice(string $flowId,Address $recipient,string $type,string $token,int $until):string
    {
        $id=bin2hex(random_bytes(32));$now=$this->unit()->now();$notice=new Notice($this->scope,$id,$type,$recipient,$token,$now,$until);$envelope=$this->notifications()->seal($notice);
        $payload=self::json(['format'=>1,'type'=>$type,'issued_at'=>$now,'valid_until'=>$until,'envelope'=>$envelope]);
        $this->ledger()->put($id,$flowId,'notice',$payload,$until);
        $this->queue()->enqueue(new Message($this->scope,'account-mailbox-recovery',Message::identifier('account-notice-'.$id,$now),'mail','account.notice',$id,$id),'account-system');return $id;
    }
    public function initialize():void
    {($this->stateGuard)();
        $this->authority('initialize');
        $this->queue()->initialize($this->scope,'account-mailbox-recovery','account-system');
        $this->unit()->run(function():void{$this->authorize('initialize','before');$this->ledger()->initialize();},null,function():void{$this->authorize('initialize','commit');});
    }
    /** Uniform accepted outcome; no selectors, subjects or token secrets are returned. Source is supplied by trusted host routing. */
    public function request(string $currentAddress,string $newAddress,string $source):void
    {
        if($this->native===null){$this->requestInternal($currentAddress,$newAddress,$source);return;}
        ($this->native)('request',function()use($currentAddress,$newAddress,$source):array{
            new Address($currentAddress,$this->policy()->allowsSmtpUtf8());$address=new Address($newAddress,$this->policy()->allowsSmtpUtf8());StateLifecycleInput::source($source);$budgetId=bin2hex(random_bytes(16));$this->charge('request','public',$source,$address,null,$budgetId);return [$budgetId];
        },function(array $admission)use($currentAddress,$newAddress,$source):void{$this->requestInternal($currentAddress,$newAddress,$source,$admission[0]);});
    }
    private function requestInternal(string $currentAddress,string $newAddress,string $source,?string $admission=null):void
    {($this->stateGuard)();
        $current=new Address($currentAddress,$this->policy()->allowsSmtpUtf8());$target=new Address($newAddress,$this->policy()->allowsSmtpUtf8());self::source($source);$budgetId=$admission??bin2hex(random_bytes(16));if($admission===null){$this->charge('request','public',$source,$target,null,$budgetId);}
        $this->unit()->run(function()use($current,$target,$source,$budgetId):?array{
            $this->ledger()->checkpoint();$this->authorize('request','before');$record=$this->byAddress($current);if($record===null){return null;}
            $subject=$record->account()->subject();$this->charge('request','subject',$source,$target,$subject,$budgetId);if(!$this->eligible($record)||$target->equals($record->address())){return null;}$facts=$this->facts($record);
            $cursor=$this->ledger()->read($this->cursor($subject));$flowId=$this->pointer($cursor,$subject);$row=$flowId===null?null:$this->ledger()->read($flowId);$now=$this->unit()->now();if($flowId!==null&&$row===null){self::corrupt();}$flow=$row===null?null:$this->flow($row);
            if($flow!==null&&$flow['valid_until']>$now){
                if($flow['state']!=='pending'||$flow['resend_at']>$now||$flow['resends']>=$this->policy()->maximumResends()||!$this->bound($flow,$facts)||!$this->target($flow)->recipient()->equals($target)){return null;}
                $until=$flow['valid_until'];$resends=$flow['resends']+1;$attempts=$flow['attempts'];$revision=$row['revision'];$alert=$flow['alert_id'];$this->ledger()->capacity(1);
            }else{
                $this->ledger()->capacity($cursor===null?4:3);$flowId=bin2hex(random_bytes(32));$row=null;$until=$now+$this->policy()->lifetime('recover_address');$resends=0;$attempts=0;$revision=null;
                $alert=$this->notice($flowId,$record->address(),'address_recovery_started','',$now+$this->policy()->lifetime('address_recovery_started'));
            }
            $token=bin2hex(random_bytes(32));$noticeId=$this->notice($flowId,$target,'recover_address',$token,$until);
            $flow=['format'=>1,'purpose'=>'mailbox_recovery','subject'=>$subject,'account'=>$record->fingerprint(),'identity'=>$facts['identity']->fingerprint(),'factor_binding'=>$facts['factor_binding'],'address_tag'=>$this->binding($record,$target,$token),'token_digest'=>hash('sha256',$token),'issued_at'=>$now,'valid_until'=>$until,'attempts'=>$attempts,'resends'=>$resends,'state'=>'pending','notice_id'=>$noticeId,'resend_at'=>min($until,$now+$this->policy()->resendSeconds()),'alert_id'=>$alert,'completion_notices'=>[],'completed_account'=>''];
            $this->ledger()->put($flowId,$this->owner($subject),'recover',self::json($flow),$until+$this->policy()->lifetime('address_recovered'),$revision);
            if($row===null){$this->ledger()->put($this->cursor($subject),$this->owner($subject),'budget',self::json(['format'=>1,'subject'=>$subject,'flow_id'=>$flowId]),$until+$this->policy()->lifetime('address_recovered'),$cursor===null?null:$cursor['revision']);}
            $this->authorize('request','after',$record);$rows=[];foreach([$flowId,$noticeId,$alert,$this->cursor($subject)] as $id){$rows[$id]=$this->ledger()->read($id);if($rows[$id]===null){self::corrupt();}}return ['facts'=>$facts,'rows'=>$rows,'checkpoint'=>$this->ledger()->checkpoint()];
        },null,function(?array $state)use($target,$source,$budgetId):void{
            if($state===null){return;}$record=$state['facts']['record'];$this->authorize('request','commit',$record);$this->charge('request','final',$source,$target,$record->account()->subject(),$budgetId);$fresh=$this->current($record->account()->subject());if($fresh===null||!$this->bound(['account'=>$record->fingerprint(),'identity'=>$state['facts']['identity']->fingerprint(),'factor_binding'=>$state['facts']['factor_binding']],$this->facts($fresh))||$this->ledger()->checkpoint()!==$state['checkpoint']){self::corrupt();}foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){self::corrupt();}}
        });
    }
    /** External factor/approval work never holds the SQL transaction. Prior charges and proofs are not refunded. */
    private function external(callable $callback,array $arguments,\SoSecurity\Support\Deadline $deadline,int &$observed,int $until)
    {
        $clock=($this->dependencies)()[12];$deadline->check('account.timeout');
        try{$now=$clock->now();}catch(\Throwable $error){throw new DependencyException('Recovery clock unavailable.','account.clock');}
        if($now<$observed||$now>=$until){throw new SecurityException('Recovery proof expired or its clock moved backwards.','account.expired');}$observed=$now;
        $local=array_values($arguments);$references=[];foreach($local as &$value){$references[]=&$value;}unset($value);
        try{$result=call_user_func_array($callback,$references);}catch(\Throwable $error){throw new DependencyException('Recovery dependency unavailable.','account.recovery_authority');}
        $deadline->check('account.timeout');
        try{$now=$clock->now();}catch(\Throwable $error){throw new DependencyException('Recovery clock unavailable.','account.clock');}
        if($now<$observed||$now>=$until){throw new SecurityException('Recovery authorization expired or its clock moved backwards.','account.expired');}$observed=$now;return $result;
    }
    private function approval(string $phase,RecoveryApproval $request,array $proof):void
    {
        $callback=($this->dependencies)()[11];if($this->unit()->invoke($callback,[$phase,$request,$proof],'account.mailbox_approval')!==true){throw new SecurityException('Current strong mailbox recovery approval required.','account.mailbox_approval');}
    }
    private function reviewData(array $state,string $selector):RecoveryApproval
    {
        $facts=$state['facts'];$context=hash('sha256',self::json(['SoSecurity.Account.MailboxRecovery.Approval.1',$this->context,$selector,$facts['record']->fingerprint(),$facts['identity']->fingerprint(),$facts['factor_binding'],$state['target']->value(),$state['flow']['token_digest'],$state['flow']['valid_until']]));
        return new RecoveryApproval('recover_address',$context,$facts['record'],$facts['identity'],$facts['factor_binding'],$state['target'],$state['flow']['valid_until']);
    }
    /** Private management review; no proof secret, grant consumption, account write or implicit approval. */
    public function approvalRequest(string $selector,string $source):?RecoveryApproval
    {($this->stateGuard)();
        self::id($selector);self::source($source);$this->authority('review');$budgetId=bin2hex(random_bytes(16));$this->charge('confirm','public',$source,null,null,$budgetId);
        $state=$this->unit()->run(function()use($selector,$source,$budgetId):?array{
            $this->ledger()->checkpoint();$this->authorize('review','before');$row=$this->ledger()->read($selector);if($row===null||$row['kind']!=='recover'){return null;}$flow=$this->flow($row);
            if($flow['state']!=='pending'||$flow['valid_until']<=$this->unit()->now()||$flow['attempts']>=$this->policy()->maximumAttempts()||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$selector){return null;}
            $record=$this->current($flow['subject']);if($record===null||!$this->eligible($record)||!$this->bound($flow,$this->facts($record))){return null;}$target=$this->target($flow)->recipient();$this->charge('confirm','subject',$source,$target,$flow['subject'],$budgetId);$this->authorize('review','read',$record);$this->charge('confirm','final',$source,$target,$flow['subject'],$budgetId);
            return ['facts'=>$this->facts($record),'row'=>$row,'flow'=>$flow,'target'=>$target];
        },null,function(?array $state):void{if($state!==null){$this->authorize('review','commit',$state['facts']['record']);$this->attemptCurrent($state);}},function(?array $state):void{if($state!==null){$this->authorize('review','complete',$state['facts']['record']);$this->attemptCurrent($state);}});
        return $state===null?null:$this->reviewData($state,$selector);
    }
    /** New-mailbox proof is necessary, never sufficient; independent strong approval is mandatory. */
    public function confirm(string $selector,string $token,string $source,array $approvalProof):bool
    {
        if($this->native===null){return $this->confirmInternal($selector,$token,$source,$approvalProof);}
        return ($this->native)('confirm',function()use($selector,$token,$source,$approvalProof):array{
            StateLifecycleInput::id($selector);StateLifecycleInput::id($token);StateLifecycleInput::source($source);$proof=StateLifecycleInput::proof($approvalProof,true);$budgetId=bin2hex(random_bytes(16));$this->charge('confirm','public',$source,null,null,$budgetId);return [$budgetId,$proof];
        },function(array $admission)use($selector,$token,$source):bool{return $this->confirmInternal($selector,$token,$source,$admission[1],$admission[0]);});
    }
    private function confirmInternal(string $selector,string $token,string $source,array $approvalProof,?string $admission=null):bool
    {($this->stateGuard)();
        self::id($selector);self::id($token);self::source($source);$keys=array_keys($approvalProof);sort($keys);
        if($keys!==['code','type']||$approvalProof['type']!=='approved'||!is_string($approvalProof['code'])||$approvalProof['code']===''||strlen($approvalProof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$approvalProof['code'])){throw new ValidationException('Explicit bounded strong approval required.','account.recovery_proof');}
        $deadline=new \SoSecurity\Support\Deadline($this->policy()->ioMilliseconds());$budgetId=$admission??bin2hex(random_bytes(16));if($admission===null){$this->charge('confirm','public',$source,null,null,$budgetId);}
        $proof=$this->unit()->run(function()use($selector,$token,$source,$budgetId):?array{
            $this->ledger()->checkpoint();$this->authorize('confirm','before');$row=$this->ledger()->read($selector);if($row===null||$row['kind']!=='recover'){return null;}$flow=$this->flow($row);
            if($flow['state']!=='pending'||$flow['valid_until']<=$this->unit()->now()||$flow['attempts']>=$this->policy()->maximumAttempts()){return null;}
            $record=$this->current($flow['subject']);if($record===null||!$this->eligible($record)||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$selector){return null;}
            $target=$this->target($flow)->recipient();$facts=$this->facts($record);$this->charge('confirm','subject',$source,$target,$flow['subject'],$budgetId);$this->authorize('confirm','proof',$record);
            $valid=$this->matches($flow,$record,$token);++$flow['attempts'];if(!$valid&&$flow['attempts']===$this->policy()->maximumAttempts()){$flow['state']='locked';}$this->saveFlow($row,$flow,$row['retire_at']);$saved=$this->ledger()->read($selector);if($saved===null){self::corrupt();}
            if(!$valid){$this->charge('confirm','final',$source,$target,$flow['subject'],$budgetId);}return ['valid'=>$valid,'facts'=>$facts,'row'=>$saved,'flow'=>$flow,'at'=>$this->unit()->now(),'target'=>$target];
        },null,function(?array $state):void{if($state!==null){$this->attemptCurrent($state);}},null,$deadline);
        if($proof===null||!$proof['valid']){return false;}$facts=$proof['facts'];$observed=$proof['at'];$until=$proof['flow']['valid_until'];
        if($facts['record']->account()->mfaRequired()&&(($this->dependencies)()[10]===null||$facts['factor_binding']==='')){return false;}
        $request=$this->reviewData($proof,$selector);
        if($this->external(($this->dependencies)()[11],['verify',$request,$approvalProof],$deadline,$observed,$until)!==true){return false;}
        try{return $this->unit()->run(function()use($proof,$selector,$token,$request,$approvalProof):?array{
            $this->ledger()->checkpoint();$row=$this->ledger()->read($selector);if($row===null||$row!==$proof['row']){return null;}$flow=$this->flow($row);$record=$this->current($flow['subject']);
            if($record===null||$flow['state']!=='pending'||$flow['valid_until']<=$this->unit()->now()||!$this->matches($flow,$record,$token)||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$selector){return null;}
            $this->authorize('confirm','replace',$record);$this->approval('current',$request,$approvalProof);$this->attemptCurrent($proof);
            $this->ledger()->capacity(2);$active=$this->host('changeAddress',[$record,$proof['target']]);if($active===null){throw new StorageException('Address recovery changed concurrently.','account.conflict');}
            if($active->account()->subject()!==$record->account()->subject()||!$active->address()->equals($proof['target'])||$active->addressVersion()===$record->addressVersion()||!$this->eligible($active)||$active->account()->version()===$record->account()->version()||$active->account()->roles()!==$record->account()->roles()||$active->account()->mfaRequired()!==$record->account()->mfaRequired()){self::corrupt();}
            $completed=$this->facts($active);if($completed['identity']->fingerprint()===$proof['facts']['identity']->fingerprint()||$completed['factor_binding']!==$proof['facts']['factor_binding']){self::corrupt();}
            $noticeUntil=$this->unit()->now()+$this->policy()->lifetime('address_recovered');$flow['state']='consumed';$flow['completed_account']=$active->fingerprint();
            $flow['completion_notices']=[$this->notice($selector,$record->address(),'address_recovered','',$noticeUntil),$this->notice($selector,$active->address(),'address_recovered','',$noticeUntil)];$this->saveFlow($row,$flow,max($row['retire_at'],$noticeUntil));$saved=$this->ledger()->read($selector);if($saved===null){self::corrupt();}return ['facts'=>$completed,'row'=>$saved];
        },function()use($observed,$until):bool{$now=$this->unit()->now();if($now<$observed||$now>=$until){throw new SecurityException('Mailbox recovery authorization expired.','account.expired');}return true;},function(?array $state)use($proof,$request,$approvalProof,$source,$budgetId):void{
            if($state===null){return;}$record=$state['facts']['record'];$this->authorize('confirm','commit',$record);$this->approval('commit',$request,$approvalProof);$this->completed($state,$proof['flow']['valid_until']);$this->charge('confirm','final',$source,$proof['target'],$record->account()->subject(),$budgetId);$this->completed($state,$proof['flow']['valid_until']);
        },function(?array $state)use($proof,$request,$approvalProof):void{
            if($state!==null){$this->authorize('confirm','complete',$state['facts']['record']);$this->approval('complete',$request,$approvalProof);$this->completed($state,$proof['flow']['valid_until']);}
        },$deadline)!==null;}catch(\Throwable $error){if($this->unit()->committed()){throw new StorageException('Address recovery committed but completion is unknown.','account.completion_unknown');}throw $error;}
    }
    private function attemptCurrent(array $state):void
    {
        $record=$this->current($state['flow']['subject']);if($record===null||$this->unit()->now()>=$state['flow']['valid_until']||$record->fingerprint()!==$state['facts']['record']->fingerprint()||$this->ledger()->read($state['row']['record_id'])!==$state['row']){throw new SecurityException('Mailbox recovery changed before approval.','account.changed');}
        $fresh=$this->facts($record);if($fresh['identity']->fingerprint()!==$state['facts']['identity']->fingerprint()||$fresh['factor_binding']!==$state['facts']['factor_binding']){throw new SecurityException('Mailbox recovery identity changed.','account.changed');}
    }
    private function completed(array $state,int $until):void
    {
        $record=$this->current($state['facts']['record']->account()->subject());if($record===null||$this->unit()->now()>=$until||$record->fingerprint()!==$state['facts']['record']->fingerprint()||$this->ledger()->read($state['row']['record_id'])!==$state['row']){throw new SecurityException('Recovery completion changed or expired.','account.changed');}
        $fresh=$this->facts($record);if($fresh['identity']->fingerprint()!==$state['facts']['identity']->fingerprint()||$fresh['factor_binding']!==$state['facts']['factor_binding']){throw new SecurityException('Recovery authentication changed before completion.','account.changed');}
    }
    /** Consume this recovery proof to cancel, without changing the host account or granting a session. */
    public function cancel(string $selector,string $token,string $source):bool
    {
        if($this->native===null){return $this->cancelInternal($selector,$token,$source);}
        return ($this->native)('cancel',function()use($selector,$token,$source):array{
            StateLifecycleInput::id($selector);StateLifecycleInput::id($token);StateLifecycleInput::source($source);$budgetId=bin2hex(random_bytes(16));$this->charge('cancel','public',$source,null,null,$budgetId);return [$budgetId];
        },function(array $admission)use($selector,$token,$source):bool{return $this->cancelInternal($selector,$token,$source,$admission[0]);});
    }
    private function cancelInternal(string $selector,string $token,string $source,?string $admission=null):bool
    {($this->stateGuard)();
        self::id($selector);self::id($token);self::source($source);$budgetId=$admission??bin2hex(random_bytes(16));if($admission===null){$this->charge('cancel','public',$source,null,null,$budgetId);}
        try{
            $result=$this->unit()->run(function()use($selector,$token,$source,$budgetId):?array{
                $this->ledger()->checkpoint();$this->authorize('cancel','before');$row=$this->ledger()->read($selector);if($row===null||$row['kind']!=='recover'){return null;}$flow=$this->flow($row);$now=$this->unit()->now();
                if($flow['state']!=='pending'||$flow['valid_until']<=$now||$flow['attempts']>=$this->policy()->maximumAttempts()){return null;}
                $record=$this->current($flow['subject']);if($record===null||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$selector){return null;}
                $this->authorize('cancel','proof',$record);$this->charge('cancel','subject',$source,$record->address(),$flow['subject'],$budgetId);$valid=$this->matches($flow,$record,$token);++$flow['attempts'];
                if($valid){$flow['state']='cancelled';$flow['resend_at']=min($flow['valid_until'],max($flow['resend_at'],$now+$this->policy()->resendSeconds()));}elseif($flow['attempts']===$this->policy()->maximumAttempts()){$flow['state']='locked';}
                $this->saveFlow($row,$flow,$row['retire_at']);$this->charge('cancel','final',$source,$record->address(),$flow['subject'],$budgetId);return ['record'=>$record,'expires'=>$flow['valid_until'],'cancelled'=>$valid];
            },null,function(?array $outcome):void{
                if($outcome===null){return;}if($this->unit()->now()>=$outcome['expires']){throw new StorageException('Cancellation proof expired before commit.','account.expired');}$current=$this->current($outcome['record']->account()->subject());if($current===null||$current->fingerprint()!==$outcome['record']->fingerprint()){self::corrupt();}$this->authorize('cancel','commit',$current);
            },function(?array $outcome):void{
                if($outcome===null){return;}if($this->unit()->now()>=$outcome['expires']){throw new StorageException('Cancellation completion crossed its deadline.','account.completion_unknown');}$current=$this->current($outcome['record']->account()->subject());if($current===null||$current->fingerprint()!==$outcome['record']->fingerprint()){self::corrupt();}$this->authorize('cancel','complete',$current);
            });return $result!==null&&$result['cancelled'];
        }catch(\Throwable $error){if($this->unit()->committed()){throw new StorageException('Cancellation committed but completion could not be confirmed.','account.completion_unknown');}throw $error;}
    }
    private function noticeData(array $row):array
    {
        $data=json_decode($row['payload'],true,3);
        if($row['kind']!=='notice'||!is_array($data)||array_keys($data)!==['format','type','issued_at','valid_until','envelope']||$data['format']!==1||!in_array($data['type'],['recover_address','address_recovery_started','address_recovered'],true)||!is_int($data['issued_at'])||!is_int($data['valid_until'])||!is_string($data['envelope'])||strlen($data['envelope'])>8192||$data['issued_at']<$row['created_at']||$data['valid_until']<=$data['issued_at']||$data['valid_until']-$data['issued_at']>$this->policy()->lifetime($data['type'])||$row['retire_at']<$data['valid_until']||self::json($data)!==$row['payload']){self::corrupt();}return $data;
    }
    /** Parse only known recovery records; future workflow formats must not be silently adopted or deleted. */
    private function maintenanceData(array $row):array
    {
        if($row['kind']==='recover'){return $this->flow($row);}
        if($row['kind']==='budget'){
            $data=json_decode($row['payload'],true,3);if(!is_array($data)||!isset($data['subject'])||!is_string($data['subject'])||$data['subject']===''||strlen($data['subject'])>256||preg_match('/[\x00-\x1f\x7f]/',$data['subject'])||preg_match('//u',$data['subject'])!==1){self::corrupt();}
            $this->pointer($row,$data['subject']);if($row['record_id']!==$this->cursor($data['subject'])){self::corrupt();}$target=$this->ledger()->read($data['flow_id']);if($target===null){self::corrupt();}$parsed=$this->flow($target);if($parsed['subject']!==$data['subject']||$row['retire_at']<$parsed['valid_until']){self::corrupt();}return $data;
        }
        if($row['kind']==='notice'){
            $data=$this->noticeData($row);$meta=$this->notifications()->metadata($data['envelope'],$this->scope,$row['record_id'],$data['type']);if($meta['issued_at']!==$data['issued_at']||$meta['expires_at']!==$data['valid_until']||$row['retire_at']<$data['valid_until']){self::corrupt();}return $data+['key_id'=>$meta['key_id']];
        }
        self::corrupt();
    }
    private static function pageInput(int $limit,string $after):void {if($limit<1||$limit>50||($after!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$after))){throw new ConfigurationException('Use a bounded account maintenance cursor and page.','configuration.account_maintenance');}}
    private static function progress(array $headers,int $limit,array $counts):array {$size=count($headers);return ['examined'=>$size]+$counts+['after'=>$size===$limit?$headers[$size-1]['record_id']:'','done'=>$size<$limit];}
    /** At most limit headers plus their current-pointer partner (maximum 2*limit rows). Host accounts/Outbox are never deleted. */
    /** Native management requires explicit current account roles and the exact page target. */
    public function maintainFor(StateAccountPolicy $policy,StatePermission $permission,int $limit=20,string $after=''):?array
    {return $this->nativeMaintenance('maintain',$policy,$permission,$limit,$after);}
    public function rotateFor(StateAccountPolicy $policy,StatePermission $permission,int $limit=20,string $after=''):?array
    {return $this->nativeMaintenance('rotate',$policy,$permission,$limit,$after);}
    private function nativeMaintenance(string $action,StateAccountPolicy $policy,StatePermission $permission,int $limit,string $after):?array
    {
        if($this->maintenanceState===null){throw new ConfigurationException('Declare the complete native account maintenance graph.','configuration.state_connection');}
        self::pageInput($limit,$after);$guard=$this->authority($action);$scope=$this->scope;
        return $this->maintenanceState->maintenance('mailbox_recovery',$action,$policy,$permission,$limit,$after,function()use($guard,$action,$scope):bool{
            // Host admission is outside SQL observation units; the witness checks the full source before effects.
            $phase='admission';$record=null;try{return $guard($action,$phase,$scope,$record)===true;}catch(\Throwable $error){throw new \SoSecurity\Exception\DependencyException('Account maintenance admission unavailable.','account.authority');}
        },function()use($action,$limit,$after):array{return $this->$action($limit,$after);});
    }
    public function maintain(int $limit=20,string $after=''):array
    {($this->stateGuard)();
        self::pageInput($limit,$after);$this->authority('maintain');$state=$this->unit()->run(function()use($limit,$after):array{
            $this->ledger()->checkpoint();$this->authorize('maintain','before');$headers=$this->ledger()->page($limit,$after);$remove=[];$expected=[];$now=$this->unit()->now();
            foreach($headers as $header){
                if(isset($remove[$header['record_id']])){continue;}$row=$this->ledger()->read($header['record_id']);if($row===null){self::corrupt();}$data=$this->maintenanceData($row);if($row['retire_at']>$now){$expected[$row['record_id']]=$row;continue;}
                if($row['kind']==='recover'){
                    if($data['valid_until']>$now){self::corrupt();}$pointer=$this->ledger()->read($this->cursor($data['subject']));
                    if($pointer!==null&&$this->pointer($pointer,$data['subject'])===$row['record_id']){if($pointer['retire_at']>$now){self::corrupt();}$remove[$pointer['record_id']]=$pointer['revision'];}
                }elseif($row['kind']==='budget'){
                    $flow=$this->ledger()->read($data['flow_id']);if($flow===null){self::corrupt();}$parsed=$this->flow($flow);
                    if($parsed['subject']!==$data['subject']||$parsed['valid_until']>$now||$flow['retire_at']>$now){self::corrupt();}$remove[$flow['record_id']]=$flow['revision'];
                }
                $remove[$row['record_id']]=$row['revision'];
            }
            $removed=$remove?$this->ledger()->remove($remove):0;return ['result'=>self::progress($headers,$limit,['removed'=>$removed]),'checkpoint'=>$this->ledger()->checkpoint(),'rows'=>array_diff_key($expected,$remove)];
        },null,function(array $state):void{
            $this->authorize('maintain','commit');foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){throw new StorageException('Retained recovery body changed before commit.','account.changed');}}
            if($this->ledger()->checkpoint()!==$state['checkpoint']){throw new StorageException('Recovery maintenance changed before commit.','account.changed');}
        },function(array $state):void{
            try{$this->authorize('maintain','complete');}
            catch(\Throwable $error){throw new StorageException('Account request history maintenance completion is uncertain; committed changes are not rolled back.','account.completion_unknown');}
        });
        return $state['result'];
    }
    /** Bounded reseal/reencryption. Pause old writers before retiring any keys; done is a page boundary only. */
    public function rotate(int $limit=20,string $after=''):array
    {($this->stateGuard)();
        self::pageInput($limit,$after);$this->authority('rotate');$state=$this->unit()->run(function()use($limit,$after):array{
            $this->ledger()->checkpoint();$this->authorize('rotate','before');$headers=$this->ledger()->page($limit,$after);$root=$this->ledger()->rotateRoot();$resealed=0;$reencrypted=0;$expected=[];
            foreach($headers as $header){
                $row=$this->ledger()->read($header['record_id']);if($row===null){self::corrupt();}$data=$this->maintenanceData($row);$payload=$row['payload'];
                if($row['kind']==='notice'&&$data['key_id']!==$this->notifications()->currentId()){
                    unset($data['key_id']);$data['envelope']=$this->notifications()->reencrypt($data['envelope'],$this->scope,$row['record_id'],$data['type']);$payload=self::json($data);++$reencrypted;
                }
                if($payload!==$row['payload']||$row['seal_key']!==$this->ledger()->currentKeyId()){$row=$this->ledger()->put($row['record_id'],$row['owner'],$row['kind'],$payload,$row['retire_at'],$row['revision']);++$resealed;}$expected[$row['record_id']]=$row;
            }
            return ['result'=>self::progress($headers,$limit,['resealed'=>$resealed,'reencrypted'=>$reencrypted,'root_rotated'=>$root]),'checkpoint'=>$this->ledger()->checkpoint(),'rows'=>$expected];
        },null,function(array $state):void{
            $this->authorize('rotate','commit');foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){throw new StorageException('Recovery rotation body changed before commit.','account.changed');}}
            if($this->ledger()->checkpoint()!==$state['checkpoint']){throw new StorageException('Recovery rotation state changed before commit.','account.changed');}
        },function(array $state):void{
            try{$this->authorize('rotate','complete');}
            catch(\Throwable $error){throw new StorageException('Account request history maintenance completion is uncertain; committed changes are not rolled back.','account.completion_unknown');}
        });
        return $state['result'];
    }
    /** Private authenticated snapshot. It never invokes or substitutes for worker authority. */
    private function notificationState(string $id):?array
    {
        $row=$this->ledger()->read($id);if($row===null){return null;}$data=$this->noticeData($row);if($data['valid_until']<=$this->unit()->now()){return null;}
        $flowRow=$this->ledger()->read($row['owner']);if($flowRow===null){self::corrupt();}$flow=$this->flow($flowRow);$notice=$this->notifications()->open($data['envelope'],$this->scope,$id,$data['type']);if($notice->issuedAt()!==$data['issued_at']||$notice->expiresAt()!==$data['valid_until']){self::corrupt();}$record=null;
        if($data['type']==='recover_address'){
            $record=$this->current($flow['subject']);if($flow['notice_id']!==$id||$record===null||$flow['state']!=='pending'||$flow['valid_until']<=$this->unit()->now()||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$row['owner']||!$this->matches($flow,$record,$notice->token())){return null;}
        }elseif($data['type']==='address_recovery_started'){if($flow['alert_id']!==$id){return null;}}
        elseif($flow['state']!=='consumed'||!in_array($id,$flow['completion_notices'],true)){return null;}
        return ['notice_row'=>$row,'flow_row'=>$flowRow,'record'=>$record,'delivery'=>new MailboxRecoveryDelivery($notice,$data['type']==='recover_address'?$row['owner']:'')];
    }
    private function unchangedNotification(array $state):void
    {
        $fresh=$this->notificationState($state['delivery']->notice()->id());
        if($fresh===null||$fresh['notice_row']!==$state['notice_row']||$fresh['flow_row']!==$state['flow_row']||($fresh['record']===null?null:$fresh['record']->fingerprint())!==($state['record']===null?null:$state['record']->fingerprint())){
            throw new SecurityException('Account notification changed during delivery authorization.','account.notification_changed');
        }
        if($state['delivery']->notice()->expiresAt()<=$this->unit()->now()){throw new SecurityException('Account notification expired during completion.','account.expired');}
    }
    /** Trusted worker read only. This authorization does not claim SMTP success or validate an Outbox lease. */
    private function notificationRead(string $id):?array
    {
        self::id($id);$this->authority('notification');$state=$this->unit()->run(function()use($id):?array{
            $this->ledger()->checkpoint();$this->authorize('notification','before');$state=$this->notificationState($id);if($state===null){return null;}
            $this->authorize('notification','read',$state['record']);$this->unchangedNotification($state);return $state;
        },null,function(?array $state):void{
            $this->authorize('notification','commit',$state===null?null:$state['record']);if($state!==null){$this->unchangedNotification($state);}
        },function(?array $state):void{
            $this->authorize('notification','complete',$state===null?null:$state['record']);if($state!==null){$this->unchangedNotification($state);}
        });
        return $state;
    }
    public function notification(string $id):?MailboxRecoveryDelivery {($this->stateGuard)();$state=$this->notificationRead($id);return $state===null?null:$state['delivery'];}
    public function notificationForDispatch(string $id):?DispatchNotice
    {($this->stateGuard)();
        $state=$this->notificationRead($id);if($state===null){return null;}$flow=$this->flow($state['flow_row']);return new DispatchNotice($state['delivery']->notice(),$state['delivery']->selector(),$flow['subject']);
    }
    /** Explicit worker factory; queue authority and current private-notice authority remain independently required. */
    public function dispatcher(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds=10000,int $transportMilliseconds=3000):Dispatcher
    {return ($this->dispatchFactory)($worker,$budgets,$templates,$transport,$workerAuthority,$budgetMilliseconds,$transportMilliseconds);}
    public function __debugInfo():array {return ['account_recovery'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize account services.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload trusted account service dependencies.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account recovery services are immutable.','configuration.immutable');}
}
