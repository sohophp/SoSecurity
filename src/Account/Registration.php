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
use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Isolated candidate. Public, management and delivery authority are independent. No SMTP or implicit login. */
final class Registration
{
    private $scope;
    private $maintenanceState;
    private $stateGuard;
    private $native;
    private $dependencies;
    private $dispatchFactory;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $integrityKeys,HmacKeys $outboxKeys,
        Repository $accounts,Notifications $notifications,PasswordHasher $hasher,PasswordPolicy $passwords,callable $authority,callable $budget,
        ?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null,?callable $deliveryGuard=null,?StateAccountConnection $state=null,?StateRequestGuard $requests=null)
    {
        $policy=$policy ?? new Policy();$clock=$clock ?? new SystemClock();if($requests!==null&&$state===null){throw new ConfigurationException('Native lifecycle admission requires an exact protected connection.','configuration.state_request');}$this->native=$requests===null?null:$state->requestHandler('registration',$requests);$this->maintenanceState=$state;$this->stateGuard=\SoSecurity\Support\SqlStateAccess::entryGuard($connection,$accounts,$site,$scope,$epoch,$clock,$policy,$state);$unit=new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        try{$same=$accounts->connection()===$connection;}catch(\Throwable $error){$same=false;}
        if(!$same){throw new ConfigurationException('Use exactly the host account transaction connection.','configuration.account_connection');}
        $ledger=new Ledger($unit,$site,$scope,$epoch,$integrityKeys,$policy);$this->scope=$scope;
        $queueAuthority=static function(string $action,string $phase,string $queueScope,string $producer,string $actor,array $metadata)use($authority,$scope):bool{
            return $action==='enqueue'&&$queueScope===$scope&&$producer==='account-registration'&&$actor==='account-system'&&self::queueGuard($authority,'outbox.enqueue',$phase,$scope);
        };
        $queueManagement=static function(string $action,string $phase,string $queueScope,string $producer,string $actor,array $metadata)use($managementGuard,$scope):bool{
            if($action!=='initialize'||$queueScope!==$scope||$producer!=='account-registration'||$actor!=='account-system'){return false;}
            // SqlOutbox.initialize() also returns false for an existing root. A denied preflight
            // must abort here, so Registration cannot mistake denial for successful setup.
            if($managementGuard===null||!self::queueGuard($managementGuard,'outbox.initialize',$phase,$scope)){throw new SecurityException('Current account management authority required.','account.denied');}return true;
        };
        $age=max($policy->lifetime('verify_registration'),$policy->lifetime('account_activated'));
        $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$queueAuthority,new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]),$clock,$queueManagement);
        $this->dispatchFactory=function(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds,int $transportMilliseconds)use($connection,$site,$scope,$epoch,$outboxKeys,$policy,$clock,$deliveryGuard):Dispatcher{
            if($deliveryGuard===null){throw new ConfigurationException('Explicit current notification authority is required for dispatch.','configuration.account_dispatch');}
            $producer='account-registration';$age=max($policy->lifetime('verify_registration'),$policy->lifetime('account_activated'));
            $authority=static function(string $action,string $phase,string $currentScope,string $currentProducer,string $actor,array $metadata)use($scope,$producer,$worker,$workerAuthority):bool{
                return $currentScope===$scope&&$currentProducer===$producer&&$actor===$worker&&in_array($action,['claim','claim_initial','claim_rejected','current_claim','acknowledge','fail'],true)&&$workerAuthority($action,$phase,$currentScope,$currentProducer,$actor,$metadata)===true;
            };
            $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$authority,new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]),$clock,null,$this->maintenanceState);
            return new Dispatcher($site,$scope,$worker,$queue,$this,$budgets,$templates,$transport,$clock,$budgetMilliseconds,$transportMilliseconds);
        };
        $this->dependencies=static function()use($unit,$ledger,$queue,$accounts,$notifications,$hasher,$passwords,$authority,$budget,$policy,$managementGuard,$deliveryGuard):array{return [$unit,$ledger,$queue,$accounts,$notifications,$hasher,$passwords,$authority,$budget,$policy,$managementGuard,$deliveryGuard];};
    }
    private function unit():SqlTransaction {return ($this->dependencies)()[0];}
    private function ledger():Ledger {return ($this->dependencies)()[1];}
    private function queue():SqlOutbox {return ($this->dependencies)()[2];}
    private function accounts():Repository {return ($this->dependencies)()[3];}
    private function notifications():Notifications {return ($this->dependencies)()[4];}
    private function hasher():PasswordHasher {return ($this->dependencies)()[5];}
    private function passwords():PasswordPolicy {return ($this->dependencies)()[6];}
    /** Arguments are local copies even when a trusted callback declares reference parameters. */
    private static function queueGuard(callable $callback,string $action,string $phase,string $scope):bool
    {
        $record=null;return $callback($action,$phase,$scope,$record)===true;
    }
    private function authority(string $action):callable
    {
        $dependencies=($this->dependencies)();
        if(in_array($action,['request','confirm','cancel'],true)){$callback=$dependencies[7];}
        elseif(in_array($action,['initialize','maintain','rotate'],true)){$callback=$dependencies[10];}
        elseif($action==='notification'){$callback=$dependencies[11];}
        else{throw new ConfigurationException('Unknown account authority purpose.','configuration.account_authority');}
        if($callback===null){throw new SecurityException('Current account operation authority required.','account.denied');}return $callback;
    }
    private function budgets():callable {return ($this->dependencies)()[8];}
    private function policy():Policy {return ($this->dependencies)()[9];}
    private static function id(string $id):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$id)){throw new ValidationException('Invalid registration proof.','account.proof');}}
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
    private function owner(string $subject):string {return hash('sha256',self::json(['SoSecurity.Account.Registration.Owner.1',$this->scope,$subject]));}
    private function cursor(string $subject):string {return hash('sha256','SoSecurity.Account.Registration.Cursor.1.'.$this->owner($subject));}
    private static function json(array $data):string {return json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    /** @return never */
    private static function corrupt():void {throw new StorageException('Registration state cannot be authenticated.','account.corrupt');}
    private function pointer(?array $row,string $subject):?string
    {
        if($row===null){return null;}$data=json_decode($row['payload'],true,3);
        if($row['kind']!=='budget'||$row['owner']!==$this->owner($subject)||!is_array($data)||array_keys($data)!==['format','subject','flow_id']||$data['format']!==1||$data['subject']!==$subject||!is_string($data['flow_id'])||!preg_match('/\A[a-f0-9]{64}\z/D',$data['flow_id'])||self::json($data)!==$row['payload']){self::corrupt();}return $data['flow_id'];
    }
    private function flow(array $row):array
    {
        $data=json_decode($row['payload'],true,3);$fields=['format','purpose','subject','account_version','address_version','address_tag','token_digest','issued_at','valid_until','attempts','resends','state','notice_id','resend_at'];
        if($row['kind']!=='register'||!is_array($data)||array_keys($data)!==$fields||$data['format']!==1||$data['purpose']!=='register'){self::corrupt();}
        foreach(['subject','account_version','address_version'] as $field){if(!is_string($data[$field])||$data[$field]===''||strlen($data[$field])>256||preg_match('/[\x00-\x1f\x7f]/',$data[$field])||preg_match('//u',$data[$field])!==1){self::corrupt();}}
        foreach(['address_tag','token_digest','notice_id'] as $field){if(!is_string($data[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$data[$field])){self::corrupt();}}
        foreach(['issued_at','valid_until','attempts','resends','resend_at'] as $field){if(!is_int($data[$field])||$data[$field]<0){self::corrupt();}}
        if($data['issued_at']<$row['created_at']||$data['valid_until']<=$data['issued_at']||$data['valid_until']-$data['issued_at']>$this->policy()->lifetime('verify_registration')||$data['attempts']>$this->policy()->maximumAttempts()||$data['resends']>$this->policy()->maximumResends()||$data['resend_at']<$data['issued_at']||$data['resend_at']>$data['valid_until']||!in_array($data['state'],['pending','consumed','locked','cancelled'],true)||$row['owner']!==$this->owner($data['subject'])||self::json($data)!==$row['payload']){self::corrupt();}return $data;
    }
    private function binding(AccountRecord $record,string $token):string
    {
        return hash_hmac('sha256',self::json([$this->scope,$record->account()->subject(),$record->account()->version(),$record->addressVersion(),$record->address()->value()]),hex2bin($token));
    }
    private function matches(array $flow,AccountRecord $record,string $token):bool
    {
        return $record->status()==='pending'&&!$record->verified()&&!$record->account()->enabled()&&$flow['account_version']===$record->account()->version()&&$flow['address_version']===$record->addressVersion()&&hash_equals($flow['token_digest'],hash('sha256',$token))&&hash_equals($flow['address_tag'],$this->binding($record,$token));
    }
    private function saveFlow(array $row,array $flow,int $retireAt):void {$this->ledger()->put($row['record_id'],$row['owner'],'register',self::json($flow),$retireAt,$row['revision']);}
    private function notice(string $flowId,AccountRecord $record,string $type,string $token,int $until):string
    {
        $id=bin2hex(random_bytes(32));$now=$this->unit()->now();$notice=new Notice($this->scope,$id,$type,$record->address(),$token,$now,$until);$envelope=$this->notifications()->seal($notice);
        $payload=self::json(['format'=>1,'type'=>$type,'issued_at'=>$now,'valid_until'=>$until,'envelope'=>$envelope]);
        $this->ledger()->put($id,$flowId,'notice',$payload,$until);
        $this->queue()->enqueue(new Message($this->scope,'account-registration',Message::identifier('account-notice-'.$id,$now),'mail','account.notice',$id,$id),'account-system');return $id;
    }
    public function initialize():void
    {($this->stateGuard)();
        $this->authority('initialize');
        $this->queue()->initialize($this->scope,'account-registration','account-system');
        $this->unit()->run(function():void{$this->authorize('initialize','before');$this->ledger()->initialize();},null,function():void{$this->authorize('initialize','commit');});
    }
    /** Uniform accepted outcome; no selectors, subjects or token secrets are returned. Source is supplied by trusted host routing. */
    public function request(string $value,string $source):void
    {
        if($this->native===null){$this->requestInternal($value,$source);return;}
        ($this->native)('request',function()use($value,$source):array{
            $address=new Address($value,$this->policy()->allowsSmtpUtf8());StateLifecycleInput::source($source);$budgetId=bin2hex(random_bytes(16));$this->charge('request','public',$source,$address,null,$budgetId);return [$budgetId];
        },function(array $admission)use($value,$source):void{$this->requestInternal($value,$source,$admission[0]);});
    }
    private function requestInternal(string $value,string $source,?string $admission=null):void
    {($this->stateGuard)();
        $address=new Address($value,$this->policy()->allowsSmtpUtf8());self::source($source);$budgetId=$admission??bin2hex(random_bytes(16));if($admission===null){$this->charge('request','public',$source,$address,null,$budgetId);}
        $this->unit()->run(function()use($address,$source,$budgetId):?AccountRecord{
            $this->authorize('request','before');$this->ledger()->capacity(1);$record=$this->byAddress($address);
            if($record!==null){$this->charge('request','subject',$source,$address,$record->account()->subject(),$budgetId);if($record->status()!=='pending'||$record->verified()){return null;}}
            $this->ledger()->capacity($record===null?3:1);
            if($record===null){$record=$this->host('createPending',[$this->scope,bin2hex(random_bytes(16)),$address]);if($record===null){return null;}$fresh=$this->byAddress($address);if($fresh===null||$fresh->fingerprint()!==$record->fingerprint()||$record->status()!=='pending'||$record->verified()||$record->account()->enabled()){self::corrupt();}$this->charge('request','subject',$source,$address,$record->account()->subject(),$budgetId);}
            $subject=$record->account()->subject();$cursor=$this->ledger()->read($this->cursor($subject));$flowId=$this->pointer($cursor,$subject);$row=$flowId===null?null:$this->ledger()->read($flowId);$now=$this->unit()->now();
            if($flowId!==null&&$row===null){self::corrupt();}$flow=$row===null?null:$this->flow($row);
            if($flow!==null&&$flow['valid_until']>$now){
                if(!in_array($flow['state'],['pending','cancelled'],true)||$flow['resend_at']>$now||$flow['resends']>=$this->policy()->maximumResends()||$flow['account_version']!==$record->account()->version()||$flow['address_version']!==$record->addressVersion()){return null;}
                $until=$flow['valid_until'];$resends=$flow['resends']+1;$revision=$row['revision'];
                if($flow['state']==='cancelled'){$this->ledger()->capacity(2);$flowId=bin2hex(random_bytes(32));$row=null;$revision=null;}
            }else{$this->ledger()->capacity($cursor===null?3:2);$flowId=bin2hex(random_bytes(32));$row=null;$until=$now+$this->policy()->lifetime('verify_registration');$resends=0;$revision=null;}
            $token=bin2hex(random_bytes(32));$noticeId=$this->notice($flowId,$record,'verify_registration',$token,$until);
            $flow=['format'=>1,'purpose'=>'register','subject'=>$subject,'account_version'=>$record->account()->version(),'address_version'=>$record->addressVersion(),'address_tag'=>$this->binding($record,$token),'token_digest'=>hash('sha256',$token),'issued_at'=>$now,'valid_until'=>$until,'attempts'=>0,'resends'=>$resends,'state'=>'pending','notice_id'=>$noticeId,'resend_at'=>min($until,$now+$this->policy()->resendSeconds())];
            $this->ledger()->put($flowId,$this->owner($subject),'register',self::json($flow),$until+$this->policy()->lifetime('account_activated'),$revision);
            if($row===null){$this->ledger()->put($this->cursor($subject),$this->owner($subject),'budget',self::json(['format'=>1,'subject'=>$subject,'flow_id'=>$flowId]),$until+$this->policy()->lifetime('account_activated'),$cursor===null?null:$cursor['revision']);}
            $this->authorize('request','after',$record);return $record;
        },null,function(?AccountRecord $changed)use($source,$budgetId):void{
            if($changed===null){return;}$fresh=$this->current($changed->account()->subject());if($fresh===null||$fresh->fingerprint()!==$changed->fingerprint()){self::corrupt();}
            $this->authorize('request','commit',$fresh);$this->charge('request','final',$source,$fresh->address(),$fresh->account()->subject(),$budgetId);
            $current=$this->current($fresh->account()->subject());if($current===null||$current->fingerprint()!==$fresh->fingerprint()){self::corrupt();}
        });
    }
    /** A failed proof's attempt is committed separately; policy checks and hashing never hold the SQL transaction. */
    public function confirm(string $selector,string $token,string $password,string $source):bool
    {
        if($this->native===null){return $this->confirmInternal($selector,$token,$password,$source);}
        return ($this->native)('confirm',function()use($selector,$token,$password,$source):array{
            StateLifecycleInput::id($selector);StateLifecycleInput::id($token);StateLifecycleInput::source($source);StateLifecycleInput::password($password,$this->hasher()->maximumBytes());$budgetId=bin2hex(random_bytes(16));$this->charge('confirm','public',$source,null,null,$budgetId);return [$budgetId];
        },function(array $admission)use($selector,$token,$password,$source):bool{return $this->confirmInternal($selector,$token,$password,$source,$admission[0]);});
    }
    private function confirmInternal(string $selector,string $token,string $password,string $source,?string $admission=null):bool
    {($this->stateGuard)();
        self::id($selector);self::id($token);self::source($source);
        if($password===''||strlen($password)>$this->hasher()->maximumBytes()||strpos($password,"\0")!==false){throw new ValidationException('Password exceeds its encoding/length budget.','password.encoding');}
        $budgetId=$admission??bin2hex(random_bytes(16));if($admission===null){$this->charge('confirm','public',$source,null,null,$budgetId);}$proof=$this->unit()->run(function()use($selector,$token,$source,$budgetId):?array{
            $this->authorize('confirm','before');$row=$this->ledger()->read($selector);if($row===null||$row['kind']!=='register'){return null;}$flow=$this->flow($row);$now=$this->unit()->now();
            if($flow['state']!=='pending'||$flow['valid_until']<=$now||$flow['attempts']>=$this->policy()->maximumAttempts()){return null;}
            $record=$this->current($flow['subject']);if($record===null){return null;}$cursor=$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject']);if($cursor!==$selector){return null;}
            $this->charge('confirm','subject',$source,$record->address(),$flow['subject'],$budgetId);$this->authorize('confirm','proof',$record);$valid=$this->matches($flow,$record,$token);++$flow['attempts'];
            if(!$valid&&$flow['attempts']===$this->policy()->maximumAttempts()){$flow['state']='locked';}$this->saveFlow($row,$flow,$row['retire_at']);return $valid?['record'=>$record,'expires'=>$flow['valid_until']]:null;
        });
        if($proof===null){return false;}
        if($this->passwords()->errors($password)){return false;}$hash=$this->hasher()->hash($password);
        try{return $this->unit()->run(function()use($selector,$token,$proof,$hash,$source,$budgetId):?AccountRecord{
            $row=$this->ledger()->read($selector);if($row===null){self::corrupt();}$flow=$this->flow($row);$record=$this->current($flow['subject']);
            if($flow['state']!=='pending'||$flow['valid_until']<=$this->unit()->now()||$record===null||$record->fingerprint()!==$proof['record']->fingerprint()||!$this->matches($flow,$record,$token)||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$selector){return null;}
            $this->authorize('confirm','activate',$record);$this->charge('confirm','final',$source,$record->address(),$flow['subject'],$budgetId);$this->ledger()->capacity(1);
            $active=$this->host('activate',[$record,$hash]);if($active===null){throw new StorageException('Account activation changed concurrently.','account.conflict');}
            if($active->account()->subject()!==$record->account()->subject()||!$active->address()->equals($record->address())||$active->addressVersion()!==$record->addressVersion()||$active->status()!=='active'||!$active->verified()||!$active->account()->enabled()||$active->account()->version()===$record->account()->version()||$active->account()->roles()!==$record->account()->roles()||$active->account()->mfaRequired()!==$record->account()->mfaRequired()){self::corrupt();}
            $fresh=$this->current($flow['subject']);$addressOwner=$this->byAddress($active->address());if($fresh===null||$addressOwner===null||$fresh->fingerprint()!==$active->fingerprint()||$addressOwner->fingerprint()!==$active->fingerprint()){self::corrupt();}
            $until=$this->unit()->now()+$this->policy()->lifetime('account_activated');$flow['state']='consumed';$flow['account_version']=$active->account()->version();$flow['notice_id']=$this->notice($selector,$active,'account_activated','',$until);$this->saveFlow($row,$flow,max($row['retire_at'],$until));return $active;
        },null,function(?AccountRecord $committed)use($selector):void{
            if($committed===null){return;}$row=$this->ledger()->read($selector);if($row===null){self::corrupt();}$flow=$this->flow($row);if($this->unit()->now()>=$flow['valid_until']){throw new StorageException('Registration proof expired before commit.','account.expired');}$fresh=$this->current($committed->account()->subject());if($fresh===null||$fresh->fingerprint()!==$committed->fingerprint()){self::corrupt();}$this->authorize('confirm','commit',$fresh);
        },function(?AccountRecord $committed)use($proof):void{
            if($committed===null){return;}if($this->unit()->now()>=$proof['expires']){throw new StorageException('Registration completion crossed its proof deadline.','account.completion_unknown');}$fresh=$this->current($committed->account()->subject());if($fresh===null||$fresh->fingerprint()!==$committed->fingerprint()){self::corrupt();}$this->authorize('confirm','complete',$fresh);
        })!==null;}catch(\Throwable $error){if($this->unit()->committed()){throw new StorageException('Registration committed but completion could not be confirmed.','account.completion_unknown');}throw $error;}
    }
    /** Consume this registration proof to cancel, without changing the host account or granting a session. */
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
                $this->authorize('cancel','before');$row=$this->ledger()->read($selector);if($row===null||$row['kind']!=='register'){return null;}$flow=$this->flow($row);$now=$this->unit()->now();
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
        if($row['kind']!=='notice'||!is_array($data)||array_keys($data)!==['format','type','issued_at','valid_until','envelope']||$data['format']!==1||!in_array($data['type'],['verify_registration','account_activated'],true)||!is_int($data['issued_at'])||!is_int($data['valid_until'])||!is_string($data['envelope'])||strlen($data['envelope'])>8192||self::json($data)!==$row['payload']){self::corrupt();}return $data;
    }
    /** Parse only known registration records; future workflow formats must not be silently adopted or deleted. */
    private function maintenanceData(array $row):array
    {
        if($row['kind']==='register'){return $this->flow($row);}
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
        return $this->maintenanceState->maintenance('registration',$action,$policy,$permission,$limit,$after,function()use($guard,$action,$scope):bool{
            // Host admission is outside SQL observation units; the witness checks the full source before effects.
            $phase='admission';$record=null;try{return $guard($action,$phase,$scope,$record)===true;}catch(\Throwable $error){throw new \SoSecurity\Exception\DependencyException('Account maintenance admission unavailable.','account.authority');}
        },function()use($action,$limit,$after):array{return $this->$action($limit,$after);});
    }
    public function maintain(int $limit=20,string $after=''):array
    {($this->stateGuard)();
        self::pageInput($limit,$after);$this->authority('maintain');$state=$this->unit()->run(function()use($limit,$after):array{
            $this->authorize('maintain','before');$headers=$this->ledger()->page($limit,$after);$remove=[];$expected=[];$now=$this->unit()->now();
            foreach($headers as $header){
                if(isset($remove[$header['record_id']])){continue;}$row=$this->ledger()->read($header['record_id']);if($row===null){self::corrupt();}$data=$this->maintenanceData($row);if($row['retire_at']>$now){$expected[$row['record_id']]=$row;continue;}
                if($row['kind']==='register'){
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
            $this->authorize('maintain','commit');foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){throw new StorageException('Retained registration body changed before commit.','account.changed');}}
            if($this->ledger()->checkpoint()!==$state['checkpoint']){throw new StorageException('Registration maintenance changed before commit.','account.changed');}
        },function(array $state):void{
            try{$this->authorize('maintain','complete');}
            catch(\Throwable $error){throw new StorageException('Account maintenance completion authority is uncertain; committed changes are not rolled back.','account.completion_unknown');}
        });
        return $state['result'];
    }
    /** Bounded reseal/reencryption. Pause old writers before retiring any keys; done is a page boundary only. */
    public function rotate(int $limit=20,string $after=''):array
    {($this->stateGuard)();
        self::pageInput($limit,$after);$this->authority('rotate');$state=$this->unit()->run(function()use($limit,$after):array{
            $this->authorize('rotate','before');$headers=$this->ledger()->page($limit,$after);$root=$this->ledger()->rotateRoot();$resealed=0;$reencrypted=0;$expected=[];
            foreach($headers as $header){
                $row=$this->ledger()->read($header['record_id']);if($row===null){self::corrupt();}$data=$this->maintenanceData($row);$payload=$row['payload'];
                if($row['kind']==='notice'&&$data['key_id']!==$this->notifications()->currentId()){
                    unset($data['key_id']);$data['envelope']=$this->notifications()->reencrypt($data['envelope'],$this->scope,$row['record_id'],$data['type']);$payload=self::json($data);++$reencrypted;
                }
                if($payload!==$row['payload']||$row['seal_key']!==$this->ledger()->currentKeyId()){$row=$this->ledger()->put($row['record_id'],$row['owner'],$row['kind'],$payload,$row['retire_at'],$row['revision']);++$resealed;}$expected[$row['record_id']]=$row;
            }
            return ['result'=>self::progress($headers,$limit,['resealed'=>$resealed,'reencrypted'=>$reencrypted,'root_rotated'=>$root]),'checkpoint'=>$this->ledger()->checkpoint(),'rows'=>$expected];
        },null,function(array $state):void{
            $this->authorize('rotate','commit');foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){throw new StorageException('Registration rotation body changed before commit.','account.changed');}}
            if($this->ledger()->checkpoint()!==$state['checkpoint']){throw new StorageException('Registration rotation state changed before commit.','account.changed');}
        },function(array $state):void{
            try{$this->authorize('rotate','complete');}
            catch(\Throwable $error){throw new StorageException('Account maintenance completion authority is uncertain; committed changes are not rolled back.','account.completion_unknown');}
        });
        return $state['result'];
    }
    /** Private authenticated snapshot. It never invokes or substitutes for worker authority. */
    private function notificationState(string $id):?array
    {
        $row=$this->ledger()->read($id);if($row===null){return null;}$data=$this->noticeData($row);
        if($data['valid_until']<=$this->unit()->now()){return null;}$flowRow=$this->ledger()->read($row['owner']);if($flowRow===null){self::corrupt();}$flow=$this->flow($flowRow);$record=$this->current($flow['subject']);
        if($record===null||$flow['notice_id']!==$id||$this->pointer($this->ledger()->read($this->cursor($flow['subject'])),$flow['subject'])!==$row['owner']){return null;}
        $notice=$this->notifications()->open($data['envelope'],$this->scope,$id,$data['type']);
        if($notice->issuedAt()!==$data['issued_at']||$notice->expiresAt()!==$data['valid_until']){self::corrupt();}
        if(!$notice->recipient()->equals($record->address())){return null;}
        if($data['type']==='verify_registration'){
            if($flow['state']!=='pending'||$flow['valid_until']<=$this->unit()->now()||!$this->matches($flow,$record,$notice->token())){return null;}
        }elseif($flow['state']!=='consumed'||$record->status()!=='active'||!$record->verified()||$record->account()->version()!==$flow['account_version']||$record->addressVersion()!==$flow['address_version']){return null;}
        return ['notice_row'=>$row,'flow_row'=>$flowRow,'record'=>$record,'delivery'=>new Delivery($notice,$data['type']==='verify_registration'?$row['owner']:'')];
    }
    private function unchangedNotification(array $state):void
    {
        $fresh=$this->notificationState($state['delivery']->notice()->id());
        if($fresh===null||$fresh['notice_row']!==$state['notice_row']||$fresh['flow_row']!==$state['flow_row']||$fresh['record']->fingerprint()!==$state['record']->fingerprint()){
            throw new SecurityException('Account notification changed during delivery authorization.','account.notification_changed');
        }
        if($state['delivery']->notice()->expiresAt()<=$this->unit()->now()){throw new SecurityException('Account notification expired during completion.','account.expired');}
    }
    /** Trusted worker read only. This authorization does not claim SMTP success or validate an Outbox lease. */
    private function notificationRead(string $id):?array
    {
        self::id($id);$this->authority('notification');$state=$this->unit()->run(function()use($id):?array{
            $this->authorize('notification','before');$state=$this->notificationState($id);if($state===null){return null;}
            $this->authorize('notification','read',$state['record']);$this->unchangedNotification($state);return $state;
        },null,function(?array $state):void{
            $this->authorize('notification','commit',$state===null?null:$state['record']);if($state!==null){$this->unchangedNotification($state);}
        },function(?array $state):void{
            $this->authorize('notification','complete',$state===null?null:$state['record']);if($state!==null){$this->unchangedNotification($state);}
        });
        return $state;
    }
    public function notification(string $id):?Delivery {($this->stateGuard)();$state=$this->notificationRead($id);return $state===null?null:$state['delivery'];}
    public function notificationForDispatch(string $id):?DispatchNotice
    {($this->stateGuard)();
        $state=$this->notificationRead($id);if($state===null){return null;}$flow=$this->flow($state['flow_row']);return new DispatchNotice($state['delivery']->notice(),$state['delivery']->selector(),$flow['subject']);
    }
    /** Explicit worker factory; queue authority and current private-notice authority remain independently required. */
    public function dispatcher(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds=10000,int $transportMilliseconds=3000):Dispatcher
    {return ($this->dispatchFactory)($worker,$budgets,$templates,$transport,$workerAuthority,$budgetMilliseconds,$transportMilliseconds);}
    public function __debugInfo():array {return ['account_registration'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize account services.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload trusted account service dependencies.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account registration services are immutable.','configuration.immutable');}
}
