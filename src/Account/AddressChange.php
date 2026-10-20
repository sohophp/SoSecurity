<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\VerifiedSession;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Operation\Grants;
use SoSecurity\Operation\Intent;
use SoSecurity\Operation\Permit;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy as OutboxPolicy;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Isolated candidate. Two mailbox proofs plus a new consumed operation grant precede a conditional address update. */
final class AddressChange
{
    private $scope;
    private $context;
    private $dependencies;
    private $dispatchFactory;
    private $observed=0;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,HmacKeys $outboxKeys,
        IdentityRepository $accounts,Notifications $notifications,SessionRegistry $sessions,Grants $grants,callable $requestGuard,callable $budget,
        ?Policy $policy=null,?Clock $clock=null,?callable $managementGuard=null,?callable $deliveryGuard=null)
    {
        Guard::label($site);if(preg_match('//u',$site)!==1){throw new ConfigurationException('Use a UTF-8 site label.','configuration.account');}
        $policy=$policy ?? new Policy();$clock=$clock ?? new SystemClock();$unit=new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        try{$same=$accounts->connection()===$connection;}catch(\Throwable $error){$same=false;}
        if(!$same){throw new ConfigurationException('Use the same account transaction PDO.','configuration.account_connection');}
        $this->scope=$scope;$context=hash('sha256',self::json(['SoSecurity.Account.AddressChange.1',$site]));$this->context=$context;
        $ledger=new Ledger($unit,$context,$scope,$epoch,$keys,$policy);
        $producerGuard=static function(string $action,string $phase,string $queueScope,string $producer,string $actor)use($requestGuard,$scope):bool{
            $record=null;$address=null;$command='outbox.enqueue';return $action==='enqueue'&&$queueScope===$scope&&$producer==='account-address-change'&&$actor==='account-system'&&$requestGuard($command,$phase,$queueScope,$record,$address)===true;
        };
        $manager=static function(string $action,string $phase,string $queueScope,string $producer,string $actor)use($managementGuard,$scope):bool{
            if($action!=='initialize'||$queueScope!==$scope||$producer!=='account-address-change'||$actor!=='account-system'){return false;}
            $record=null;$address=null;$command='outbox.initialize';
            if($managementGuard===null||$managementGuard($command,$phase,$queueScope,$record,$address)!==true){throw new SecurityException('Account management authority required.','account.denied');}return true;
        };
        $age=max($policy->lifetime('verify_address_new'),$policy->lifetime('address_changed'));
        $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$producerGuard,new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]),$clock,$manager);
        $this->dispatchFactory=function(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds,int $transportMilliseconds)use($connection,$site,$scope,$epoch,$outboxKeys,$policy,$clock,$deliveryGuard):Dispatcher{
            if($deliveryGuard===null){throw new ConfigurationException('Explicit current notification authority is required for dispatch.','configuration.account_dispatch');}
            $producer='account-address-change';$age=max($policy->lifetime('verify_address_new'),$policy->lifetime('address_changed'));
            $authority=static function(string $action,string $phase,string $currentScope,string $currentProducer,string $actor,array $metadata)use($scope,$producer,$worker,$workerAuthority):bool{
                return $currentScope===$scope&&$currentProducer===$producer&&$actor===$worker&&in_array($action,['claim','current_claim','acknowledge','fail'],true)&&$workerAuthority($action,$phase,$currentScope,$currentProducer,$actor,$metadata)===true;
            };
            $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$authority,new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]),$clock);
            return new Dispatcher($site,$scope,$worker,$queue,$this,$budgets,$templates,$transport,$clock,$budgetMilliseconds,$transportMilliseconds);
        };
        $this->dependencies=static function()use($unit,$ledger,$accounts,$notifications,$sessions,$grants,$keys,$queue,$policy,$requestGuard,$budget,$managementGuard,$deliveryGuard,$clock,$epoch):array{
            return [$unit,$ledger,$accounts,$notifications,$sessions,$grants,$keys,$queue,$policy,$requestGuard,$budget,$managementGuard,$deliveryGuard,$clock,$epoch];
        };
    }
    private function unit():SqlTransaction {return ($this->dependencies)()[0];}
    private function ledger():Ledger {return ($this->dependencies)()[1];}
    private function accounts():IdentityRepository {return ($this->dependencies)()[2];}
    private function notices():Notifications {return ($this->dependencies)()[3];}
    private function sessions():SessionRegistry {return ($this->dependencies)()[4];}
    private function grants():Grants {return ($this->dependencies)()[5];}
    private function keys():HmacKeys {return ($this->dependencies)()[6];}
    private function queue():SqlOutbox {return ($this->dependencies)()[7];}
    private function policy():Policy {return ($this->dependencies)()[8];}
    private static function json(array $data):string {return json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    private static function id(string $id):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$id)){throw new ValidationException('Invalid address-change reference.','account.proof');}}
    private static function label(string $value):void {Guard::label($value);if(preg_match('//u',$value)!==1){throw new ValidationException('Use a bounded UTF-8 account label.','account.input');}}
    private function now():int
    {
        try{$now=(($this->dependencies)()[13])->now();}catch(\Throwable $error){throw new StorageException('Account clock unavailable.','account.clock');}
        if($now<0||$now<$this->observed||$now>PHP_INT_MAX-1209601){throw new StorageException('Invalid account clock.','account.clock');}$this->observed=$now;return $now;
    }
    private function guard(string $action):callable
    {
        $d=($this->dependencies)();
        if(in_array($action,['initialize','maintain','rotate'],true)){$guard=$d[11];}
        elseif($action==='notification'){$guard=$d[12];}
        elseif(in_array($action,['request','confirm','cancel','complete'],true)){$guard=$d[9];}
        else{throw new ConfigurationException('Unknown account guard purpose.','configuration.account');}
        if($guard===null){throw new SecurityException('Account authority required.','account.denied');}return $guard;
    }
    private function authorize(string $action,string $phase,?AccountRecord $record=null,?Address $address=null):void
    {
        if($this->unit()->invoke($this->guard($action),[$action,$phase,$this->scope,$record,$address],'account.authority')!==true){throw new SecurityException('Account authority refused.','account.denied');}
    }
    private function charge(string $action,string $phase,string $source,?Address $address=null,?string $subject=null,string $operation=''):void
    {
        $callback=($this->dependencies)()[10];$args=[$action,$phase,$this->scope,$source,$address,$subject,$operation];
        if($phase==='public'){try{$refs=[];foreach($args as &$value){$refs[]=&$value;}unset($value);$allowed=call_user_func_array($callback,$refs);}catch(\Throwable $error){throw new DependencyException('Account request budget unavailable.','account.budget');}}
        else{$allowed=$this->unit()->invoke($callback,$args,'account.budget');}
        if($allowed!==true){throw new SecurityException('Account request budget refused.','account.budget');}
    }
    /** @return never */
    private static function corrupt():void {throw new StorageException('Address-change state cannot be authenticated.','account.corrupt');}
    private function facts(string $subject):?array
    {
        $record=$this->unit()->invoke([$this->accounts(),'find'],[$this->scope,$subject],'account.repository');
        if($record===null){return null;}
        if(!$record instanceof AccountRecord||$record->account()->scope()!==$this->scope||$record->account()->subject()!==$subject){self::corrupt();}
        if($record->status()!=='active'||!$record->verified()||!$record->account()->enabled()){return null;}
        $identity=$this->unit()->invoke([$this->accounts(),'identity'],[$record],'account.repository');
        if(!$identity instanceof Account||!$identity->enabled()||$identity->scope()!==$this->scope||$identity->subject()!==$subject||$identity->roles()!==$record->account()->roles()||$identity->mfaRequired()!==$record->account()->mfaRequired()){self::corrupt();}
        return ['record'=>$record,'identity'=>$identity];
    }
    private function unchangedFacts(array $facts):array
    {
        $fresh=$this->facts($facts['record']->account()->subject());
        if($fresh===null||$fresh['record']->fingerprint()!==$facts['record']->fingerprint()||$fresh['identity']->fingerprint()!==$facts['identity']->fingerprint()){throw new SecurityException('Current account changed.','account.changed');}return $fresh;
    }
    private function session(string $subject,string $token,Deadline $deadline,bool $strong):VerifiedSession
    {
        if(SessionRegistry::reference($token)===null){throw new SecurityException('Current session required.','account.authentication');}
        $deadline->check('account.timeout');try{$session=$this->sessions()->verify($this->scope,$subject,$token,1);}catch(\Throwable $error){throw new DependencyException('Current authentication authority unavailable.','account.authentication_unavailable');}$deadline->check('account.timeout');$now=$this->now();
        if($session===null||$session->expiresAt()<=$now||($strong&&(!$session->recent(min(300,$this->grants()->policy()->maximumAge()),$now,$session->account()->mfaRequired()?2:1)||!in_array($session->method(),['password','totp','webauthn'],true)))){throw new SecurityException('Recent approved authentication required.','account.authentication');}
        if($session->account()->mfaRequired()&&!in_array($session->method(),['totp','webauthn'],true)){throw new SecurityException('Current MFA required.','account.authentication');}return $session;
    }
    private function owner(string $subject):string {return hash('sha256',self::json([$this->context,$this->scope,$subject]));}
    private function cursor(string $subject):string {return hash('sha256','SoSecurity.Account.AddressChange.Cursor.1.'.$this->owner($subject));}
    private function pointer(string $subject):array
    {
        $row=$this->ledger()->read($this->cursor($subject));if($row===null){return [null,null];}$data=json_decode($row['payload'],true,3);
        if($row['kind']!=='budget'||$row['owner']!==$this->owner($subject)||!is_array($data)||array_keys($data)!==['format','subject','flow_id']||$data['format']!==1||$data['subject']!==$subject||!is_string($data['flow_id'])||!preg_match('/\A[a-f0-9]{64}\z/D',$data['flow_id'])||self::json($data)!==$row['payload']){self::corrupt();}return [$row,$data['flow_id']];
    }
    private function flow(array $row):array
    {
        $f=json_decode($row['payload'],true,6);
        if($row['kind']!=='change'||!is_array($f)||array_keys($f)!==['format','purpose','subject','account','identity','issued_at','valid_until','resend_at','resends','state','proofs','completed_account','completed_identity','success']||$f['format']!==1||$f['purpose']!=='address_change'){self::corrupt();}
        if(!is_string($f['subject'])||$f['subject']===''||strlen($f['subject'])>256||preg_match('/[\x00-\x1f\x7f]/',$f['subject'])||preg_match('//u',$f['subject'])!==1||$row['owner']!==$this->owner($f['subject'])){self::corrupt();}
        foreach(['account','identity'] as $key){if(!is_string($f[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$f[$key])){self::corrupt();}}
        foreach(['issued_at','valid_until','resend_at','resends'] as $key){if(!is_int($f[$key])||$f[$key]<0){self::corrupt();}}
        if($f['issued_at']<$row['created_at']||$f['valid_until']<=$f['issued_at']||$f['valid_until']-$f['issued_at']>$this->policy()->lifetime('verify_address_new')||$f['resend_at']<$f['issued_at']||$f['resend_at']>$f['valid_until']||$f['resends']>$this->policy()->maximumResends()||!in_array($f['state'],['pending','ready','consumed','cancelled','locked'],true)||!is_array($f['proofs'])||array_keys($f['proofs'])!==['old','new','cancel']){self::corrupt();}
        $ids=[];foreach($f['proofs'] as $side=>$proof){
            if(!is_array($proof)||array_keys($proof)!==['digest','address_tag','notice_id','attempts','confirmed']||!is_int($proof['attempts'])||$proof['attempts']<0||$proof['attempts']>$this->policy()->maximumAttempts()||!is_bool($proof['confirmed'])||($side==='cancel'&&$proof['confirmed'])){self::corrupt();}
            foreach(['digest','address_tag','notice_id'] as $key){if(!is_string($proof[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$proof[$key])){self::corrupt();}}$ids[]=$proof['notice_id'];
        }
        if(count(array_unique($ids))!==3||$row['retire_at']<$f['valid_until']||(in_array($f['state'],['ready','consumed'],true)&&(!$f['proofs']['old']['confirmed']||!$f['proofs']['new']['confirmed']))||($f['state']==='pending'&&$f['proofs']['old']['confirmed']&&$f['proofs']['new']['confirmed'])||!is_array($f['success'])||array_keys($f['success'])!==['old','new']){self::corrupt();}
        foreach($f['proofs'] as $proof){if($proof['confirmed']&&$proof['attempts']<1){self::corrupt();}}
        foreach(['completed_account','completed_identity'] as $key){if(!is_string($f[$key])||($f['state']==='consumed'?!preg_match('/\A[a-f0-9]{64}\z/D',$f[$key]):$f[$key]!=='')){self::corrupt();}}
        foreach($f['success'] as $entry){
            if($f['state']!=='consumed'){if($entry!==null){self::corrupt();}continue;}
            if(!is_array($entry)||array_keys($entry)!==['notice_id','key_id','recipient_tag']||!is_string($entry['key_id'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$entry['key_id'])){self::corrupt();}
            foreach(['notice_id','recipient_tag'] as $key){if(!is_string($entry[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$entry[$key])){self::corrupt();}}
        }
        if($f['state']==='consumed'&&($f['completed_account']===$f['account']||$f['completed_identity']===$f['identity']||$f['success']['old']['notice_id']===$f['success']['new']['notice_id'])){self::corrupt();}
        if(self::json($f)!==$row['payload']){self::corrupt();}return $f;
    }
    private function bound(array $flow,array $facts):bool {return $flow['account']===$facts['record']->fingerprint()&&$flow['identity']===$facts['identity']->fingerprint();}
    private function unchangedFlow(array $row):void
    {
        if($this->ledger()->read($row['record_id'])!==$row){throw new SecurityException('Address proof changed.','account.changed');}
        $flow=$this->flow($row);list(,$current)=$this->pointer($flow['subject']);if($current!==$row['record_id']){throw new SecurityException('A newer address request superseded this proof.','account.changed');}
    }
    private function tag(array $flow,string $side,Address $address,string $token):string {return hash_hmac('sha256',self::json([$this->context,$this->scope,$flow['subject'],$flow['account'],$flow['identity'],$side,$address->value()]),hex2bin($token));}
    private function type(string $side):string {return ['old'=>'verify_address_old','new'=>'verify_address_new','cancel'=>'cancel_change'][$side];}
    private function noticeRow(string $id,?array $row=null):array
    {
        $row=$row ?? $this->ledger()->read($id);if($row===null||$row['kind']!=='notice'){self::corrupt();}$data=json_decode($row['payload'],true,3);
        if(!is_array($data)||array_keys($data)!==['format','type','issued_at','valid_until','envelope']||$data['format']!==1||!is_string($data['type'])||!in_array($data['type'],['verify_address_old','verify_address_new','cancel_change','address_changed'],true)||!is_int($data['issued_at'])||!is_int($data['valid_until'])||!is_string($data['envelope'])||strlen($data['envelope'])>8192||self::json($data)!==$row['payload']){self::corrupt();}
        if($data['issued_at']<$row['created_at']||$data['valid_until']<=$data['issued_at']||$data['valid_until']-$data['issued_at']>$this->policy()->lifetime($data['type'])||$row['retire_at']<$data['valid_until']){self::corrupt();}return ['row'=>$row,'data'=>$data];
    }
    private function openNotice(array $entry):Notice
    {
        $row=$entry['row'];$d=$entry['data'];$notice=$this->notices()->open($d['envelope'],$this->scope,$row['record_id'],$d['type']);
        if($notice->issuedAt()!==$d['issued_at']||$notice->expiresAt()!==$d['valid_until']||$row['retire_at']<$d['valid_until']){self::corrupt();}return $notice;
    }
    private function target(array $flow,string $selector,string $side):Notice
    {
        $entry=$this->noticeRow($flow['proofs'][$side]['notice_id']);if($entry['row']['owner']!==$selector||$entry['data']['type']!==$this->type($side)||$entry['data']['valid_until']!==$flow['valid_until']){self::corrupt();}
        $notice=$this->openNotice($entry);$proof=$flow['proofs'][$side];
        if(!hash_equals($proof['digest'],hash('sha256',$side.'.'.$notice->token()))||!hash_equals($proof['address_tag'],$this->tag($flow,$side,$notice->recipient(),$notice->token()))){self::corrupt();}return $notice;
    }
    private function intent(array $facts,Address $address,string $selector=''):Intent
    {
        $context=bin2hex($this->keys()->sign(self::json(['SoSecurity.Account.AddressChange.Intent.1',$this->context,($this->dependencies)()[14],$this->scope,$address->value()])));
        return new Intent($selector===''?'account.address.request':'account.address.complete',new Resource($this->scope,'account',$facts['record']->account()->subject(),$facts['record']->fingerprint(),['owner'=>$facts['record']->account()->subject()]),['target'=>$context,'identity'=>$facts['identity']->fingerprint(),'flow'=>$selector],['address']);
    }
    private function review(string $subject,string $sessionToken,?Address $address,string $selector,string $action,Deadline $deadline,bool $strong):array
    {
        $session=$this->session($subject,$sessionToken,$deadline,$strong);
        $snapshot=$this->unit()->run(function()use($subject,$address,$selector,$action):array{
            $this->ledger()->checkpoint(); // Match proof/maintenance order: ledger root before host account.
            $facts=$this->facts($subject);if($facts===null){throw new SecurityException('Current account required.','account.authentication');}$target=$address;
            if($selector!==''){
                $row=$this->ledger()->read($selector);if($row===null){throw new SecurityException('Address change is not ready.','account.change_incomplete');}$flow=$this->flow($row);list(,$current)=$this->pointer($subject);
                if($flow['subject']!==$subject||$current!==$selector||$flow['state']!=='ready'||$flow['valid_until']<=$this->unit()->now()||!$this->bound($flow,$facts)){throw new SecurityException('Address change is not ready.','account.change_incomplete');}
                $target=$this->target($flow,$selector,'new')->recipient();
            }
            $this->authorize($action,'review',$facts['record'],$target);$this->unchangedFacts($facts);return $facts+['address'=>$target,'intent'=>$this->intent($facts,$target,$selector)];
        },null,null,null,$deadline);
        if($snapshot['identity']->fingerprint()!==$session->account()->fingerprint()){throw new SecurityException('Authentication identity differs from current account.','account.changed');}return $snapshot+['session'=>$session];
    }
    private function permit(array $review,string $subject,string $sessionToken,string $grant,Deadline $deadline):Permit
    {
        if(!preg_match('/\Aog1\.[a-f0-9]{32}\.[a-f0-9]{64}\z/D',$grant)){throw new ValidationException('Invalid operation grant.','account.operation');}
        $deadline->check('account.timeout');$permit=$this->grants()->consume($this->scope,$subject,$sessionToken,$review['intent'],$grant);$deadline->check('account.timeout');
        if($permit===null||$permit->account()->fingerprint()!==$review['identity']->fingerprint()||$permit->sessionId()!==$review['session']->id()||$permit->method()!==$review['session']->method()||$permit->authenticatedAt()!==$review['session']->authenticatedAt()||$permit->expiresAt()<=$this->now()){throw new SecurityException('Current operation grant required.','account.operation');}return $permit;
    }
    private function send(string $selector,Address $recipient,string $type,string $token,int $until):string
    {
        $id=bin2hex(random_bytes(32));$now=$this->unit()->now();$notice=new Notice($this->scope,$id,$type,$recipient,$token,$now,$until);
        $this->ledger()->put($id,$selector,'notice',self::json(['format'=>1,'type'=>$type,'issued_at'=>$now,'valid_until'=>$until,'envelope'=>$this->notices()->seal($notice)]),$until);
        $this->queue()->enqueue(new Message($this->scope,'account-address-change',Message::identifier('account-change-notice-'.$id,$now),'mail','account.notice',$id,$id),'account-system');return $id;
    }
    public function initialize():void
    {
        $this->guard('initialize');$this->queue()->initialize($this->scope,'account-address-change','account-system');$this->unit()->run(function():void{$this->authorize('initialize','before');$this->ledger()->initialize();},null,function():void{$this->authorize('initialize','commit');});
    }
    /** Review metadata only. The subsequent Grants begin/reauthenticate/confirm sequence remains mandatory. */
    public function proposal(string $subject,string $newAddress,string $sessionToken,string $source):Intent
    {
        self::label($subject);self::label($source);$address=new Address($newAddress,$this->policy()->allowsSmtpUtf8());$deadline=new Deadline($this->policy()->ioMilliseconds());$this->charge('request','public',$source,$address,$subject);return $this->review($subject,$sessionToken,$address,'','request',$deadline,false)['intent'];
    }
    public function completionProposal(string $subject,string $selector,string $sessionToken,string $source):Intent
    {
        self::label($subject);self::label($source);self::id($selector);$deadline=new Deadline($this->policy()->ioMilliseconds());$this->charge('complete','public',$source,null,$subject);return $this->review($subject,$sessionToken,null,$selector,'complete',$deadline,false)['intent'];
    }
    public function request(string $subject,string $newAddress,string $sessionToken,string $grant,string $source):void
    {
        self::label($subject);self::label($source);$address=new Address($newAddress,$this->policy()->allowsSmtpUtf8());$deadline=new Deadline($this->policy()->ioMilliseconds());$budgetId=bin2hex(random_bytes(16));$this->charge('request','public',$source,$address,$subject,$budgetId);
        $review=$this->review($subject,$sessionToken,$address,'','request',$deadline,true);$permit=$this->permit($review,$subject,$sessionToken,$grant,$deadline);
        try{$this->unit()->run(function()use($subject,$address,$review,$permit,$source,$budgetId):?array{
            $this->ledger()->checkpoint(); // Match proof/maintenance order: ledger root before host account.
            $this->authorize('request','before',$review['record'],$address);$facts=$this->unchangedFacts($review);$this->charge('request','subject',$source,$address,$subject,$budgetId);$now=$this->unit()->now();
            if($permit->expiresAt()<=$now){throw new SecurityException('Operation expired.','account.operation');}
            $other=$this->unit()->invoke([$this->accounts(),'findAddress'],[$this->scope,$address],'account.repository');if($other!==null||$facts['record']->address()->equals($address)){return null;}
            list($cursor,$previous)=$this->pointer($subject);$prior=$previous===null?null:$this->ledger()->read($previous);if($previous!==null&&$prior===null){self::corrupt();}$old=$prior===null?null:$this->flow($prior);$resends=0;$until=$now+$this->policy()->lifetime('verify_address_new');
            if($old!==null&&$old['resend_at']>$now){return null;}
            if($old!==null&&$old['valid_until']>$now&&$old['state']!=='consumed'){
                if($old['resends']>=$this->policy()->maximumResends()){return null;}$resends=$old['resends']+1;$until=$old['valid_until'];
            }
            $this->ledger()->capacity($cursor===null?5:4);$selector=bin2hex(random_bytes(32));$flow=['format'=>1,'purpose'=>'address_change','subject'=>$subject,'account'=>$facts['record']->fingerprint(),'identity'=>$facts['identity']->fingerprint(),'issued_at'=>$now,'valid_until'=>$until,'resend_at'=>min($until,$now+$this->policy()->resendSeconds()),'resends'=>$resends,'state'=>'pending','proofs'=>[],'completed_account'=>'','completed_identity'=>'','success'=>['old'=>null,'new'=>null]];
            foreach(['old','new','cancel'] as $side){$token=bin2hex(random_bytes(32));$recipient=$side==='new'?$address:$facts['record']->address();$id=$this->send($selector,$recipient,$this->type($side),$token,$until);$flow['proofs'][$side]=['digest'=>hash('sha256',$side.'.'.$token),'address_tag'=>$this->tag($flow,$side,$recipient,$token),'notice_id'=>$id,'attempts'=>0,'confirmed'=>false];}
            $row=$this->ledger()->put($selector,$this->owner($subject),'change',self::json($flow),$until+$this->policy()->lifetime('address_changed'));
            $this->ledger()->put($this->cursor($subject),$this->owner($subject),'budget',self::json(['format'=>1,'subject'=>$subject,'flow_id'=>$selector]),$row['retire_at'],$cursor===null?null:$cursor['revision']);
            return $facts+['row'=>$row,'until'=>$until,'address'=>$address];
        },null,function(?array $state)use($permit,$source,$budgetId):void{
            if($state===null){return;}$this->authorize('request','commit',$state['record'],$state['address']);$this->unchangedFacts($state);$this->charge('request','final',$source,$state['address'],$state['record']->account()->subject(),$budgetId);$this->unchangedFlow($state['row']);if(min($permit->expiresAt(),$state['until'])<=$this->unit()->now()){throw new SecurityException('Address request expired.','account.expired');}
        },function(?array $state)use($permit):void{if($state!==null){$this->authorize('request','complete',$state['record'],$state['address']);$this->unchangedFacts($state);$this->unchangedFlow($state['row']);if(min($state['until'],$permit->expiresAt())<=$this->unit()->now()){throw new SecurityException('Address request expired during completion.','account.expired');}}},$deadline);
        }catch(\Throwable $error){if($this->unit()->committed()){throw new StorageException('Address request committed but completion is unknown.','account.completion_unknown');}throw $error;}
    }
    public function confirm(string $selector,string $side,string $token,string $source):bool
    {
        if(!in_array($side,['old','new'],true)){throw new ValidationException('Use a fixed mailbox proof purpose.','account.proof');}return $this->proof($selector,$side,$token,$source);
    }
    public function cancel(string $selector,string $token,string $source):bool {return $this->proof($selector,'cancel',$token,$source);}
    private function proof(string $selector,string $side,string $token,string $source):bool
    {
        self::id($selector);self::id($token);self::label($source);$action=$side==='cancel'?'cancel':'confirm';$deadline=new Deadline($this->policy()->ioMilliseconds());$budgetId=bin2hex(random_bytes(16));$this->charge($action,'public',$source,null,null,$budgetId);
        try{$state=$this->unit()->run(function()use($selector,$side,$token,$source,$action,$budgetId):?array{
            $this->authorize($action,'before');$row=$this->ledger()->read($selector);if($row===null||$row['kind']!=='change'){return null;}$flow=$this->flow($row);
            if(!in_array($flow['state'],$side==='cancel'?['pending','ready','locked']:['pending','ready'],true)||$flow['valid_until']<=$this->unit()->now()||$flow['proofs'][$side]['attempts']>=$this->policy()->maximumAttempts()||$flow['proofs'][$side]['confirmed']){return null;}
            $facts=$this->facts($flow['subject']);list(,$current)=$this->pointer($flow['subject']);if($facts===null||!$this->bound($flow,$facts)||$current!==$selector){return null;}
            $this->charge($action,'subject',$source,null,$flow['subject'],$budgetId);$this->authorize($action,'proof',$facts['record']);$this->unchangedFacts($facts);++$flow['proofs'][$side]['attempts'];$valid=hash_equals($flow['proofs'][$side]['digest'],hash('sha256',$side.'.'.$token));
            if($valid){$notice=$this->target($flow,$selector,$side);$valid=hash_equals($notice->token(),$token)&&($side==='new'||$notice->recipient()->equals($facts['record']->address()));}
            if($valid){if($side==='cancel'){$flow['state']='cancelled';}else{$flow['proofs'][$side]['confirmed']=true;if($flow['proofs']['old']['confirmed']&&$flow['proofs']['new']['confirmed']){$flow['state']='ready';}}}
            elseif($flow['proofs'][$side]['attempts']===$this->policy()->maximumAttempts()&&$side!=='cancel'){$flow['state']='locked';}
            $saved=$this->ledger()->put($selector,$row['owner'],'change',self::json($flow),$row['retire_at'],$row['revision']);return $facts+['row'=>$saved,'until'=>$flow['valid_until'],'valid'=>$valid];
        },null,function(?array $state)use($source,$action,$budgetId):void{
            if($state===null){return;}$this->authorize($action,'commit',$state['record']);$this->unchangedFacts($state);$this->charge($action,'final',$source,null,$state['record']->account()->subject(),$budgetId);$this->unchangedFlow($state['row']);if($state['until']<=$this->unit()->now()){throw new SecurityException('Address proof expired.','account.expired');}
        },function(?array $state)use($action):void{if($state!==null&&$state['valid']){$this->authorize($action,'complete',$state['record']);$this->unchangedFacts($state);$this->unchangedFlow($state['row']);if($state['until']<=$this->unit()->now()){throw new SecurityException('Address proof expired during completion.','account.expired');}}},$deadline);return $state!==null&&$state['valid'];
        }catch(\Throwable $error){if($this->unit()->committed()){throw new StorageException('Proof committed but completion is unknown.','account.completion_unknown');}throw $error;}
    }
    private function recipientMessage(string $selector,string $side,Address $address):string {return self::json(['SoSecurity.Account.AddressChange.Recipient.1',$this->context,$this->scope,$selector,$side,$address->value()]);}
    public function complete(string $subject,string $selector,string $sessionToken,string $grant,string $source):bool
    {
        self::label($subject);self::id($selector);self::label($source);$deadline=new Deadline($this->policy()->ioMilliseconds());$budgetId=bin2hex(random_bytes(16));$this->charge('complete','public',$source,null,$subject,$budgetId);
        $review=$this->review($subject,$sessionToken,null,$selector,'complete',$deadline,true);$permit=$this->permit($review,$subject,$sessionToken,$grant,$deadline);
        try{$result=$this->unit()->run(function()use($subject,$selector,$review,$permit,$source,$budgetId):?array{
            $this->ledger()->checkpoint(); // Match proof/maintenance order: ledger root before host account.
            $facts=$this->unchangedFacts($review);$row=$this->ledger()->read($selector);if($row===null){self::corrupt();}$flow=$this->flow($row);list(,$current)=$this->pointer($subject);
            if($current!==$selector||$flow['state']!=='ready'||$flow['subject']!==$subject||!$this->bound($flow,$facts)||$flow['valid_until']<=$this->unit()->now()){return null;}
            $target=$this->target($flow,$selector,'new')->recipient();if(!$target->equals($review['address'])){self::corrupt();}$old=$this->target($flow,$selector,'old')->recipient();if(!$old->equals($facts['record']->address())){self::corrupt();}
            $this->authorize('complete','before',$facts['record'],$target);$this->unchangedFacts($facts);$this->charge('complete','subject',$source,$target,$subject,$budgetId);
            $this->unchangedFlow($row);$this->unchangedFacts($facts);
            if($permit->expiresAt()<=$this->unit()->now()){throw new SecurityException('Operation expired.','account.operation');}
            if($this->unit()->invoke([$this->accounts(),'findAddress'],[$this->scope,$target],'account.repository')!==null){return null;}$this->ledger()->capacity(2);
            $changed=$this->unit()->invoke([$this->accounts(),'changeAddress'],[$facts['record'],$target],'account.repository');
            if(!$changed instanceof AccountRecord||$changed->account()->subject()!==$subject||$changed->account()->scope()!==$this->scope||!$changed->address()->equals($target)||$changed->account()->version()===$facts['record']->account()->version()||$changed->addressVersion()===$facts['record']->addressVersion()||$changed->account()->roles()!==$facts['record']->account()->roles()||$changed->account()->mfaRequired()!==$facts['record']->account()->mfaRequired()||!$changed->verified()||$changed->status()!=='active'||!$changed->account()->enabled()){throw new StorageException('Address update conflicted with current account.','account.conflict');}
            $after=$this->facts($subject);if($after===null||$after['record']->fingerprint()!==$changed->fingerprint()||$after['identity']->fingerprint()===$facts['identity']->fingerprint()){self::corrupt();}$until=$this->unit()->now()+$this->policy()->lifetime('address_changed');$flow['state']='consumed';$flow['completed_account']=$after['record']->fingerprint();$flow['completed_identity']=$after['identity']->fingerprint();
            foreach(['old'=>$old,'new'=>$target] as $side=>$address){$id=$this->send($selector,$address,'address_changed','',$until);$flow['success'][$side]=['notice_id'=>$id,'key_id'=>$this->keys()->currentId(),'recipient_tag'=>bin2hex($this->keys()->sign($this->recipientMessage($selector,$side,$address)))];}
            $saved=$this->ledger()->put($selector,$row['owner'],'change',self::json($flow),max($row['retire_at'],$until),$row['revision']);return $after+['row'=>$saved,'until'=>$flow['valid_until'],'target'=>$target];
        },null,function(?array $state)use($permit,$source,$budgetId):void{
            if($state===null){return;}$this->authorize('complete','commit',$state['record'],$state['target']);$this->unchangedFacts($state);$this->charge('complete','final',$source,$state['target'],$state['record']->account()->subject(),$budgetId);
            $this->unchangedFlow($state['row']);if(min($state['until'],$permit->expiresAt())<=$this->unit()->now()){throw new SecurityException('Address completion expired.','account.expired');}
        },function(?array $state)use($permit):void{
            if($state===null){return;}$this->authorize('complete','complete',$state['record'],$state['target']);$this->unchangedFacts($state);$this->unchangedFlow($state['row']);
            if(min($state['until'],$permit->expiresAt())<=$this->unit()->now()){throw new SecurityException('Address completion expired during commit.','account.expired');}
        },$deadline);return $result!==null;
        }catch(\Throwable $error){if($this->unit()->committed()){throw new StorageException('Address changed but completion could not be confirmed.','account.completion_unknown');}throw $error;}
    }
    private function deliveryState(string $id):?array
    {
        $raw=$this->ledger()->read($id);if($raw===null){return null;}$entry=$this->noticeRow($id,$raw);if($entry['data']['valid_until']<=$this->unit()->now()){return null;}$row=$this->ledger()->read($entry['row']['owner']);if($row===null){self::corrupt();}$flow=$this->flow($row);$facts=$this->facts($flow['subject']);$type=$entry['data']['type'];$notice=$this->openNotice($entry);$selector=$row['record_id'];
        if($type==='address_changed'){
            if($flow['state']!=='consumed'){return null;}$side=null;foreach($flow['success'] as $name=>$meta){if($meta['notice_id']===$id){$side=$name;break;}}if($side===null){self::corrupt();}$meta=$flow['success'][$side];
            if(!$this->keys()->verify($meta['key_id'],$this->recipientMessage($selector,$side,$notice->recipient()),hex2bin($meta['recipient_tag']))){self::corrupt();}$selector='';
        }else{
            $side=array_search($type,['old'=>'verify_address_old','new'=>'verify_address_new','cancel'=>'cancel_change'],true);list(,$current)=$this->pointer($flow['subject']);
            if($side===false||$facts===null||$current!==$selector||!$this->bound($flow,$facts)||!in_array($flow['state'],$side==='cancel'?['pending','ready','locked']:['pending','ready'],true)||$flow['valid_until']<=$this->unit()->now()||$flow['proofs'][$side]['notice_id']!==$id||$flow['proofs'][$side]['confirmed']){return null;}
            $this->target($flow,$selector,$side);if($side!=='new'&&!$notice->recipient()->equals($facts['record']->address())){self::corrupt();}
        }
        return ['row'=>$entry['row'],'flow'=>$row,'record'=>$facts===null?null:$facts['record'],'delivery'=>new ChangeDelivery($notice,$selector)];
    }
    private function unchangedDelivery(array $state):void
    {
        $fresh=$this->deliveryState($state['delivery']->notice()->id());$before=$state['record']===null?null:$state['record']->fingerprint();$after=$fresh===null||$fresh['record']===null?null:$fresh['record']->fingerprint();
        if($fresh===null||$fresh['row']!==$state['row']||$fresh['flow']!==$state['flow']||$before!==$after||$state['delivery']->notice()->expiresAt()<=$this->unit()->now()){throw new SecurityException('Address delivery changed during authority checks.','account.notification_changed');}
    }
    private function notificationRead(string $id):?array
    {
        self::id($id);$this->guard('notification');$state=$this->unit()->run(function()use($id):?array{$this->authorize('notification','before');$state=$this->deliveryState($id);if($state!==null){$this->authorize('notification','read',$state['record']);$this->unchangedDelivery($state);}return $state;},
            null,function(?array $state):void{$this->authorize('notification','commit',$state===null?null:$state['record']);if($state!==null){$this->unchangedDelivery($state);}},
            function(?array $state):void{$this->authorize('notification','complete',$state===null?null:$state['record']);if($state!==null){$this->unchangedDelivery($state);}});
        return $state;
    }
    public function notification(string $id):?ChangeDelivery {$state=$this->notificationRead($id);return $state===null?null:$state['delivery'];}
    public function notificationForDispatch(string $id):?DispatchNotice
    {
        $state=$this->notificationRead($id);if($state===null){return null;}$flow=$this->flow($state['flow']);return new DispatchNotice($state['delivery']->notice(),$state['delivery']->selector(),$flow['subject']);
    }
    private static function pageInput(int $limit,string $after):void
    {
        if($limit<1||$limit>50||($after!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$after))){throw new ConfigurationException('Use a bounded account page and cursor.','configuration.account_maintenance');}
    }
    private static function progress(array $headers,int $limit,array $counts):array
    {
        $size=count($headers);return ['examined'=>$size]+$counts+['after'=>$size===$limit?$headers[$size-1]['record_id']:'','done'=>$size<$limit];
    }
    private function maintenanceData(array $row):array
    {
        if($row['kind']==='change'){return $this->flow($row);}
        if($row['kind']==='budget'){
            $data=json_decode($row['payload'],true,3);
            if(!is_array($data)||!isset($data['subject'])||!is_string($data['subject'])||$data['subject']===''||strlen($data['subject'])>256||preg_match('/[\x00-\x1f\x7f]/',$data['subject'])||preg_match('//u',$data['subject'])!==1){self::corrupt();}
            list($pointer,$id)=$this->pointer($data['subject']);if($pointer!==$row||$row['record_id']!==$this->cursor($data['subject'])||$id===null){self::corrupt();}
            $target=$this->ledger()->read($id);if($target===null){self::corrupt();}$flow=$this->flow($target);
            if($flow['subject']!==$data['subject']||$row['retire_at']<$target['retire_at']){self::corrupt();}return $data;
        }
        if($row['kind']==='notice'){
            $entry=$this->noticeRow($row['record_id'],$row);$data=$entry['data'];$meta=$this->notices()->metadata($data['envelope'],$this->scope,$row['record_id'],$data['type']);
            if($meta['issued_at']!==$data['issued_at']||$meta['expires_at']!==$data['valid_until']){self::corrupt();}return $data+['key_id'=>$meta['key_id']];
        }
        self::corrupt();
    }
    /** A flow can own at most three proofs and two security notices. Validate all retained links before retiring it. */
    private function retirementLinks(array $row,array $flow):void
    {
        $references=[];foreach($flow['proofs'] as $side=>$proof){$references[]=['id'=>$proof['notice_id'],'type'=>$this->type($side),'until'=>$flow['valid_until']];}
        foreach($flow['success'] as $meta){if($meta!==null){$references[]=['id'=>$meta['notice_id'],'type'=>'address_changed','until'=>null];}}
        foreach($references as $reference){
            $notice=$this->ledger()->read($reference['id']);if($notice===null){continue;}$data=$this->maintenanceData($notice);
            if($notice['kind']!=='notice'||$notice['owner']!==$row['record_id']||$data['type']!==$reference['type']||($reference['until']!==null&&$data['valid_until']!==$reference['until'])||$data['valid_until']>$row['retire_at']){self::corrupt();}
        }
    }
    /** At most limit headers plus current-pointer partners are deleted. Host accounts and Outbox remain untouched. */
    public function maintain(int $limit=20,string $after=''):array
    {
        self::pageInput($limit,$after);$this->guard('maintain');
        $state=$this->unit()->run(function()use($limit,$after):array{
            $this->authorize('maintain','before');$headers=$this->ledger()->page($limit,$after);$remove=[];$expected=[];$now=$this->unit()->now();
            foreach($headers as $header){
                if(isset($remove[$header['record_id']])){continue;}$row=$this->ledger()->read($header['record_id']);if($row===null){self::corrupt();}$data=$this->maintenanceData($row);
                if($row['retire_at']>$now){$expected[$row['record_id']]=$row;continue;}
                if($row['kind']==='change'){
                    if($data['valid_until']>$now){self::corrupt();}$this->retirementLinks($row,$data);list($pointer,$current)=$this->pointer($data['subject']);
                    if($pointer!==null){$this->maintenanceData($pointer);if($current===$row['record_id']){if($pointer['retire_at']>$now){self::corrupt();}$remove[$pointer['record_id']]=$pointer['revision'];}}
                }elseif($row['kind']==='budget'){
                    $flowRow=$this->ledger()->read($data['flow_id']);if($flowRow===null){self::corrupt();}$flow=$this->flow($flowRow);
                    if($flowRow['retire_at']>$now||$flow['valid_until']>$now){self::corrupt();}$this->retirementLinks($flowRow,$flow);$remove[$flowRow['record_id']]=$flowRow['revision'];
                }
                $remove[$row['record_id']]=$row['revision'];
            }
            $result=self::progress($headers,$limit,['removed'=>$remove?$this->ledger()->remove($remove):0]);return ['result'=>$result,'checkpoint'=>$this->ledger()->checkpoint(),'rows'=>array_diff_key($expected,$remove)];
        },null,function(array $state):void{
            $this->authorize('maintain','commit');foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){throw new StorageException('Retained account payload changed before commit.','account.changed');}}
            if($this->ledger()->checkpoint()!==$state['checkpoint']){throw new StorageException('Account maintenance state changed before commit.','account.changed');}
        });
        return $state['result'];
    }
    private function rotateRecipients(array $row,array $flow,int &$count):array
    {
        if($flow['state']!=='consumed'){return $flow;}
        foreach($flow['success'] as $side=>$meta){
            $noticeRow=$this->ledger()->read($meta['notice_id']);if($noticeRow===null){continue;}$entry=$this->noticeRow($meta['notice_id'],$noticeRow);
            if($noticeRow['owner']!==$row['record_id']||$entry['data']['type']!=='address_changed'||$entry['data']['valid_until']>$row['retire_at']){self::corrupt();}
            $this->maintenanceData($noticeRow);
            // Expired or already retired notices cannot be delivered. Preserve their inert historical tags.
            if($entry['data']['valid_until']<=$this->unit()->now()){continue;}
            $notice=$this->openNotice($entry);$message=$this->recipientMessage($row['record_id'],$side,$notice->recipient());
            if(!$this->keys()->verify($meta['key_id'],$message,hex2bin($meta['recipient_tag']))){self::corrupt();}
            if($meta['key_id']!==$this->keys()->currentId()){$flow['success'][$side]['key_id']=$this->keys()->currentId();$flow['success'][$side]['recipient_tag']=bin2hex($this->keys()->sign($message));++$count;}
        }
        return $flow;
    }
    /** Reseal every record and reencrypt every notice; live inner recipient tags must rotate before retiring old keys. */
    public function rotate(int $limit=20,string $after=''):array
    {
        self::pageInput($limit,$after);$this->guard('rotate');
        $state=$this->unit()->run(function()use($limit,$after):array{
            $this->authorize('rotate','before');$headers=$this->ledger()->page($limit,$after);$root=$this->ledger()->rotateRoot();$resealed=0;$reencrypted=0;$retagged=0;$expected=[];
            foreach($headers as $header){
                $row=$this->ledger()->read($header['record_id']);if($row===null){self::corrupt();}$data=$this->maintenanceData($row);$payload=$row['payload'];
                if($row['kind']==='change'){$payload=self::json($this->rotateRecipients($row,$data,$retagged));}
                elseif($row['kind']==='notice'&&$data['key_id']!==$this->notices()->currentId()){
                    unset($data['key_id']);$data['envelope']=$this->notices()->reencrypt($data['envelope'],$this->scope,$row['record_id'],$data['type']);$payload=self::json($data);++$reencrypted;
                }
                if($payload!==$row['payload']||$row['seal_key']!==$this->keys()->currentId()){$row=$this->ledger()->put($row['record_id'],$row['owner'],$row['kind'],$payload,$row['retire_at'],$row['revision']);++$resealed;}$expected[$row['record_id']]=$row;
            }
            return ['result'=>self::progress($headers,$limit,['resealed'=>$resealed,'reencrypted'=>$reencrypted,'recipient_tags'=>$retagged,'root_rotated'=>$root]),'checkpoint'=>$this->ledger()->checkpoint(),'rows'=>$expected];
        },null,function(array $state):void{
            $this->authorize('rotate','commit');foreach($state['rows'] as $id=>$row){if($this->ledger()->read($id)!==$row){throw new StorageException('Rotated account payload changed before commit.','account.changed');}}
            if($this->ledger()->checkpoint()!==$state['checkpoint']){throw new StorageException('Account rotation state changed before commit.','account.changed');}
        });
        return $state['result'];
    }
    /** Explicit worker factory; queue authority and current private-notice authority remain independently required. */
    public function dispatcher(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds=10000,int $transportMilliseconds=3000):Dispatcher
    {return ($this->dispatchFactory)($worker,$budgets,$templates,$transport,$workerAuthority,$budgetMilliseconds,$transportMilliseconds);}
    public function __debugInfo():array {return ['account_address_change'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload private account services.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload private account services.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account services are immutable.','configuration.immutable');}
}
