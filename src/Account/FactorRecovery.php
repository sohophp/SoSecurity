<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Mfa\Enrollment;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;

/** Strong-approved replacement. All SQL participants use the host PDO; prepared slots never authenticate users. */
final class FactorRecovery
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $factors,callable $facts,callable $activate,callable $authority,callable $budgets,callable $approval,callable $events,Policy $policy,Clock $clock,callable $managementFacts,?LocalEpochFence $fence=null)
    {
        foreach([$site,$scope] as $label){self::label($label);}self::id($epoch);
        if($fence!==null&&!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use the matching factor worker authority.','configuration.factor_fence');}
        new SqlTransaction($connection,$clock,$policy->ioMilliseconds());$factors->validateConfiguration($clock,true);
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$factors,$facts,$activate,$authority,$budgets,$approval,$events,$policy,$clock,$managementFacts,$fence):array{return [$connection,$site,$scope,$epoch,$keys,$factors,$facts,$activate,$authority,$budgets,$approval,$events,$policy,$clock,$managementFacts,$fence];};
    }
    private function withWork(callable $operation) {$d=$this->d();return $d[15]===null?$operation():$d[15]->work($operation);}
    public function initialize():void {$this->withWork(function():void{$this->initializeInternal();});}
    public function begin(string $subject,string $source):FactorRecoveryEnrollment {return $this->withWork(function()use($subject,$source){return $this->beginInternal($subject,$source);});}
    public function prove(string $selector,string $code,string $source):?array {return $this->withWork(function()use($selector,$code,$source){return $this->proveInternal($selector,$code,$source);});}
    public function approvalRequest(string $selector,string $source):?FactorReplacementApproval {return $this->withWork(function()use($selector,$source){return $this->approvalRequestInternal($selector,$source);});}
    public function confirm(string $selector,string $source,array $proof):bool {return $this->withWork(function()use($selector,$source,$proof){return $this->confirmInternal($selector,$source,$proof);});}
    public function cancel(string $selector,string $source):bool {return $this->withWork(function()use($selector,$source){return $this->cancelInternal($selector,$source);});}
    public function clean(string $selector,string $source):array {return $this->withWork(function()use($selector,$source){return $this->cleanInternal($selector,$source);});}
    private function d():array {return ($this->dependencies)();}
    private function unit():SqlTransaction {$d=$this->d();return new SqlTransaction($d[0],$d[13],$d[12]->ioMilliseconds());}
    private function ledger(SqlTransaction $u):Ledger {$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[12],$d[15]===null?1:2,$d[15]===null?null:$d[15]->binding());}
    private static function label(string $value):void {Guard::label($value);if(preg_match('//u',$value)!==1){throw new ValidationException('Use a bounded UTF-8 factor recovery label.','account.factor_input');}}
    private static function id(string $value):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new ValidationException('Use a fixed factor recovery selector.','account.factor_input');}}
    private static function json(array $value):string {return json_encode($value,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    private static function corrupt():void {throw new StorageException('Factor recovery state cannot be authenticated.','account.factor_corrupt');}
    private function owner(string $subject):string {return hash('sha256','SoSecurity.Account.FactorRecovery.Owner.1.'.$subject);}
    private function cursor(string $subject):string {return hash('sha256','SoSecurity.Account.FactorRecovery.Cursor.1.'.$subject);}
    private function guard(SqlTransaction $u,string $action,string $phase,?array $state=null,string $selector=''):void
    {
        $d=$this->d();$authorityRoot=null;if($action!=='worker_rotate'){$d[5]->enlistWorkers($d[0]);$authorityRoot=$action==='initialize'?$this->ledger($u)->checkpointIfInitialized():$this->ledger($u)->checkpoint();}$record=$state['facts']['record']??null;$metadata=$state===null?[]:['subject'=>$state['flow']['subject'],'valid_until'=>$state['flow']['valid_until'],'state'=>$state['flow']['state'],'revision'=>$state['row']['revision'],'retire_at'=>$state['row']['retire_at'],'target_stamp'=>$state['facts']['stamp']??''];
        if($u->invoke($d[8],[$action,$phase,$d[2],$record,$selector,$metadata],'account.factor_authority')!==true){throw new SecurityException('Current factor recovery authority required.','account.factor_denied');}if($action!=='worker_rotate'){$d[5]->enlistWorkers($d[0]);$currentRoot=$action==='initialize'?$this->ledger($u)->checkpointIfInitialized():$this->ledger($u)->checkpoint();if($currentRoot!==$authorityRoot){throw new StorageException('Recovery root changed during current actor checks.','account.factor_changed');}}
    }
    private function charge(SqlTransaction $u,string $action,string $phase,string $source,string $operation,?array $state=null):void
    {
        $d=$this->d();if($u->invoke($d[9],[$action,$phase,$d[2],$source,$state['flow']['subject']??null,$operation],'account.factor_budget')!==true){throw new SecurityException('Factor recovery budget refused.','account.factor_budget');}
    }
    private function facts(SqlTransaction $u,string $subject):array {$d=$this->d();return $u->invoke($d[6],[$u,$subject],'account.factor_directory');}
    private function managementFacts(SqlTransaction $u,string $subject):array {$d=$this->d();return $u->invoke($d[14],[$u,$subject],'account.factor_directory');}
    private function parse(array $row):array
    {
        $f=json_decode($row['payload'],true,4);$keys=['format','purpose','subject','account','identity','old_binding','old_scope','old_subject','old_factor','slot_scope','slot_subject','issued_at','valid_until','enrollment_id','new_factor','attempts','state','completed_account','completed_identity','completed_binding'];
        if($row['kind']!=='recover'||!is_array($f)||array_keys($f)!==$keys||$f['format']!==2||$f['purpose']!=='factor_recovery'){self::corrupt();}
        foreach(['subject','old_scope','old_subject','slot_scope','slot_subject'] as $key){if(!is_string($f[$key])||$f[$key]===''||strlen($f[$key])>256||preg_match('//u',$f[$key])!==1||preg_match('/[\x00-\x1f\x7f]/',$f[$key])){self::corrupt();}}
        foreach(['account','identity','old_binding'] as $key){if(!is_string($f[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$f[$key])){self::corrupt();}}
        if(!in_array($f['state'],['preparing','pending','proven','consumed','cancelled'],true)){self::corrupt();}
        if(!is_string($f['old_factor'])||!preg_match('/\A[a-f0-9]{32}\z/D',$f['old_factor'])||$f['enrollment_id']===''){self::corrupt();}
        foreach(['enrollment_id','new_factor'] as $key){if(!is_string($f[$key])||($f[$key]!==''&&!preg_match('/\A[a-f0-9]{32}\z/D',$f[$key]))){self::corrupt();}}
        foreach(['issued_at','valid_until','attempts'] as $key){if(!is_int($f[$key])||$f[$key]<0){self::corrupt();}}
        $d=$this->d();if($f['issued_at']!==$row['created_at']||$f['valid_until']<=$f['issued_at']||$f['valid_until']-$f['issued_at']>$d[12]->lifetime('recover_account')||$row['retire_at']<$f['valid_until']||$f['attempts']>$d[12]->maximumAttempts()||$row['owner']!==$this->owner($f['subject'])){self::corrupt();}
        if(($f['state']==='preparing'&&$f['new_factor']!=='')||($f['state']==='pending'&&($f['enrollment_id']===''||$f['new_factor']!==''))||(in_array($f['state'],['proven','consumed'],true)&&($f['enrollment_id']===''||$f['new_factor']!==$f['enrollment_id']))){self::corrupt();}
        foreach(['completed_account','completed_identity','completed_binding'] as $key){if(!is_string($f[$key])||($f['state']==='consumed'?!preg_match('/\A[a-f0-9]{64}\z/D',$f[$key]):$f[$key]!=='')){self::corrupt();}}
        if(self::json($f)!==$row['payload']){self::corrupt();}return $f;
    }
    private function pointer(?array $row,string $subject):?string
    {
        if($row===null){return null;}$f=json_decode($row['payload'],true,3);
        if($row['kind']!=='budget'||$row['record_id']!==$this->cursor($subject)||$row['owner']!==$this->owner($subject)||!is_array($f)||array_keys($f)!==['format','purpose','subject','flow_id']||$f['format']!==1||$f['purpose']!=='factor_recovery_cursor'||$f['subject']!==$subject||!is_string($f['flow_id'])||!preg_match('/\A[a-f0-9]{64}\z/D',$f['flow_id'])||self::json($f)!==$row['payload']){self::corrupt();}return $f['flow_id'];
    }
    private function bound(array $f,array $facts,bool $completed=false):bool
    {
        return $facts['record']->fingerprint()===($completed?$f['completed_account']:$f['account'])&&$facts['identity']->fingerprint()===($completed?$f['completed_identity']:$f['identity'])&&$facts['slot']->binding()===($completed?$f['completed_binding']:$f['old_binding']);
    }
    private function load(SqlTransaction $u,string $selector,array $states):?array
    {
        $l=$this->ledger($u);$l->checkpoint();$row=$l->read($selector);if($row===null){return null;}$f=$this->parse($row);
        if(!in_array($f['state'],$states,true)||$f['valid_until']<=$u->now()||$this->pointer($l->read($this->cursor($f['subject'])),$f['subject'])!==$selector){return null;}
        $facts=$this->facts($u,$f['subject']);if(!$this->bound($f,$facts,$f['state']==='consumed')){return null;}
        return ['row'=>$row,'flow'=>$f,'facts'=>$facts,'checkpoint'=>$l->checkpoint()];
    }
    private function save(SqlTransaction $u,array $state,array $f):array
    {
        $l=$this->ledger($u);$row=$state['row'];$saved=$l->put($row['record_id'],$row['owner'],'recover',self::json($f),$row['retire_at'],$row['revision']);return ['row'=>$saved,'flow'=>$f,'facts'=>$state['facts'],'checkpoint'=>$l->checkpoint()];
    }
    private function check(SqlTransaction $u,array $state,string $action,string $source,string $operation,string $phase='commit',?FactorReplacementApproval $review=null,array $proof=[]):void
    {
        $selector=$state['row']['record_id'];$this->charge($u,$action,'final',$source,$operation,$state);if($review!==null&&!$this->approved($u,$phase,$review,$proof)){throw new SecurityException('Factor approval is no longer current.','account.factor_denied');}$this->guard($u,$action,$phase,$state,$selector);$l=$this->ledger($u);
        if($l->checkpoint()!==$state['checkpoint']||$l->read($selector)!==$state['row']||$this->pointer($l->read($this->cursor($state['flow']['subject'])),$state['flow']['subject'])!==$selector||!$this->bound($state['flow'],$this->facts($u,$state['flow']['subject']),$state['flow']['state']==='consumed')||$u->now()>=$state['flow']['valid_until']){throw new StorageException('Factor recovery changed before completion.','account.factor_changed');}
    }
    private function event(SqlTransaction $u,string $type,array $before,array $after,string $selector):void
    {
        $d=$this->d();if($u->invoke($d[11],[$type,$d[2],$before['record'],$after['record'],$selector,['subject'=>$before['slot']->subject()]],'account.factor_event')!==true){throw new StorageException('A durable factor security notification is required.','account.factor_event');}
    }
    private function initializeInternal():void
    {
        $u=$this->unit();$u->run(function()use($u):void{$this->guard($u,'initialize','before');$this->ledger($u)->initialize();},null,function()use($u):void{$this->guard($u,'initialize','commit');});
    }
    /** Reservation and notification commit before any external factor state is created. Failed preparation is retained for explicit cleanup. */
    private function beginInternal(string $subject,string $source):FactorRecoveryEnrollment
    {
        self::label($subject);self::label($source);$d=$this->d();$operation=bin2hex(random_bytes(16));$selector=bin2hex(random_bytes(32));$u=$this->unit();
        $state=$u->run(function()use($u,$subject,$source,$operation,$selector,$d):array{
            $this->charge($u,'begin','public',$source,$operation);$this->guard($u,'begin','before');$l=$this->ledger($u);$l->checkpoint();$facts=$this->facts($u,$subject);$cursor=$l->read($this->cursor($subject));$old=$this->pointer($cursor,$subject);
            if($old!==null){$previous=$l->read($old);if($previous===null){self::corrupt();}$prior=$this->parse($previous);if($prior['valid_until']>$u->now()&&!in_array($prior['state'],['consumed','cancelled'],true)){throw new SecurityException('An existing factor preparation is still pending.','account.factor_pending');}}
            $now=$u->now();$until=$now+$d[12]->lifetime('recover_account');$l->capacity($cursor===null?2:1);
            $f=['format'=>2,'purpose'=>'factor_recovery','subject'=>$subject,'account'=>$facts['record']->fingerprint(),'identity'=>$facts['identity']->fingerprint(),'old_binding'=>$facts['slot']->binding(),'old_scope'=>$facts['slot']->slotScope(),'old_subject'=>$facts['slot']->slotSubject(),'old_factor'=>$facts['slot']->factorId(),'slot_scope'=>'factor-recovery:'.bin2hex(random_bytes(32)),'slot_subject'=>$selector,'issued_at'=>$now,'valid_until'=>$until,'enrollment_id'=>bin2hex(random_bytes(16)),'new_factor'=>'','attempts'=>0,'state'=>'preparing','completed_account'=>'','completed_identity'=>'','completed_binding'=>''];
            $row=$l->put($selector,$this->owner($subject),'recover',self::json($f),$until+$d[12]->lifetime('account_activated'));
            $l->put($this->cursor($subject),$this->owner($subject),'budget',self::json(['format'=>1,'purpose'=>'factor_recovery_cursor','subject'=>$subject,'flow_id'=>$selector]),$until+$d[12]->lifetime('account_activated'),$cursor['revision']??null);
            $this->event($u,'factor_recovery_started',$facts,$facts,$selector);return ['row'=>$row,'flow'=>$f,'facts'=>$facts,'checkpoint'=>$l->checkpoint()];
        },null,function(array $state)use($u,$source,$operation):void{$this->check($u,$state,'begin',$source,$operation);});
        $f=$state['flow'];$pending=$d[5]->prepare($f['slot_scope'],$f['slot_subject'],$f['enrollment_id'],$state['facts']['record']->address()->value());$u=$this->unit();
        $saved=$u->run(function()use($u,$state,$pending,$selector):array{
            $fresh=$this->load($u,$selector,['preparing']);if($fresh===null||$fresh['row']!==$state['row']){throw new StorageException('Factor preparation changed.','account.factor_changed');}$this->guard($u,'begin','prepared',$fresh,$selector);
            $f=$fresh['flow'];if($pending->id()!==$f['enrollment_id']){self::corrupt();}$f['state']='pending';return $this->save($u,$fresh,$f);
        },null,function(array $state)use($u,$source,$operation):void{$this->check($u,$state,'begin',$source,$operation);});
        $this->complete($saved,'begin',$source,$operation);$until=min($pending->expiresAt(),$saved['flow']['valid_until']);if($d[13]->now()>=$until){throw new StorageException('Factor preparation expired before delivery.','account.completion_unknown');}
        return new FactorRecoveryEnrollment($selector,new Enrollment($pending->id(),$pending->provisioningUri(),$until));
    }
    /** Spend SQL attempts before any irreversible external factor proof or approval consumption. */
    private function attempt(string $selector,string $source,string $action,string $required,string $operation):?array
    {
        $u=$this->unit();$d=$this->d();return $u->run(function()use($u,$selector,$source,$action,$required,$operation,$d):?array{
            $this->charge($u,$action,'public',$source,$operation);$this->guard($u,$action,'before',null,$selector);$state=$this->load($u,$selector,[$required]);if($state===null||$state['flow']['attempts']>=$d[12]->maximumAttempts()){return null;}
            $this->guard($u,$action,'proof',$state,$selector);$f=$state['flow'];++$f['attempts'];return $this->save($u,$state,$f);
        },null,function(?array $state)use($u,$source,$action,$operation):void{if($state!==null){$this->check($u,$state,$action,$source,$operation);}});
    }
    /** Explicit recovery-code output once. [] means a previously confirmed isolated slot was proved again after a SQL failure. */
    private function proveInternal(string $selector,string $code,string $source):?array
    {
        self::id($selector);self::label($source);if(!preg_match('/\A[0-9]{6,8}\z/D',$code)){throw new ValidationException('Use a bounded factor possession code.','account.factor_input');}
        $d=$this->d();$deadline=new Deadline($d[12]->ioMilliseconds());$operation=bin2hex(random_bytes(16));$state=$this->attempt($selector,$source,'prove','pending',$operation);if($state===null){return null;}$d=$this->d();$f=$state['flow'];$deadline->check('account.factor_expired');$status=$d[5]->status($f['slot_scope'],$f['slot_subject']);
        if($status['enabled']){$codes=$status['factor_id']===$f['enrollment_id']&&$d[5]->verifyBound($f['slot_scope'],$f['slot_subject'],$f['enrollment_id'],$code)?[]:null;}
        else{$codes=$d[5]->confirm($f['slot_scope'],$f['slot_subject'],$f['enrollment_id'],$code);}
        if($codes===null){return null;}$deadline->check('account.factor_expired');if($d[13]->now()<$f['issued_at']||$d[13]->now()>=$f['valid_until']){throw new StorageException('Prepared factor proof crossed its deadline.','account.factor_expired');}$u=$this->unit();$committed=false;$commitReady=false;
        try{$saved=$u->run(function()use($u,$state,$selector,$d):array{
            $fresh=$this->load($u,$selector,['pending']);if($fresh===null||$fresh['row']!==$state['row']){throw new StorageException('Factor proof changed.','account.factor_changed');}$f=$fresh['flow'];$status=$u->invoke([$d[5],'status'],[$f['slot_scope'],$f['slot_subject']],'account.factor_store');
            if($status['factor_id']!==$f['enrollment_id']||$status['pending']){throw new SecurityException('The isolated factor is no longer current.','account.factor_changed');}$f['state']='proven';$f['new_factor']=$f['enrollment_id'];return $this->save($u,$fresh,$f);
        },null,function(array $state)use($u,$source,$operation,&$commitReady):void{$this->check($u,$state,'prove',$source,$operation);$commitReady=true;},null,$deadline);$committed=true;$this->complete($saved,'prove',$source,$operation);return $codes;}
        catch(\Throwable $error){if($commitReady||$committed||$u->committed()){throw new StorageException('Factor proof committed but completion is unknown.','account.completion_unknown');}throw $error;}
    }
    private function review(array $state):FactorReplacementApproval
    {
        $d=$this->d();$f=$state['flow'];$selector=$state['row']['record_id'];$context=hash('sha256',self::json(['SoSecurity.Account.FactorReplacement.1',$d[1],$d[2],$d[3],$selector,$f['account'],$f['identity'],$f['old_binding'],$f['slot_scope'],$f['slot_subject'],$f['new_factor'],$f['valid_until']]));
        return new FactorReplacementApproval($context,$selector,$state['facts']['record'],$state['facts']['identity'],$state['facts']['slot'],$f['slot_scope'],$f['slot_subject'],$f['new_factor'],$f['valid_until']);
    }
    private function approvalRequestInternal(string $selector,string $source):?FactorReplacementApproval
    {
        self::id($selector);self::label($source);$u=$this->unit();$operation=bin2hex(random_bytes(16));$state=$u->run(function()use($u,$selector,$source,$operation):?array{$this->charge($u,'review','public',$source,$operation);$this->guard($u,'review','before',null,$selector);return $this->load($u,$selector,['proven']);},null,function(?array $state)use($u,$source,$operation):void{if($state!==null){$this->check($u,$state,'review',$source,$operation);}});return $state===null?null:$this->review($state);
    }
    private function approved(SqlTransaction $u,string $phase,FactorReplacementApproval $review,array $proof):bool {$d=$this->d();return $u->invoke($d[10],[$phase,$review,$proof],'account.factor_approval')===true;}
    private function confirmInternal(string $selector,string $source,array $proof):bool
    {
        self::id($selector);self::label($source);$keys=array_keys($proof);sort($keys);if($keys!==['code','type']||$proof['type']!=='approved'||!is_string($proof['code'])||$proof['code']===''||strlen($proof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$proof['code'])){throw new ValidationException('Use explicit independent strong factor approval.','account.factor_input');}
        $d=$this->d();$deadline=new Deadline($d[12]->ioMilliseconds());$operation=bin2hex(random_bytes(16));$state=$this->attempt($selector,$source,'confirm','proven',$operation);if($state===null){return false;}$review=$this->review($state);$deadline->check('account.factor_expired');$observed=$d[13]->now();
        try{$allowed=call_user_func($d[10],'verify',$review,$proof);}catch(\Throwable $error){throw new DependencyException('Independent factor approval unavailable.','account.factor_approval');}
        $deadline->check('account.factor_expired');$now=$d[13]->now();if($now<$observed||$now>=$review->expiresAt()){throw new StorageException('Independent factor approval crossed its deadline.','account.factor_expired');}if($allowed!==true){return false;}
        $u=$this->unit();$committed=false;$commitReady=false;
        try{$saved=$u->run(function()use($u,$state,$selector,$review,$proof,$d):?array{
            $fresh=$this->load($u,$selector,['proven']);if($fresh===null||$fresh['row']!==$state['row']){return null;}$this->guard($u,'confirm','replace',$fresh,$selector);if(!$this->approved($u,'current',$review,$proof)){throw new SecurityException('Factor approval is no longer current.','account.factor_denied');}
            $f=$fresh['flow'];$updated=$u->invoke($d[7],[$u,$fresh['facts'],$f['slot_scope'],$f['slot_subject'],$f['new_factor']],'account.factor_directory');$this->event($u,'factor_replaced',$fresh['facts'],$updated,$selector);
            $f['state']='consumed';$f['completed_account']=$updated['record']->fingerprint();$f['completed_identity']=$updated['identity']->fingerprint();$f['completed_binding']=$updated['slot']->binding();$fresh['facts']=$updated;return $this->save($u,$fresh,$f);
        },null,function(?array $state)use($u,$source,$operation,$review,$proof,&$commitReady):void{if($state!==null){$this->check($u,$state,'confirm',$source,$operation,'commit',$review,$proof);$commitReady=true;}},null,$deadline);
            if($saved===null){return false;}$committed=true;$this->complete($saved,'confirm',$source,$operation,$review,$proof);return true;
        }catch(\Throwable $error){if($commitReady||$committed||$u->committed()){throw new StorageException('Factor replacement committed but completion is unknown.','account.completion_unknown');}throw $error;}
    }
    private function complete(array $state,string $action,string $source,string $operation,?FactorReplacementApproval $review=null,array $proof=[]):void
    {
        $u=$this->unit();$u->run(function()use($u,$state,$action,$source,$operation,$review,$proof):void{
            $this->check($u,$state,$action,$source,$operation,'complete',$review,$proof);
        });
    }
    private function terminal(SqlTransaction $u,string $selector):?array
    {
        $l=$this->ledger($u);$l->checkpoint();$row=$l->read($selector);if($row===null){return null;}$f=$this->parse($row);$facts=$this->managementFacts($u,$f['subject']);
        return ['row'=>$row,'flow'=>$f,'facts'=>$facts,'checkpoint'=>$l->checkpoint()];
    }
    /** Cancellation/cleanup may outlive the original identity and deadline, but always require current management authority. */
    private function checkTerminal(SqlTransaction $u,array $state,string $action,string $source,string $operation,string $phase='commit'):void
    {
        $selector=$state['row']['record_id'];$this->charge($u,$action,'final',$source,$operation,$state);$this->guard($u,$action,$phase,$state,$selector);$l=$this->ledger($u);
        // Every phase, including post-commit verification, locks workflow before directory/account rows.
        $l->checkpoint();$l->read($selector);$fresh=$this->managementFacts($u,$state['flow']['subject']);
        if($l->checkpoint()!==$state['checkpoint']||$l->read($selector)!==$state['row']||$fresh['stamp']!==$state['facts']['stamp']){throw new StorageException('Factor cleanup authority or state changed.','account.factor_changed');}
    }
    /** Fence the SQL workflow first. Does not remove the current factor or change credentials. */
    private function cancelInternal(string $selector,string $source):bool
    {
        self::id($selector);self::label($source);$u=$this->unit();$operation=bin2hex(random_bytes(16));$ready=false;$committed=false;
        try{$state=$u->run(function()use($u,$selector,$source,$operation):?array{
            $this->charge($u,'cancel','public',$source,$operation);$this->guard($u,'cancel','before',null,$selector);$state=$this->terminal($u,$selector);if($state===null||in_array($state['flow']['state'],['consumed','cancelled'],true)){return null;}
            $this->guard($u,'cancel','current',$state,$selector);$f=$state['flow'];$f['state']='cancelled';$this->event($u,'factor_recovery_cancelled',$state['facts'],$state['facts'],$selector);return $this->save($u,$state,$f);
        },null,function(?array $state)use($u,$source,$operation,&$ready):void{if($state!==null){$this->checkTerminal($u,$state,'cancel',$source,$operation);$ready=true;}});
            if($state===null){return false;}$committed=true;$finish=$this->unit();$finish->run(function()use($finish,$state,$source,$operation):void{$this->checkTerminal($finish,$state,'cancel',$source,$operation,'complete');});return true;
        }catch(\Throwable $error){if($ready||$committed||$u->committed()){throw new StorageException('Factor cancellation completion is unknown.','account.completion_unknown');}throw $error;}
    }
    /** One signed workflow, at most one CAS deletion. Retain the signed tombstone for repeated cleanup and writer fencing. */
    private function cleanInternal(string $selector,string $source):array
    {
        self::id($selector);self::label($source);$operation=bin2hex(random_bytes(16));$d=$this->d();$u=$this->unit();
        $expired=$u->run(function()use($u,$selector,$source,$operation):bool{
            $this->charge($u,'clean','public',$source,$operation);$this->guard($u,'clean','before',null,$selector);$state=$this->terminal($u,$selector);if($state===null){return false;}$this->checkTerminal($u,$state,'clean',$source,$operation,'inspect');return !in_array($state['flow']['state'],['consumed','cancelled'],true)&&$state['flow']['valid_until']<=$u->now();
        });
        if($expired){$this->cancelInternal($selector,$source);}$u=$this->unit();$effectPossible=false;$ready=false;
        try{$result=$u->run(function()use($u,$selector,$source,$operation,$d,&$effectPossible):array{
            $this->guard($u,'clean','before',null,$selector);$state=$this->terminal($u,$selector);$counts=['examined'=>0,'absent'=>0,'conflicts'=>0,'active'=>0];if($state===null){return ['state'=>null,'counts'=>$counts];}$counts['examined']=1;$f=$state['flow'];
            if(!in_array($f['state'],['consumed','cancelled'],true)){return ['state'=>$state,'counts'=>$counts];}
            $old=$f['state']==='consumed';$scope=$old?$f['old_scope']:$f['slot_scope'];$subject=$old?$f['old_subject']:$f['slot_subject'];$generation=$old?$f['old_factor']:$f['enrollment_id'];$slot=$state['facts']['slot'];
            if(!$state['facts']['retired']&&$slot->slotScope()===$scope&&$slot->slotSubject()===$subject){$counts['active']=1;return ['state'=>$state,'counts'=>$counts];}
            // Hold the signed directory row lock across the bounded external CAS. Never use this operation in a retryable AtomicStore callback.
            $this->checkTerminal($u,$state,'clean',$source,$operation,'delete');$effectPossible=true;$removed=$u->invoke([$d[5],'revokeGeneration'],[$scope,$subject,$generation],'account.factor_store');
            $counts[$removed===true?'absent':'conflicts']=1;return ['state'=>$state,'counts'=>$counts];
        },null,function(array $result)use($u,$source,$operation,&$ready):void{if($result['state']!==null){$this->checkTerminal($u,$result['state'],'clean',$source,$operation);}$ready=true;});
            if($result['state']!==null){$finish=$this->unit();$finish->run(function()use($finish,$result,$source,$operation):void{$this->checkTerminal($finish,$result['state'],'clean',$source,$operation,'complete');});}return $result['counts'];
        }catch(\Throwable $error){if($effectPossible||$ready||$u->committed()){throw new StorageException('Inactive factor cleanup completion is unknown; retain its signed record.','account.completion_unknown');}throw $error;}
    }
    /** Explicitly close this worker epoch and retire ONE terminal, retained workflow. Other epochs require migration. */
    public function drainAndPurge(string $selector,string $source):array
    {
        self::id($selector);self::label($source);$d=$this->d();$fence=$d[15];
        if($fence===null){throw new ConfigurationException('Capacity purge requires a bound worker fence.','configuration.factor_fence');}
        $operation=bin2hex(random_bytes(16));$u=$this->unit();
        $initial=$u->run(function()use($u,$selector,$source,$operation):?array{
            $this->charge($u,'purge','public',$source,$operation);$this->guard($u,'purge','before',null,$selector);$state=$this->terminal($u,$selector);
            if($state!==null){$this->checkTerminal($u,$state,'purge',$source,$operation,'inspect');}return $state;
        });
        $counts=['examined'=>$initial===null?0:1,'removed'=>0,'absent'=>0,'conflicts'=>0,'active'=>0];
        if($initial===null||$initial['row']['retire_at']>$d[13]->now()){return $counts;}
        // This authority check executes while EX is held but BEFORE the permanent close is written.
        return $fence->drain(function()use($selector,$source,$operation,$counts):array{
            return $this->purgeClosed($selector,$source,$operation,$counts);
        },function()use($initial,$selector,$source,$operation):bool{
            $u=$this->unit();$u->run(function()use($u,$initial,$selector,$source,$operation):void{
                $state=$this->terminal($u,$selector);
                if($state===null||$state['row']!==$initial['row']||$state['facts']['stamp']!==$initial['facts']['stamp']||$state['row']['retire_at']>$u->now()){throw new StorageException('Purge selection changed before drain.','account.factor_changed');}
                $this->checkTerminal($u,$state,'purge',$source,$operation,'authorize');
            });return true;
        });
    }
    private function purgeClosed(string $selector,string $source,string $operation,array $counts):array
    {
        $d=$this->d();$probe=$this->unit();$pending=$probe->run(function()use($probe,$selector):?array{return $this->terminal($probe,$selector);});
        if($pending!==null&&!in_array($pending['flow']['state'],['consumed','cancelled'],true)){
            if($pending['row']['retire_at']>$d[13]->now()||$pending['flow']['valid_until']>$d[13]->now()){throw new StorageException('Pending flow retention has not elapsed.','account.factor_changed');}
            $this->cancelInternal($selector,$source);
        }
        $u=$this->unit();$effectPossible=false;$ready=false;
        try{
            $result=$u->run(function()use($u,$selector,$source,$operation,$counts,$d,&$effectPossible):array{
                $this->guard($u,'purge','before',null,$selector);$state=$this->terminal($u,$selector);
                if($state===null){return ['state'=>null,'counts'=>$counts];}
                $f=$state['flow'];
                if(!in_array($f['state'],['consumed','cancelled'],true)||$state['row']['retire_at']>$u->now()){throw new StorageException('Only retained terminal flows may be purged.','account.factor_changed');}
                $old=$f['state']==='consumed';$scope=$old?$f['old_scope']:$f['slot_scope'];$subject=$old?$f['old_subject']:$f['slot_subject'];$generation=$old?$f['old_factor']:$f['enrollment_id'];$slot=$state['facts']['slot'];
                if(!$state['facts']['retired']&&$slot->slotScope()===$scope&&$slot->slotSubject()===$subject){$counts['active']=1;return ['state'=>$state,'counts'=>$counts];}
                $this->checkTerminal($u,$state,'purge',$source,$operation,'delete');$effectPossible=true;
                if($u->invoke([$d[5],$d[5]->isManaged()?'revokeGenerationClosed':'revokeGeneration'],$d[5]->isManaged()?[$d[15],$scope,$subject,$generation,function()use($u,$state,$source,$operation):bool{$this->checkTerminal($u,$state,'purge',$source,$operation,'physical');return true;}]:[$scope,$subject,$generation],'account.factor_store')!==true){$counts['conflicts']=1;return ['state'=>$state,'counts'=>$counts];}
                $counts['absent']=1;$this->checkTerminal($u,$state,'purge',$source,$operation,'remove');
                $this->event($u,'factor_recovery_purged',$state['facts'],$state['facts'],$selector);
                $this->checkTerminal($u,$state,'purge',$source,$operation,'audit');
                $l=$this->ledger($u);$cursorId=$this->cursor($f['subject']);$cursor=$l->read($cursorId);$pointer=$this->pointer($cursor,$f['subject']);
                $selected=[$selector=>$state['row']['revision']];
                if($pointer===$selector){
                    if($cursor['retire_at']>$u->now()){throw new StorageException('Current flow cursor retention has not elapsed.','account.factor_changed');}
                    $selected[$cursorId]=$cursor['revision'];
                }
                $counts['removed']=$l->remove($selected);
                return ['state'=>$state,'counts'=>$counts,'checkpoint'=>$l->checkpoint(),'cursor_id'=>$cursorId,'cursor'=>$l->read($cursorId)];
            },null,function(array $result)use($u,$source,$operation,&$ready):void{
                if($result['state']!==null){$this->checkPurged($u,$result,$source,$operation,'commit');}$ready=true;
            });
            if($result['state']!==null){$finish=$this->unit();$finish->run(function()use($finish,$result,$source,$operation):void{$this->checkPurged($finish,$result,$source,$operation,'complete');});}
            return $result['counts'];
        }catch(\Throwable $error){
            if($effectPossible||$ready||$u->committed()){throw new StorageException('Purge completion is unknown; the epoch remains closed.','account.completion_unknown');}throw $error;
        }
    }
    private function checkPurged(SqlTransaction $u,array $result,string $source,string $operation,string $phase):void
    {
        $state=$result['state'];
        if($result['counts']['removed']===0){$this->checkTerminal($u,$state,'purge',$source,$operation,$phase);return;}
        $selector=$state['row']['record_id'];$this->charge($u,'purge','final',$source,$operation,$state);$this->guard($u,'purge',$phase,$state,$selector);$l=$this->ledger($u);
        // Same lock order as all flow operations: recovery root/row, then directory/account.
        if($l->checkpoint()!==$result['checkpoint']||$l->read($selector)!==null||$l->read($result['cursor_id'])!==$result['cursor']||$this->managementFacts($u,$state['flow']['subject'])['stamp']!==$state['facts']['stamp']){throw new StorageException('Purge state changed before completion.','account.factor_changed');}
        if($l->checkpoint()!==$result['checkpoint']||$l->read($selector)!==null||$l->read($result['cursor_id'])!==$result['cursor']){throw new StorageException('Purge history changed during authority inspection.','account.factor_changed');}
    }
    private function workerLedger(SqlTransaction $u,LocalEpochFence $fence):Ledger
    {
        $d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[12],2,$fence->binding());
    }
    private function workerOwner():string {$d=$this->d();return hash('sha256',self::json(['SoSecurity.Account.WorkerRotation.Owner.1',$d[1],$d[2]]));}
    private function workerHistory(SqlTransaction $u):Ledger
    {
        $d=$this->d();$options=$d[12]->options();$options['maximum_entries']=1000;
        return new Ledger($u,'account-factor-worker-receipts:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],new Policy($options));
    }
    private function workerHistoryState(SqlTransaction $u,string $operation,bool $optional=false):array
    {
        $l=$this->workerHistory($u);
        try{return ['checkpoint'=>$l->checkpoint(),'receipt'=>$l->read($operation)];}
        catch(StorageException $error){if(!$optional||$error->reason()!=='account.uninitialized'){throw $error;}$l->capacity(1,true);return ['checkpoint'=>null,'receipt'=>null];}
    }
    private function workerApproval(SqlTransaction $u,callable $approval,string $phase,array $context):void
    {
        if($u->invoke($approval,[$phase,$context],'account.worker_approval')!==true){throw new SecurityException('Current independent worker rotation authority required.','account.worker_denied');}
    }
    /** A valid next root alone is insufficient: require the exact same-transaction transition receipt. */
    private function workerState(SqlTransaction $u,LocalEpochFence $next,string $expected,string $operation,string $payload):array
    {
        $old=$this->ledger($u);$new=$this->workerLedger($u,$next);
        try{$root=$old->checkpoint();}
        catch(ConfigurationException $error){
            if($error->reason()!=='configuration.account_state'){throw $error;}
            $root=$new->checkpoint();$history=$this->workerHistoryState($u,$operation);$receipt=$history['receipt'];
            if($receipt===null||$receipt['kind']!=='budget'||$receipt['owner']!==$this->workerOwner()||$receipt['payload']!==$payload){throw new StorageException('No matching worker transition receipt.','account.worker_changed');}
            return ['changed'=>false,'checkpoint'=>$root,'receipt'=>$receipt,'receipt_checkpoint'=>$history['checkpoint']];
        }
        $history=$this->workerHistoryState($u,$operation,true);
        if(!hash_equals($expected,Ledger::digest($root))||$history['receipt']!==null){throw new StorageException('Trusted worker transition state changed.','account.worker_changed');}
        $this->workerHistory($u)->capacity(1,true);return ['changed'=>true,'checkpoint'=>$root,'receipt'=>null,'receipt_checkpoint'=>$history['checkpoint']];
    }
    /** Explicit global management operation; preserve the account/directory epoch and all existing workflows. */
    public function rotateWorkers(LocalEpochFence $next,string $trustedRoot,string $source,callable $approval,callable $audit):array
    {
        self::id($trustedRoot);self::label($source);$d=$this->d();$old=$d[15];
        if($old===null||!$next->matches($d[1],$d[2],$d[3])||$old->binding()===$next->binding()){throw new ConfigurationException('Use a distinct matching worker authority.','configuration.factor_fence');}
        $context=['format'=>1,'purpose'=>'factor_worker_rotation','site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'from'=>$old->binding(),'to'=>$next->binding(),'root'=>$trustedRoot];$payload=self::json($context);$operation=hash('sha256','SoSecurity.Account.WorkerRotation.1.'.$payload);
        // Only the active root owner can enter the operation; no locks are retained across this preflight.
        $u=$this->unit();$u->run(function()use($u,$next,$trustedRoot,$operation,$payload,$source,$approval,$context):void{
            $this->charge($u,'worker_rotate','public',$source,$operation);$this->workerState($u,$next,$trustedRoot,$operation,$payload);$this->guard($u,'worker_rotate','before');$this->workerState($u,$next,$trustedRoot,$operation,$payload);$this->workerApproval($u,$approval,'inspect',$context);$this->workerState($u,$next,$trustedRoot,$operation,$payload);
        });
        // Next SH then old EX: the next authority cannot close during a committed handoff.
        return $next->work(function()use($next,$old,$trustedRoot,$operation,$payload,$source,$approval,$audit,$context):array{
            return $old->drain(function()use($next,$trustedRoot,$operation,$payload,$source,$approval,$audit,$context):array{
                return $this->rotateClosed($next,$trustedRoot,$operation,$payload,$source,$approval,$audit,$context);
            },function()use($next,$trustedRoot,$operation,$payload,$source,$approval,$context):bool{
                $u=$this->unit();$u->run(function()use($u,$next,$trustedRoot,$operation,$payload,$source,$approval,$context):void{
                    $state=$this->workerState($u,$next,$trustedRoot,$operation,$payload);$this->charge($u,'worker_rotate','final',$source,$operation);$this->workerApproval($u,$approval,'authorize',$context);$this->guard($u,'worker_rotate','authorize');
                    $fresh=$this->workerState($u,$next,$trustedRoot,$operation,$payload);if($state!==$fresh){throw new StorageException('Worker transition changed during approval.','account.worker_changed');}
                    if($state['changed']){$this->ledger($u)->verifyBodies();if($state['receipt_checkpoint']!==null){$this->workerHistory($u)->verifyBodies();}}
                });return true;
            });
        });
    }
    private function rotateClosed(LocalEpochFence $next,string $expected,string $operation,string $payload,string $source,callable $approval,callable $audit,array $context):array
    {
        $d=$this->d();$u=$this->unit();$possible=false;$ready=false;
        try{
            $result=$u->run(function()use($u,$next,$expected,$operation,$payload,$source,$approval,$audit,$context,$d,&$possible):array{
                $state=$this->workerState($u,$next,$expected,$operation,$payload);$this->charge($u,'worker_rotate','final',$source,$operation);$this->workerApproval($u,$approval,'current',$context);$this->guard($u,'worker_rotate','apply');
                if($state!==$this->workerState($u,$next,$expected,$operation,$payload)){throw new StorageException('Worker transition changed before application.','account.worker_changed');}
                if(!$state['changed']){return $state;}
                $l=$this->ledger($u);$history=$this->workerHistory($u);$possible=true;$history->initialize();$history->put($operation,$this->workerOwner(),'budget',$payload,$u->now()+$d[12]->lifetime('account_activated'));
                $after=$l->rebindAuthority($expected,$next->binding());
                if($u->invoke($audit,[$context,$operation,$state['checkpoint'],$after],'account.worker_audit')!==true){throw new StorageException('Same-transaction worker audit required.','account.worker_audit');}
                return ['changed'=>true,'checkpoint'=>$after,'receipt'=>$history->read($operation),'receipt_checkpoint'=>$history->checkpoint()];
            },null,function(array $result)use($u,$next,$operation,$payload,$source,$approval,$context,&$ready):void{
                $this->checkWorkerResult($u,$next,$result,$operation,$payload,$source,$approval,$context,'commit',true);$ready=true;
            });
            $finish=$this->unit();$current=$finish->run(function()use($finish,$next,$result,$operation,$payload,$source,$approval,$context):array{
                return $this->checkWorkerResult($finish,$next,$result,$operation,$payload,$source,$approval,$context,'complete',false);
            });
            return ['changed'=>$result['changed'],'operation'=>$operation,'checkpoint'=>Ledger::digest($current),'entries'=>$current['entries']];
        }catch(\Throwable $error){if($possible||$ready||$u->committed()){throw new StorageException('Worker rotation completion is unknown; never reopen the old authority.','account.completion_unknown');}throw $error;}
    }
    private function checkWorkerResult(SqlTransaction $u,LocalEpochFence $next,array $result,string $operation,string $payload,string $source,callable $approval,array $context,string $phase,bool $exact):array
    {
        $l=$this->workerLedger($u,$next);$actorRoot=$l->checkpoint();$this->charge($u,'worker_rotate','final',$source,$operation);$this->workerApproval($u,$approval,$phase,$context);$this->guard($u,'worker_rotate',$phase);$root=$l->verifyBodies();if($root!==$actorRoot){throw new StorageException('Worker root changed during current actor checks.','account.worker_changed');}$history=$this->workerHistory($u);$historyRoot=$history->verifyBodies();$receipt=$history->read($operation);
        if(($exact&&($root!==$result['checkpoint']||$historyRoot!==$result['receipt_checkpoint']))||$receipt===null||$receipt!==$result['receipt']||$receipt['payload']!==$payload||$receipt['kind']!=='budget'||$receipt['owner']!==$this->workerOwner()){throw new StorageException('Worker transition receipt or history changed.','account.worker_changed');}
        if($l->checkpoint()!==$root||$history->checkpoint()!==$historyRoot||$history->read($operation)!==$receipt){throw new StorageException('Worker transition changed during completion.','account.worker_changed');}return $root;
    }
    private static function receiptMode(string $mode,int $limit,string $after):void
    {
        if(!in_array($mode,['clean','rotate'],true)||$limit<1||$limit>50){throw new ConfigurationException('Use a worker receipt page of 1-50 records.','configuration.worker_receipts');}if($after!==''){self::id($after);}
    }
    private function receiptData(array $row):array
    {
        $d=$this->d();$c=json_decode($row['payload'],true,3);$fields=['format','purpose','site','scope','epoch','from','to','root'];
        if($row['kind']!=='budget'||$row['owner']!==$this->workerOwner()||!is_array($c)||array_keys($c)!==$fields||$c['format']!==1||$c['purpose']!=='factor_worker_rotation'||$c['site']!==$d[1]||$c['scope']!==$d[2]||$c['epoch']!==$d[3]){throw new StorageException('Invalid worker transition receipt.','account.worker_receipt_corrupt');}
        foreach(['from','to','root'] as $field){if(!is_string($c[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$c[$field])){throw new StorageException('Invalid worker transition receipt.','account.worker_receipt_corrupt');}}
        if($c['from']===$c['to']||self::json($c)!==$row['payload']||hash('sha256','SoSecurity.Account.WorkerRotation.1.'.$row['payload'])!==$row['record_id']||$row['retire_at']-$row['created_at']>$d[12]->lifetime('account_activated')){throw new StorageException('Invalid worker transition receipt.','account.worker_receipt_corrupt');}return $c;
    }
    private function receiptFrame(SqlTransaction $u,string $mode,int $limit,string $after):array
    {
        $d=$this->d();if($d[15]===null){throw new ConfigurationException('Worker receipt maintenance requires an active fence.','configuration.factor_fence');}
        // Always take the live recovery root before the receipt root, as in rotateWorkers().
        $flow=$this->ledger($u)->checkpoint();$l=$this->workerHistory($u);$history=$l->checkpointIfInitialized();$rows=[];$actions=[];$protected=0;$metadata=[];
        foreach($history===null?[]:$l->bodyPage($limit,$after) as $row){
            $c=$this->receiptData($row);$id=$row['record_id'];$rows[$id]=$row;$header=$row;unset($header['payload']);$metadata[$id]=$header;$incoming=$c['to']===$d[15]->binding();if($incoming){++$protected;}
            if($mode==='clean'?(!$incoming&&$row['retire_at']<=$u->now()):$row['seal_key']!==$l->currentKeyId()){$actions[$id]=$row['revision'];}
        }
        $rootRotation=$mode==='rotate'&&$history!==null&&$history['seal_key']!==$l->currentKeyId();
        $context=['format'=>1,'purpose'=>'factor_worker_receipt_'.$mode,'site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[15]->binding(),'limit'=>$limit,'after'=>$after,'history'=>$history===null?hash('sha256','SoSecurity.Account.WorkerReceipts.Uninitialized.1'):Ledger::digest($history),'selection'=>hash('sha256','SoSecurity.Account.WorkerReceipts.Selection.1.'.self::json([$metadata,$actions,$rootRotation])),'root_key'=>$l->currentKeyId()];
        $ids=array_keys($rows);$count=count($ids);$next=$count===$limit?$ids[$count-1]:'';
        return ['mode'=>$mode,'context'=>$context,'flow'=>$flow,'history'=>$history,'rows'=>$rows,'actions'=>$actions,'root_rotation'=>$rootRotation,'counts'=>['examined'=>$count,'eligible'=>count($actions),'protected'=>$protected,'root_rotation'=>$rootRotation,'next'=>$next,'complete'=>$count<$limit]];
    }
    /** Review is data only. Execution rebuilds this exact page and requires independent current approval. */
    public function reviewWorkerReceipts(string $mode,string $source,int $limit=20,string $after=''):array
    {
        self::receiptMode($mode,$limit,$after);self::label($source);$d=$this->d();if($d[15]===null){throw new ConfigurationException('Worker receipt maintenance requires a fence.','configuration.factor_fence');}
        return $this->withWork(function()use($mode,$source,$limit,$after):array{
            $u=$this->unit();$operation=bin2hex(random_bytes(16));$frame=$u->run(function()use($u,$mode,$source,$limit,$after,$operation):array{
                $this->charge($u,'worker_receipt_'.$mode,'public',$source,$operation);$this->guard($u,'worker_receipt_'.$mode,'review');return $this->receiptFrame($u,$mode,$limit,$after);
            },null,function(array $frame)use($u,$mode,$source,$limit,$after,$operation):void{
                $this->charge($u,'worker_receipt_'.$mode,'final',$source,$operation);$this->guard($u,'worker_receipt_'.$mode,'review_complete');$fresh=$this->receiptFrame($u,$mode,$limit,$after);if($fresh!==$frame){throw new StorageException('Worker receipt review changed before return.','account.worker_changed');}
            });return ['context'=>$frame['context']]+$frame['counts'];
        });
    }
    private function receiptContext(array $context):array
    {
        $fields=['format','purpose','site','scope','epoch','authority','limit','after','history','selection','root_key'];
        if(count($context)!==count($fields)||array_diff(array_keys($context),$fields)||$context['format']!==1||!in_array($context['purpose'],['factor_worker_receipt_clean','factor_worker_receipt_rotate'],true)){throw new ValidationException('Use a complete worker receipt review.','account.worker_input');}
        foreach(['site','scope'] as $field){if(!is_string($context[$field])){throw new ValidationException('Use bounded worker receipt review fields.','account.worker_input');}self::label($context[$field]);}
        foreach(['epoch','authority','history','selection'] as $field){if(!is_string($context[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$context[$field])){throw new ValidationException('Use exact worker receipt review digests.','account.worker_input');}}
        if(!is_int($context['limit'])||!is_string($context['after'])||!is_string($context['root_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$context['root_key'])){throw new ValidationException('Use typed worker receipt review fields.','account.worker_input');}
        self::receiptMode($context['purpose']==='factor_worker_receipt_clean'?'clean':'rotate',$context['limit'],$context['after']);$ordered=[];foreach($fields as $field){$ordered[$field]=$context[$field];}return $ordered;
    }
    /** The old review is rejected after a state change, including an acknowledged/unknown COMMIT. Never follows a new page implicitly. */
    public function maintainWorkerReceipts(array $context,string $source,callable $approval,callable $audit):array
    {
        $context=$this->receiptContext($context);self::label($source);$d=$this->d();if($d[15]===null){throw new ConfigurationException('Worker receipt maintenance requires a fence.','configuration.factor_fence');}
        return $this->withWork(function()use($context,$source,$approval,$audit):array{
            $mode=$context['purpose']==='factor_worker_receipt_clean'?'clean':'rotate';$operation=hash('sha256','SoSecurity.Account.WorkerReceipts.Maintenance.1.'.self::json($context));$u=$this->unit();$possible=false;$ready=false;
            try{
                $result=$u->run(function()use($u,$mode,$context,$source,$approval,$audit,$operation,&$possible):array{
                    $this->charge($u,'worker_receipt_'.$mode,'public',$source,$operation);$this->guard($u,'worker_receipt_'.$mode,'before');$frame=$this->receiptFrame($u,$mode,$context['limit'],$context['after']);
                    if($frame['context']!==$context){throw new StorageException('Worker receipt review is stale.','account.worker_changed');}
                    $this->workerApproval($u,$approval,'authorize',$context);$this->checkReceiptMaintenance($u,$frame,$frame['rows'],$frame['history'],$source,$operation,$approval,'current',true,false);
                    if($this->receiptFrame($u,$mode,$context['limit'],$context['after'])['context']!==$context){throw new StorageException('Worker receipt selection changed.','account.worker_changed');}
                    $l=$this->workerHistory($u);$counts=$frame['counts'];$counts['removed']=0;$counts['resealed']=0;$counts['root_rotated']=false;unset($counts['root_rotation'],$counts['eligible']);
                    if($frame['history']!==null){
                        if($mode==='clean'&&$frame['actions']){$possible=true;$counts['removed']=$l->remove($frame['actions']);}
                        if($mode==='rotate'){
                            $possible=$frame['root_rotation']||count($frame['actions'])>0;$counts['root_rotated']=$l->rotateRoot();if($frame['actions']){$counts['resealed']=$l->reseal($frame['actions']);}
                        }
                    }
                    $ids=array_keys($frame['rows']);$rows=$ids?$l->readMany($ids):[];$history=$l->checkpointIfInitialized();
                    if($possible&&$u->invoke($audit,[$context,$operation,$counts],'account.worker_audit')!==true){throw new StorageException('Same-transaction worker receipt audit required.','account.worker_audit');}
                    return ['frame'=>$frame,'rows'=>$rows,'history'=>$history,'counts'=>$counts+['operation'=>$operation]];
                },null,function(array $result)use($u,$source,$operation,$approval,&$ready):void{
                    $this->checkReceiptMaintenance($u,$result['frame'],$result['rows'],$result['history'],$source,$operation,$approval,'commit',true,true);$ready=true;
                });
                $finish=$this->unit();$finish->run(function()use($finish,$result,$source,$operation,$approval):void{$this->checkReceiptMaintenance($finish,$result['frame'],$result['rows'],$result['history'],$source,$operation,$approval,'complete',false,true);});return $result['counts'];
            }catch(\Throwable $error){if($possible||$ready||$u->committed()){throw new StorageException('Worker receipt maintenance completion is unknown; inspect the durable audit and obtain a fresh review.','account.completion_unknown');}throw $error;}
        });
    }
    private function checkReceiptMaintenance(SqlTransaction $u,array $frame,array $rows,?array $history,string $source,string $operation,callable $approval,string $phase,bool $exact,bool $bodies):void
    {
        $this->charge($u,'worker_receipt_'.$frame['mode'],'final',$source,$operation);$this->workerApproval($u,$approval,$phase,$frame['context']);$this->guard($u,'worker_receipt_'.$frame['mode'],$phase);$flow=$this->ledger($u)->checkpoint();$l=$this->workerHistory($u);$current=$l->checkpointIfInitialized();
        if($exact&&($flow!==$frame['flow']||$current!==$history)){throw new StorageException('Worker maintenance roots changed.','account.worker_changed');}
        $ids=array_keys($frame['rows']);if(($ids?$l->readMany($ids):[])!==$rows){throw new StorageException('Worker maintenance rows changed.','account.worker_changed');}
        if($bodies&&$current!==null&&$l->verifyBodies()!==$current){throw new StorageException('Worker maintenance bodies changed.','account.worker_changed');}
        if($this->ledger($u)->checkpoint()!==$flow||$l->checkpointIfInitialized()!==$current){throw new StorageException('Worker maintenance changed during verification.','account.worker_changed');}
    }
    public function __debugInfo():array {return ['factor_recovery'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload factor recovery configuration.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload factor recovery configuration.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Factor recovery is immutable.','configuration.immutable');}
}
