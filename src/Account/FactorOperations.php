<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;

/** Candidate normal management. SQL intent precedes external effects; completed code output is never replayed. */
final class FactorOperations
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $factors,LocalEpochFence $fence,callable $facts,callable $mutate,callable $authority,callable $budgets,callable $approval,callable $events,Policy $policy,Clock $clock)
    {
        self::label($site);self::label($scope);self::id($epoch);if(!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use the matching management fence.','configuration.factor_operations');}
        new SqlTransaction($connection,$clock,$policy->ioMilliseconds());$factors->validateConfiguration($clock,true);
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$factors,$fence,$facts,$mutate,$authority,$budgets,$approval,$events,$policy,$clock):array{return [$connection,$site,$scope,$epoch,$keys,$factors,$fence,$facts,$mutate,$authority,$budgets,$approval,$events,$policy,$clock];};
    }
    private function d():array {return ($this->dependencies)();}
    private function unit():SqlTransaction {$d=$this->d();return new SqlTransaction($d[0],$d[14],$d[13]->ioMilliseconds());}
    private function ledger(SqlTransaction $u):Ledger {$d=$this->d();return new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[13],2,$d[6]->binding());}
    private static function label(string $v):void {Guard::label($v);if(preg_match('//u',$v)!==1){throw new ValidationException('Use bounded UTF-8 management labels.','account.factor_input');}}
    private static function id(string $v):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$v)){throw new ValidationException('Use exact management identifiers.','account.factor_input');}}
    private static function json(array $v):string {return json_encode($v,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    private function facts(SqlTransaction $u,string $subject):array {$d=$this->d();return $u->invoke($d[7],[$u,$subject],'account.factor_directory');}
    private function guard(SqlTransaction $u,string $action,string $phase,?array $facts=null,?array $review=null):void
    {
        $d=$this->d();if($u->invoke($d[9],[$action,$phase,$d[2],$facts['record']??null,$review],'account.factor_authority')!==true){throw new SecurityException('Current normal factor authority required.','account.factor_denied');}
    }
    private function budget(SqlTransaction $u,string $action,string $phase,string $source,string $operation):void {$d=$this->d();if($u->invoke($d[10],[$action,$phase,$source,$operation],'account.factor_budget')!==true){throw new SecurityException('Normal factor management budget denied.','account.factor_budget');}}
    /** Request budget and current authority precede schema/history reads. Ownership probes may run first. */
    private function request(SqlTransaction $u,string $action,string $phase,string $source,string $operation,?array $review=null):bool
    {
        $this->budget($u,$action,'public',$source,$operation);$this->guard($u,$action,$phase,null,$review);return true;
    }
    /** Preserve a refused request's domain error: SqlTransaction deliberately masks thrown preflight callbacks. */
    private function requested(SqlTransaction $u,callable $body,callable $request,?callable $beforeCommit=null)
    {
        $rejection=null;$result=$u->run($body,static function()use($request,&$rejection):bool{
            try{return $request()===true;}catch(\Throwable $error){$rejection=$error;return false;}
        },$beforeCommit);if($rejection!==null){throw $rejection;}return $result;
    }
    private function approved(SqlTransaction $u,string $phase,array $review,array $proof,array $facts):void
    {
        $d=$this->d();if($u->invoke($d[11],[$phase,$review,$proof,$facts['record'],$facts['identity']],'account.factor_approval')!==true){throw new SecurityException('Current exact management approval required.','account.factor_denied');}
    }
    private function owner(string $subject):string {return hash('sha256','SoSecurity.Account.FactorOperations.Owner.1.'.$subject);}
    private function check(SqlTransaction $u,array $review,string $source,array $proof,array $expected,string $phase,?array $row=null,?array $root=null):void
    {
        $this->budget($u,$review['action'],'final',$source,$review['operation']);$this->approved($u,$phase,$review,$proof,$expected);$this->guard($u,$review['action'],$phase,$expected,$review);
        $fresh=$this->facts($u,$review['subject']);if($fresh['stamp']!==$expected['stamp']||$fresh['row']!==$expected['row']||$fresh['checkpoint']!==$expected['checkpoint']||$u->now()>=$review['expires']){throw new StorageException('Management account or approval deadline changed.','account.factor_changed');}
        if($row!==null){$l=$this->ledger($u);if($l->checkpoint()!==$root||$l->read($review['operation'])!==$row){throw new StorageException('Management intent changed.','account.factor_changed');}}
    }
    public function initialize():void
    {
        $d=$this->d();$d[6]->work(function():void{$u=$this->unit();$this->requested($u,function()use($u):void{$this->ledger($u)->initialize();},function()use($u):bool{$this->guard($u,'initialize','before');return true;},function()use($u):void{$this->guard($u,'initialize','commit');$this->ledger($u)->checkpoint();});});
    }
    /** Signed short-lived review. Its signature binds server facts, purpose, authority, expiry and operation ID, never grants approval. */
    public function review(string $action,string $subject,string $source):array
    {
        if(!in_array($action,['disable','regenerate','reencrypt','enroll'],true)){throw new ValidationException('Use an explicit factor management action.','account.factor_input');}self::label($subject);self::label($source);$d=$this->d();
        return $d[6]->work(function()use($d,$action,$subject,$source):array{$u=$this->unit();$operation=bin2hex(random_bytes(32));$state=$this->requested($u,function()use($u,$d,$action,$subject,$operation):array{
            $l=$this->ledger($u);$root=$l->checkpoint();$facts=$this->facts($u,$subject);if(($action==='enroll')===$facts['slot']->enabled()){throw new SecurityException('Use enrollment only for an empty managed directory.','account.factor_unproven');}
            $review=['format'=>1,'purpose'=>'factor_management','site'=>$d[1],'scope'=>$d[2],'epoch'=>$d[3],'authority'=>$d[6]->binding(),'action'=>$action,'subject'=>$subject,'operation'=>$operation,'stamp'=>$facts['stamp'],'issued'=>$u->now(),'expires'=>$u->now()+min(300,$d[13]->lifetime('recover_account')),'key'=>$d[4]->currentId()];
            if($action==='enroll'){$review['target_scope']='factor-enrollment:'.hash('sha256',self::json([$d[1],$d[2],$d[3],$operation]));$review['target_subject']=$operation;$review['target_factor']=bin2hex(random_bytes(16));}
            $review['seal']=bin2hex($d[4]->sign('SoSecurity.Account.FactorOperations.Review.1.'.self::json($review)));return ['review'=>$review,'facts'=>$facts,'root'=>$root];
        },function()use($u,$action,$source,$operation):bool{return $this->request($u,$action,'review',$source,$operation);},function(array $state)use($u,$action,$source,$operation):void{$this->budget($u,$action,'final',$source,$operation);$this->guard($u,$action,'review_complete',$state['facts'],$state['review']);$fresh=$this->facts($u,$state['review']['subject']);if($fresh['stamp']!==$state['facts']['stamp']||$this->ledger($u)->checkpoint()!==$state['root']){throw new StorageException('Management review changed.','account.factor_changed');}});return $state['review'];});
    }
    private function reviewInput(array $v,bool $historical=false):array
    {
        $fields=['format','purpose','site','scope','epoch','authority','action','subject','operation','stamp','issued','expires','key'];if(($v['action']??null)==='enroll'){$fields=array_merge($fields,['target_scope','target_subject','target_factor']);}$fields[]='seal';$keys=array_keys($v);sort($keys);$expected=$fields;sort($expected);if($keys!==$expected||$v['format']!==1||$v['purpose']!=='factor_management'||!is_int($v['issued'])||!is_int($v['expires'])||$v['issued']<0||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>300){throw new ValidationException('Invalid management review.','account.factor_input');}
        foreach(['site','scope','subject'] as $k){if(!is_string($v[$k])){throw new ValidationException('Invalid management label.','account.factor_input');}self::label($v[$k]);}
        foreach(['epoch','authority','operation','stamp','seal'] as $k){if(!is_string($v[$k])){throw new ValidationException('Invalid management identifier.','account.factor_input');}self::id($v[$k]);}
        if(!is_string($v['action'])||!in_array($v['action'],['disable','regenerate','reencrypt','enroll'],true)||!is_string($v['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])){throw new ValidationException('Invalid management action or key.','account.factor_input');}
        if($v['action']==='enroll'){
            foreach(['target_scope','target_subject','target_factor'] as $k){if(!is_string($v[$k])){throw new ValidationException('Invalid reserved enrollment target.','account.factor_input');}}
            if($v['target_scope']!=='factor-enrollment:'.hash('sha256',self::json([$v['site'],$v['scope'],$v['epoch'],$v['operation']]))||$v['target_subject']!==$v['operation']||!preg_match('/\A[a-f0-9]{32}\z/D',$v['target_factor'])){throw new ValidationException('Use the exact reserved enrollment target.','account.factor_input');}
        }
        $ordered=[];foreach($fields as $k){$ordered[$k]=$v[$k];}$v=$ordered;$d=$this->d();$seal=$v['seal'];unset($v['seal']);
        if($v['site']!==$d[1]||$v['scope']!==$d[2]||$v['epoch']!==$d[3]||(!$historical&&($v['authority']!==$d[6]->binding()||!$d[4]->verify($v['key'],'SoSecurity.Account.FactorOperations.Review.1.'.self::json($v),hex2bin($seal))))){throw new SecurityException('Management review cannot be authenticated.','account.factor_denied');}return $v+['seal'=>$seal];
    }
    private static function proofs(string $action,array $proof,array $factor):void
    {
        $keys=array_keys($proof);sort($keys);if($keys!==['code','type']||$proof['type']!=='approved'||!is_string($proof['code'])||$proof['code']===''||strlen($proof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$proof['code'])){throw new ValidationException('Use explicit bounded management approval.','account.factor_input');}
        if(in_array($action,['reencrypt','enroll'],true)){if($factor!==[]){throw new ValidationException('Re-encryption takes no plaintext factor proof.','account.factor_input');}return;}
        $keys=array_keys($factor);sort($keys);if($keys!==['code','type']||!in_array($factor['type'],$action==='disable'?['totp','recovery']:['totp'],true)||!is_string($factor['code'])||!preg_match($factor['type']==='totp'?'/\A[0-9]{6,8}\z/D':'/\A[a-f0-9]{8}(?:-[a-f0-9]{8}){3}\z/D',$factor['code'])){throw new ValidationException('Use a current bounded factor proof.','account.factor_input');}
    }
    private function event(SqlTransaction $u,string $type,array $review,array $before,array $after):void
    {
        $d=$this->d();if($u->invoke($d[12],[$type,$d[2],$before['record'],$after['record'],$review['operation'],$review],'account.factor_event')!==true){throw new StorageException('A durable same-PDO management notification is required.','account.factor_event');}
    }
    private function intent(SqlTransaction $u,array $review,array $facts,string $state,?array $old=null,?array $target=null,?int $attempts=null):array
    {
        $l=$this->ledger($u);$slot=$old===null?($target??['binding'=>$facts['slot']->binding(),'scope'=>$facts['slot']->slotScope(),'subject'=>$facts['slot']->slotSubject(),'factor'=>$facts['slot']->factorId()]):$this->parse($old)['slot'];$body=['format'=>1,'purpose'=>$review['action']==='enroll'?'factor_enrollment':'factor_operation','review'=>$review,'state'=>$state,'after'=>$facts['stamp'],'slot'=>$slot];if($review['action']==='enroll'){$body['attempts']=$attempts??($old===null?0:$this->parse($old)['attempts']);}
        return $l->put($review['operation'],$this->owner($review['subject']),'recover',self::json($body),$old['retire_at']??($review['expires']+$this->d()[13]->lifetime('account_activated')),$old['revision']??null);
    }
    /** Host approval verify runs outside SQL. Other phases must check current authority without network I/O. */
    public function execute(array $review,string $source,array $proof,array $factorProof=[]):array
    {
        $review=$this->reviewInput($review);if($review['action']==='enroll'){throw new ValidationException('Use explicit enrollment preparation and confirmation.','account.factor_input');}self::label($source);self::proofs($review['action'],$proof,$factorProof);$d=$this->d();
        return $d[6]->work(function()use($d,$review,$source,$proof,$factorProof):array{
            $u=$this->unit();$pre=$this->requested($u,function()use($u,$review,$source,$proof):array{$this->ledger($u)->checkpoint();$facts=$this->facts($u,$review['subject']);if($u->now()<$review['issued']||$facts['stamp']!==$review['stamp']||!$facts['slot']->enabled()){throw new SecurityException('Management review is stale.','account.factor_changed');}if($this->ledger($u)->read($review['operation'])!==null){throw new SecurityException('A management operation is never implicitly replayed.','account.factor_replayed');}$this->check($u,$review,$source,$proof,$facts,'inspect');return $facts;},function()use($u,$review,$source):bool{return $this->request($u,$review['action'],'request',$source,$review['operation'],$review);});
            // The approval is a one-use capability. Failure does not refund it or a spent factor code.
            $this->verifyApproval($review,$proof,$pre);
            $reserved=false;$external=false;$committed=false;$reserveReady=false;
            try{
                $u=$this->unit();$reservedState=$u->run(function()use($u,$review,$source,$proof,$pre):array{$l=$this->ledger($u);$l->checkpoint();$this->check($u,$review,$source,$proof,$pre,'reserve');if($l->read($review['operation'])!==null){throw new SecurityException('Management operation was already reserved.','account.factor_replayed');}$row=$this->intent($u,$review,$pre,'prepared');$root=$l->checkpoint();$this->event($u,'factor_management_started',$review,$pre,$pre);return ['row'=>$row,'root'=>$root];},null,function(array $s)use($u,$review,$source,$proof,$pre,&$reserveReady):void{$this->check($u,$review,$source,$proof,$pre,'reserve_commit',$s['row'],$s['root']);$reserveReady=true;});$reserved=true;
                $u=$this->unit();$result=$u->run(function()use($u,$review,$source,$proof,$factorProof,$pre,$reservedState,$d,&$external):array{
                    $l=$this->ledger($u);$l->checkpoint();if($l->read($review['operation'])!==$reservedState['row']){throw new StorageException('Management reservation changed.','account.factor_changed');}$applyRoot=$l->checkpoint();$this->check($u,$review,$source,$proof,$pre,'apply',$reservedState['row'],$applyRoot);$slot=$pre['slot'];$external=true;$codes=null;
                    if($review['action']==='disable'){$ok=$d[5]->verifyBound($slot->slotScope(),$slot->slotSubject(),$slot->factorId(),$factorProof['code'],$factorProof['type']==='recovery');}
                    elseif($review['action']==='regenerate'){$codes=$d[5]->regenerateRecoveryCodesBound($slot->slotScope(),$slot->slotSubject(),$slot->factorId(),$factorProof['code']);$ok=$codes!==null;}
                    else{$ok=$d[5]->reencryptBound($slot->slotScope(),$slot->slotSubject(),$slot->factorId());}
                    if(!$ok){throw new SecurityException('Current factor proof or generation required.','account.factor_unproven');}
                    // The exact pointer/account must still match after the external operation.
                    if($this->facts($u,$review['subject'])['stamp']!==$pre['stamp']){throw new StorageException('Factor account changed during its external operation.','account.factor_changed');}
                    $after=$review['action']==='reencrypt'?$pre:$u->invoke($d[8],[$u,$pre,$review['action']!=='disable'],'account.factor_directory');$row=$this->intent($u,$review,$after,'completed',$reservedState['row']);$root=$l->checkpoint();$this->event($u,'factor_management_completed',$review,$pre,$after);return ['row'=>$row,'root'=>$root,'facts'=>$after,'codes'=>$codes];
                },null,function(array $s)use($u,$review,$source,$proof):void{$this->check($u,$review,$source,$proof,$s['facts'],'commit',$s['row'],$s['root']);});$committed=true;
                $u=$this->unit();$cleanup=$u->run(function()use($u,$review,$source,$proof,$pre,$result,$d):bool{$this->ledger($u)->checkpoint();$this->check($u,$review,$source,$proof,$result['facts'],'complete',$result['row'],$result['root']);if($review['action']!=='disable'){return false;}$slot=$pre['slot'];return $u->invoke([$d[5],'revokeGeneration'],[$slot->slotScope(),$slot->slotSubject(),$slot->factorId()],'account.factor_store');},null,function()use($u,$review,$source,$proof,$result):void{$this->check($u,$review,$source,$proof,$result['facts'],'return',$result['row'],$result['root']);});
                return ['operation'=>$review['operation'],'action'=>$review['action'],'completed'=>true,'factor_removed'=>$cleanup,'codes'=>$result['codes']];
            }catch(\Throwable $error){if($reserveReady||$reserved||$external||$committed||$u->committed()){throw new StorageException('Management completion is unknown; inspect the signed intent and never replay code output.','account.completion_unknown', $error);}throw $error;}
        });
    }
    private function verifyApproval(array $review,array $proof,array $facts):void
    {
        $d=$this->d();$deadline=new \SoSecurity\Support\Deadline($d[13]->ioMilliseconds());$observed=$d[14]->now();
        try{$allowed=call_user_func($d[11],'verify',$review,$proof,$facts['record'],$facts['identity']);}catch(\Throwable $error){throw new \SoSecurity\Exception\DependencyException('Management approval unavailable.','account.factor_approval',$error);}
        $deadline->check('account.factor_expired');if($d[14]->now()<$observed||$d[14]->now()>=$review['expires']){throw new SecurityException('Management approval expired.','account.factor_expired');}if($allowed!==true){throw new SecurityException('Exact management approval required.','account.factor_denied');}
    }
    private function enrollmentTarget(array $review):array
    {
        return ['binding'=>hash('sha256','SoSecurity.Account.Enrollment.Reservation.1.'.self::json([$review['site'],$review['scope'],$review['epoch'],$review['operation'],$review['target_scope'],$review['target_subject'],$review['target_factor']])),'scope'=>$review['target_scope'],'subject'=>$review['target_subject'],'factor'=>$review['target_factor']];
    }
    private static function sameEnrollment(array $a,array $b):bool
    {
        foreach(['authority','key','seal'] as $k){unset($a[$k],$b[$k]);}return $a===$b;
    }
    private function enrollmentInput(array $review,string $source,array $proof):array
    {
        $review=$this->reviewInput($review);self::label($source);if($review['action']!=='enroll'){throw new ValidationException('Use an enrollment-specific signed review.','account.factor_input');}self::proofs('enroll',$proof,[]);return $review;
    }
    private function pendingEnrollment(SqlTransaction $u,array $review):?array
    {
        $l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($review['operation']);if($row===null){return null;}$b=$this->parse($row);
        if($b['purpose']!=='factor_enrollment'||!self::sameEnrollment($review,$b['review'])){throw new SecurityException('Enrollment intent does not match the review.','account.factor_changed');}
        if($b['state']!=='pending'||$u->now()<$review['issued']||$u->now()>=$review['expires']||$b['attempts']>=$this->d()[13]->maximumAttempts()){return null;}
        $facts=$this->facts($u,$review['subject']);if($facts['stamp']!==$review['stamp']||$facts['slot']->enabled()){throw new SecurityException('Enrollment account changed.','account.factor_changed');}return ['row'=>$row,'body'=>$b,'facts'=>$facts,'root'=>$root];
    }
    /** Reserve and notify before physical preparation. Provisioning URI is never persisted or reissued. */
    public function beginEnrollment(array $review,string $source,array $proof):FactorEnrollment
    {
        $review=$this->enrollmentInput($review,$source,$proof);$d=$this->d();return $d[6]->work(function()use($review,$source,$proof,$d):FactorEnrollment{
            $u=$this->unit();$facts=$this->requested($u,function()use($u,$review,$source,$proof):array{
                $l=$this->ledger($u);$l->checkpoint();$facts=$this->facts($u,$review['subject']);if($facts['slot']->enabled()||$facts['stamp']!==$review['stamp']||$u->now()<$review['issued']){throw new SecurityException('Enrollment review is stale.','account.factor_changed');}if($l->read($review['operation'])!==null){throw new SecurityException('Enrollment cannot be implicitly prepared again.','account.factor_replayed');}$this->check($u,$review,$source,$proof,$facts,'inspect');return $facts;
            },function()use($u,$review,$source):bool{return $this->request($u,'enroll','request',$source,$review['operation'],$review);});$this->verifyApproval($review,$proof,$facts);$reserved=false;$external=false;$reserveReady=false;
            try{
                $u=$this->unit();$reservation=$u->run(function()use($u,$review,$source,$proof,$facts):array{
                    $l=$this->ledger($u);$l->checkpoint();$this->check($u,$review,$source,$proof,$facts,'reserve');if($l->read($review['operation'])!==null){throw new SecurityException('Enrollment was already reserved.','account.factor_replayed');}
                    $row=$this->intent($u,$review,$facts,'preparing',null,$this->enrollmentTarget($review));$root=$l->checkpoint();$this->event($u,'factor_enrollment_started',$review,$facts,$facts);return ['row'=>$row,'root'=>$root];
                },null,function(array $s)use($u,$review,$source,$proof,$facts,&$reserveReady):void{$this->check($u,$review,$source,$proof,$facts,'reserve_commit',$s['row'],$s['root']);$reserveReady=true;});$reserved=true;
                $target=$this->enrollmentTarget($review);$external=true;$pending=$d[5]->prepare($target['scope'],$target['subject'],$target['factor'],$facts['record']->address()->value());
                if($pending->id()!==$target['factor']){throw new StorageException('Prepared enrollment generation changed.','account.factor_changed');}
                $u=$this->unit();$prepared=$u->run(function()use($u,$review,$source,$proof,$facts,$reservation):array{
                    $l=$this->ledger($u);$root=$l->checkpoint();$this->check($u,$review,$source,$proof,$facts,'prepared',$reservation['row'],$root);$row=$this->intent($u,$review,$facts,'pending',$reservation['row']);$root=$l->checkpoint();$this->event($u,'factor_enrollment_prepared',$review,$facts,$facts);return ['row'=>$row,'root'=>$root];
                },null,function(array $s)use($u,$review,$source,$proof,$facts):void{$this->check($u,$review,$source,$proof,$facts,'prepared_commit',$s['row'],$s['root']);});
                $u=$this->unit();$u->run(function()use($u,$review,$source,$proof,$facts,$prepared):void{$root=$this->ledger($u)->checkpoint();$this->check($u,$review,$source,$proof,$facts,'prepared_return',$prepared['row'],$root);});
                $until=min($pending->expiresAt(),$review['expires']);if($d[14]->now()>=$until){throw new StorageException('Enrollment expired before provisioning delivery.','account.completion_unknown');}return new FactorEnrollment($review['operation'],new \SoSecurity\Mfa\Enrollment($pending->id(),$pending->provisioningUri(),$until));
            }catch(\Throwable $error){if($reserveReady||$reserved||$external||$u->committed()){throw new StorageException('Enrollment preparation completion is unknown; inspect or cancel its reserved slot.','account.completion_unknown',$error);}throw $error;}
        });
    }
    /** Obtain a fresh authority signature after handoff, preserving the original target and deadline. */
    public function enrollmentReview(string $operation,string $source):?array
    {
        self::id($operation);self::label($source);$d=$this->d();return $d[6]->work(function()use($operation,$source,$d):?array{
            $u=$this->unit();$s=$this->requested($u,function()use($u,$operation,$d):?array{
                $l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($operation);if($row===null){return null;}$b=$this->parse($row);if($b['purpose']!=='factor_enrollment'||$b['state']!=='pending'||$u->now()>=$b['review']['expires']||$b['attempts']>=$d[13]->maximumAttempts()){return null;}$r=$b['review'];$facts=$this->facts($u,$r['subject']);if($facts['stamp']!==$r['stamp']||$facts['slot']->enabled()){throw new SecurityException('Enrollment account changed.','account.factor_changed');}
                unset($r['seal']);$r['authority']=$d[6]->binding();$r['key']=$d[4]->currentId();$r['seal']=bin2hex($d[4]->sign('SoSecurity.Account.FactorOperations.Review.1.'.self::json($r)));return ['review'=>$r,'facts'=>$facts,'row'=>$row,'root'=>$root];
            },function()use($u,$operation,$source):bool{return $this->request($u,'enroll','review',$source,$operation);},function(?array $s)use($u,$operation,$source):void{if($s===null){return;}$this->budget($u,'enroll','final',$source,$operation);$this->guard($u,'enroll','review_complete',$s['facts'],$s['review']);$fresh=$this->facts($u,$s['review']['subject']);$l=$this->ledger($u);if($fresh['stamp']!==$s['facts']['stamp']||$l->checkpoint()!==$s['root']||$l->read($operation)!==$s['row']||$u->now()>=$s['review']['expires']){throw new StorageException('Enrollment review changed.','account.factor_changed');}});return $s===null?null:$s['review'];
        });
    }
    /** Fresh exact approval and new-factor proof. [] means a previously confirmed slot was re-proved; codes are never replayed. */
    public function confirmEnrollment(array $review,string $source,array $proof,string $code):?array
    {
        $review=$this->enrollmentInput($review,$source,$proof);if(!preg_match('/\A[0-9]{6,8}\z/D',$code)){throw new ValidationException('Use a bounded new-factor proof.','account.factor_input');}$d=$this->d();return $d[6]->work(function()use($review,$source,$proof,$code,$d):?array{
            $u=$this->unit();$pre=$this->requested($u,function()use($u,$review,$source,$proof):?array{$s=$this->pendingEnrollment($u,$review);if($s!==null){$this->check($u,$review,$source,$proof,$s['facts'],'inspect',$s['row'],$s['root']);}return $s;},function()use($u,$review,$source):bool{return $this->request($u,'enroll','request',$source,$review['operation'],$review);});if($pre===null){return null;}$this->verifyApproval($review,$proof,$pre['facts']);
            $u=$this->unit();$attemptReady=false;try{$attempt=$u->run(function()use($u,$review,$source,$proof,$pre):?array{
                $s=$this->pendingEnrollment($u,$review);if($s===null||$s['row']!==$pre['row']){return null;}$this->check($u,$review,$source,$proof,$s['facts'],'attempt',$s['row'],$s['root']);$row=$this->intent($u,$review,$s['facts'],'pending',$s['row'],null,$s['body']['attempts']+1);return ['row'=>$row,'root'=>$this->ledger($u)->checkpoint(),'facts'=>$s['facts']];
            },null,function(?array $s)use($u,$review,$source,$proof,&$attemptReady):void{if($s!==null){$this->check($u,$review,$source,$proof,$s['facts'],'attempt_commit',$s['row'],$s['root']);$attemptReady=true;}});}catch(\Throwable $error){if($attemptReady||$u->committed()){throw new StorageException('Enrollment attempt completion is unknown; inspect the retained attempt counter.','account.completion_unknown',$error);}throw $error;}if($attempt===null){return null;}
            $external=false;$committed=false;
            try{
                $target=$this->enrollmentTarget($review);
                $u=$this->unit();$result=$u->run(function()use($u,$review,$source,$proof,$attempt,$target,$d,$code,&$external):?array{
                    $l=$this->ledger($u);$root=$l->checkpoint();$this->check($u,$review,$source,$proof,$attempt['facts'],'activate',$attempt['row'],$root);
                    // Keep the signed row locked through bounded external proof and activation. A newer SQL attempt cannot steal a proof already in progress.
                    $external=true;$status=$d[5]->status($target['scope'],$target['subject']);if($status['enabled']){$codes=$status['factor_id']===$target['factor']&&$d[5]->verifyBound($target['scope'],$target['subject'],$target['factor'],$code)?[]:null;}else{$codes=$d[5]->confirm($target['scope'],$target['subject'],$target['factor'],$code);}if($codes===null){return null;}
                    $after=$u->invoke($d[8],[$u,$attempt['facts'],true,$target],'account.factor_directory');$row=$this->intent($u,$review,$after,'completed',$attempt['row']);$root=$l->checkpoint();$this->event($u,'factor_enrolled',$review,$attempt['facts'],$after);return ['row'=>$row,'root'=>$root,'facts'=>$after,'codes'=>$codes];
                },null,function(?array $s)use($u,$review,$source,$proof):void{if($s!==null){$this->check($u,$review,$source,$proof,$s['facts'],'commit',$s['row'],$s['root']);}});if($result===null){return null;}$committed=true;
                $u=$this->unit();$u->run(function()use($u,$review,$source,$proof,$result):void{$root=$this->ledger($u)->checkpoint();$this->check($u,$review,$source,$proof,$result['facts'],'complete',$result['row'],$root);});return $result['codes'];
            }catch(\Throwable $error){if($external||$committed||$u->committed()){throw new StorageException('Enrollment confirmation completion is unknown; never reissue recovery codes.','account.completion_unknown',$error);}throw $error;}
        });
    }
    /** Cancel durably before cleanup; cancellation does not require the old account identity or an unexpired preview. */
    public function cancelEnrollment(string $operation,string $source):array
    {
        self::id($operation);self::label($source);$d=$this->d();return $d[6]->work(function()use($operation,$source,$d):array{
            $u=$this->unit();$ready=false;
            try{$s=$this->requested($u,function()use($u,$operation,$source,$d):?array{
                $l=$this->ledger($u);$l->checkpoint();$row=$l->read($operation);if($row===null){return null;}$b=$this->parse($row);if($b['purpose']!=='factor_enrollment'){throw new SecurityException('Use an exact enrollment intent.','account.factor_denied');}$r=$b['review'];$facts=$u->invoke($d[7],[$u,$r['subject'],false],'account.factor_directory');$root=$l->checkpoint();$this->budget($u,'enroll_cancel','final',$source,$operation);$this->guard($u,'enroll_cancel','current',$facts,$r);$fresh=$u->invoke($d[7],[$u,$r['subject'],false],'account.factor_directory');if($fresh['stamp']!==$facts['stamp']||$l->checkpoint()!==$root||$l->read($operation)!==$row){throw new StorageException('Enrollment cancellation changed.','account.factor_changed');}
                if($b['state']==='completed'){return null;}if(!in_array($b['state'],['cancelled','cleaned'],true)){$b['state']='cancelled';$row=$l->put($operation,$row['owner'],'recover',self::json($b),$row['retire_at'],$row['revision']);$root=$l->checkpoint();$this->event($u,'factor_enrollment_cancelled',$r,$facts,$facts);}return ['row'=>$row,'root'=>$root,'facts'=>$facts,'review'=>$r];
            },function()use($u,$operation,$source):bool{return $this->request($u,'enroll_cancel','before',$source,$operation);},function(?array $s)use($u,$operation,$source,$d,&$ready):void{if($s===null){return;}$this->budget($u,'enroll_cancel','final',$source,$operation);$this->guard($u,'enroll_cancel','commit',$s['facts'],$s['review']);$fresh=$u->invoke($d[7],[$u,$s['review']['subject'],false],'account.factor_directory');$l=$this->ledger($u);if($fresh['stamp']!==$s['facts']['stamp']||$l->checkpoint()!==$s['root']||$l->read($operation)!==$s['row']){throw new StorageException('Enrollment cancellation changed before commit.','account.factor_changed');}$ready=true;});if($s===null){return ['cancelled'=>false,'absent'=>0,'conflicts'=>0];}return ['cancelled'=>true]+$this->clean($operation,$source);
            }catch(\Throwable $error){if($ready||$u->committed()){throw new StorageException('Enrollment cancellation completion is unknown; retain its cancellation intent.','account.completion_unknown',$error);}throw $error;}
        });
    }
    private function parse(array $row):array
    {
        $b=json_decode($row['payload'],true,5);$enroll=is_array($b)&&($b['purpose']??null)==='factor_enrollment';$resolved=is_array($b)&&($b['format']??null)===2;$fields=['format','purpose','review','state','after','slot'];if($resolved){$fields[]='resolution';}if($enroll){$fields[]='attempts';}
        if(!is_array($b)||array_keys($b)!==$fields||(!in_array($b['format'],[1,2],true)||($resolved&&$enroll))||!in_array($b['purpose'],['factor_operation','factor_enrollment'],true)||!is_array($b['review'])||!in_array($b['state'],$enroll?['preparing','pending','completed','cancelled','cleaned']:($resolved?['abandoned']:['prepared','completed','cleaned']),true)||!is_string($b['after'])||!is_array($b['slot'])||array_keys($b['slot'])!==['binding','scope','subject','factor']){throw new StorageException('Invalid management intent.','account.factor_corrupt');}
        if($resolved){
            $r=$b['resolution'];if(!is_array($r)||array_keys($r)!==['purpose','decision','context','resolved_at','retain_until']||$r['purpose']!=='factor_operation_abandonment'||!is_string($r['decision'])||!is_string($r['context'])||!is_int($r['resolved_at'])||!is_int($r['retain_until'])||$r['resolved_at']<$row['created_at']||$r['resolved_at']>$row['updated_at']||$r['retain_until']-$r['resolved_at']!==$this->d()[13]->lifetime('account_activated')){throw new StorageException('Invalid retained operation decision.','account.factor_corrupt');}self::id($r['decision']);self::id($r['context']);
        }
        $review=$this->reviewInput($b['review'],true);self::id($b['after']);foreach(['binding','scope','subject','factor'] as $k){if(!is_string($b['slot'][$k])){throw new StorageException('Invalid management slot.','account.factor_corrupt');}}
        $slot=new FactorSlot($review['subject'],$b['slot']['binding'],$b['slot']['scope'],$b['slot']['subject'],$b['slot']['factor']);if(!$slot->enabled()||$row['kind']!=='recover'||$row['record_id']!==$review['operation']||$row['owner']!==$this->owner($review['subject'])||self::json($b)!==$row['payload']||($review['action']==='enroll')!==$enroll){throw new StorageException('Management intent binding changed.','account.factor_corrupt');}
        if($enroll&&(!is_int($b['attempts'])||$b['attempts']<0||$b['attempts']>$this->d()[13]->maximumAttempts()||$b['slot']!==$this->enrollmentTarget($review))){throw new StorageException('Enrollment attempts or reserved target changed.','account.factor_corrupt');}return $b;
    }
    /** Retained metadata only, including unknown completion. Never returns or reissues recovery codes. */
    public function inspect(string $operation,string $source):?array
    {
        self::id($operation);self::label($source);$d=$this->d();return $d[6]->work(function()use($operation,$source):?array{
            $u=$this->unit();$s=$this->requested($u,function()use($u,$operation):array{$l=$this->ledger($u);$root=$l->checkpoint();$row=$l->read($operation);$body=$row===null?null:$this->parse($row);$this->guard($u,'inspect','current',null,$body===null?null:$body['review']);return ['row'=>$row,'root'=>$root,'body'=>$body];},function()use($u,$operation,$source):bool{return $this->request($u,'inspect','before',$source,$operation);},function(array $s)use($u,$operation,$source):void{$this->budget($u,'inspect','final',$source,$operation);$this->guard($u,'inspect','return',null,$s['body']===null?null:$s['body']['review']);$l=$this->ledger($u);if($l->checkpoint()!==$s['root']||$l->read($operation)!==$s['row']){throw new StorageException('Management inspection changed.','account.factor_changed');}});return $s['body'];
        });
    }
    /** Explicit privileged retry of inactive exact-generation cleanup. It never retries an operation or code output. */
    public function clean(string $operation,string $source):array
    {
        self::id($operation);self::label($source);$d=$this->d();return $d[6]->work(function()use($operation,$source,$d):array{
            $u=$this->unit();$possible=false;
            try{return $this->requested($u,function()use($u,$operation,$source,$d,&$possible):array{
                $l=$this->ledger($u);$l->checkpoint();$row=$l->read($operation);if($row===null){throw new SecurityException('Retained operation required.','account.factor_changed');}$b=$this->parse($row);$beforeRoot=$l->checkpoint();$r=$b['review'];if(($r['action']==='disable'&&!in_array($b['state'],['completed','cleaned'],true))||($r['action']==='enroll'&&!in_array($b['state'],['cancelled','cleaned'],true))||!in_array($r['action'],['disable','enroll'],true)){throw new SecurityException('Only logically disabled slots may be cleaned.','account.factor_denied');}
                $facts=$u->invoke($d[7],[$u,$r['subject'],false],'account.factor_directory');$this->budget($u,'clean','final',$source,$operation);$this->guard($u,'clean','delete',$facts,$r);$fresh=$u->invoke($d[7],[$u,$r['subject'],false],'account.factor_directory');if($fresh['stamp']!==$facts['stamp']||$l->checkpoint()!==$beforeRoot||$l->read($operation)!==$row){throw new StorageException('Cleanup management changed.','account.factor_changed');}
                if(!$facts['retired']&&$facts['slot']->enabled()&&$facts['slot']->slotScope()===$b['slot']['scope']&&$facts['slot']->slotSubject()===$b['slot']['subject']){throw new SecurityException('Current managed slot cannot be cleaned.','account.factor_denied');}
                $possible=true;$removed=$u->invoke([$d[5],'revokeGeneration'],[$b['slot']['scope'],$b['slot']['subject'],$b['slot']['factor']],'account.factor_store');$saved=$row;
                if($removed&&$b['state']!=='cleaned'){$b['state']='cleaned';$saved=$l->put($operation,$row['owner'],'recover',self::json($b),$row['retire_at'],$row['revision']);}$root=$l->checkpoint();if($saved!==$row){$this->event($u,$r['action']==='enroll'?'factor_enrollment_cleaned':'factor_management_cleaned',$r,$facts,$facts);}return ['removed'=>$removed,'facts'=>$facts,'row'=>$saved,'root'=>$root,'review'=>$r];
            },function()use($u,$operation,$source):bool{return $this->request($u,'clean','before',$source,$operation);},function(array $s)use($u,$operation,$source,$d):void{$this->budget($u,'clean','final',$source,$operation);$this->guard($u,'clean','commit',$s['facts'],$s['review']);$fresh=$u->invoke($d[7],[$u,$s['review']['subject'],false],'account.factor_directory');$l=$this->ledger($u);if($fresh['stamp']!==$s['facts']['stamp']||$l->checkpoint()!==$s['root']||$l->read($operation)!==$s['row']){throw new StorageException('Cleanup changed before commit.','account.factor_changed');}})['removed']?['absent'=>1,'conflicts'=>0]:['absent'=>0,'conflicts'=>1];}
            catch(\Throwable $error){if($possible||$u->committed()){throw new StorageException('Inactive management cleanup completion is unknown.','account.completion_unknown',$error);}throw $error;}
        });
    }
    /** Explicit construction capability. Prefer the registry factory, which supplies its exact same-PDO CAS. */
    public function resolution(callable $advance,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorOperationResolution
    {
        $d=$this->d();return new FactorOperationResolution($d[0],$d[1],$d[2],$d[3],$d[4],$d[5],$d[6],function(array $row):array{return $this->parse($row);},$d[7],$advance,$authority,$budgets,$approval,$audit,$events,$d[13],$d[14]);
    }
    /** Purpose-specific SQL history only. Unknown and uncleared physical outcomes stay protected. */
    public function maintenance(callable $authority,callable $budgets,callable $approval,callable $audit,callable $events):FactorIntentMaintenance
    {
        $d=$this->d();if(!$d[5]->isManaged()||!$d[5]->boundTo($d[6])){throw new ConfigurationException('History purge requires the exact managed worker authority.','configuration.factor_operations');}
        return new FactorIntentMaintenance($d[0],$d[1],$d[2],$d[3],$d[4],$d[5],$d[6],function(array $row):array{return ['row'=>$row,'body'=>$this->parse($row)];},static function():bool{return true;},$authority,$budgets,$approval,$audit,$events,$d[13],$d[14],'operations');
    }
    public function __debugInfo():array {return ['factor_operations'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current factor management.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current factor management.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Factor management is immutable.','configuration.immutable');}
}
