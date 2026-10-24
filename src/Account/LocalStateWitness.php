<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** external whole-operation witness. Every protected entry must use the same independent authority. */
final class LocalStateWitness
{
    private $directory;
    private $directoryStat;
    private $path;
    private $context;
    private $binding;
    private $dependencies;
    private $milliseconds;
    private $busy=false;
    private $inode;
    private $format;
    private $generation;
    private $lockOwner;
    private $containment;
    private $recoveryAudit;
    private $auditWrite;
    private $lockDeadline;

    /** Explicit same-PDO source; persist(resource) must synchronously flush the stable inode. */
    public function __construct(PDO $pdo,string $directory,string $site,string $scope,string $epoch,HmacKeys $keys,StateSnapshot $snapshot,callable $persist,int $milliseconds=1000,int $format=2,?string $generation=null,?StateRecoveryAudit $recoveryAudit=null)
    {
        if(!in_array($format,[1,2,3],true)||($format===3?(!is_string($generation)||preg_match('/\A[a-f0-9]{64}\z/D',$generation)!==1):$generation!==null)){throw new ConfigurationException('Use an explicit supported witness format and generation.','configuration.state_witness');}$this->format=$format;$this->generation=$generation;
        if($format>=2&&!$snapshot instanceof CompositeStateSnapshot&&!$snapshot instanceof SqlStateSnapshot&&!$snapshot instanceof FileStateSnapshot){throw new ConfigurationException('Semantic protection requires an exact concrete bounded source.','configuration.state_witness');}
        foreach([$site,$scope] as $label){Guard::label($label);if(preg_match('//u',$label)!==1){throw new ConfigurationException('Use UTF-8 witness identities.','configuration.state_witness');}}
        self::digest($epoch);$source=$snapshot->fingerprint();self::digest($source);if($snapshot->connection()!==$pdo){throw new ConfigurationException('Use the exact protected snapshot connection.','configuration.state_witness');}new Deadline($milliseconds);new SqlTransaction($pdo,new SystemClock(),$milliseconds);
        $real=realpath($directory);$stat=@lstat($directory);
        if($real===false||$real!==$directory||!is_array($stat)||($stat['mode']&0170077)!==0040000){throw new ConfigurationException('Use a canonical private independent authority directory.','configuration.state_witness');}
        $this->directory=$real;$this->directoryStat=$stat;$this->milliseconds=$milliseconds;
        if($recoveryAudit!==null&&($format<2||!$recoveryAudit->usesKeys($keys)||!StateStorageDomain::disjoint([StateStorageDomain::directory($real,$stat)],[$recoveryAudit->storageDomain()]))){throw new ConfigurationException('Use a separate exact keyed recovery audit domain.','configuration.recovery_audit');}$this->recoveryAudit=$recoveryAudit;
        $this->context=json_encode(['SoSecurity.Account.LocalStateWitness.2',$site,$scope,$epoch,$source],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $this->binding=hash('sha256',$this->context.$real.':'.$stat['dev'].':'.$stat['ino']);$this->path=$real.'/'.hash('sha256',$this->context).'.witness';
        $this->dependencies=static function()use($pdo,$keys,$snapshot,$persist,$source,$scope):array{return [$pdo,$keys,$snapshot,$persist,$source,$scope];};
    }
    private function d():array{return ($this->dependencies)();}
    public function independentOf(LocalStateWitness $other):bool
    {
        $a=$this->d();$b=$other->d();if($this===$other||$a[0]===$b[0]||!$a[2] instanceof CompositeStateSnapshot||!$b[2] instanceof CompositeStateSnapshot){return false;}$this->checkDirectory();$other->checkDirectory();$one=$a[2]->storageDomains();$one[]=StateStorageDomain::directory($this->directory,$this->directoryStat);$two=$b[2]->storageDomains();$two[]=StateStorageDomain::directory($other->directory,$other->directoryStat);if($this->recoveryAudit!==null){$one[]=$this->recoveryAudit->storageDomain();}if($other->recoveryAudit!==null){$two[]=$other->recoveryAudit->storageDomain();}return StateStorageDomain::disjoint($one,$two);
    }
    public function usesKeys(HmacKeys $keys):bool{return $this->d()[1]===$keys;}
    public function allowsScope(string $scope):bool{return strlen($scope)<=256&&$scope===$this->d()[5];}
    public function format():int{return $this->format;}
    public function usesConnection(PDO $connection):bool{return $this->d()[0]===$connection;}
    public function generation():?string{return $this->generation;}
    public function internalOperation(string $action):StateOperation{return StateOperation::internal($action,$this->d()[5]);}
    public function binding():string{return $this->binding;}
    public function matches(string $site,string $scope,string $epoch):bool{if(strlen($site)>256||strlen($scope)>256||strlen($epoch)!==64||preg_match('//u',$site)!==1||preg_match('//u',$scope)!==1){return false;}$d=$this->d();return $this->context===json_encode(['SoSecurity.Account.LocalStateWitness.2',$site,$scope,$epoch,$d[4]],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    public function coversFence(LocalEpochFence $fence):bool{$source=$this->d()[2];return $source instanceof CompositeStateSnapshot&&$source->coversFence($fence);}
    public function coversSnapshot(StateSnapshot $snapshot):bool{$d=$this->d();return $d[2]===$snapshot&&$snapshot->connection()===$d[0]&&$snapshot->fingerprint()===$d[4];}
    public function sameSnapshot(self $other):bool{$a=$this->d();$b=$other->d();return $a[0]===$b[0]&&$a[2]===$b[2]&&$a[4]===$b[4];}
    public function coversStore(\SoSecurity\Storage\AtomicStore $store):bool
    {
        $d=$this->d();if($d[2]->connection()!==$d[0]||$d[2]->fingerprint()!==$d[4]){throw new ConfigurationException('Snapshot coverage or connection changed.','configuration.state_witness');}
        return $d[2] instanceof StateStoreSource&&$d[2]->coversStore($store);
    }
    private static function digest(string $value):void{if(!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new ConfigurationException('Use a canonical state digest.','configuration.state_witness');}}
    private static function json(array $value):string{return json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    private function idle(Deadline $deadline):void
    {
        $this->assertOwner();$deadline->check('account.witness_timeout');$d=$this->d();$u=SqlTransaction::forObservation($d[0],new SystemClock(),$this->milliseconds);$u->run(static function():void{},null,null,null,$deadline);
    }
    /** @phpstan-impure */
    private function snapshot(Deadline $deadline):string
    {
        $this->assertOwner();$d=$this->d();if($d[2]->connection()!==$d[0]||$d[2]->fingerprint()!==$d[4]){throw new ConfigurationException('Snapshot coverage or connection changed.','configuration.state_witness');}$this->idle($deadline);$this->isolation($d[2]);$deadline->check('account.witness_timeout');$value=$d[2]->digest();$this->idle($deadline);if($d[2]->connection()!==$d[0]||$d[2]->fingerprint()!==$d[4]){throw new ConfigurationException('Snapshot coverage or connection changed.','configuration.state_witness');}
        if(!is_string($value)||!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new StorageException('State snapshot provider returned invalid data.','account.witness_snapshot');}return $value;
    }
    private function isolation(StateSnapshot $source):void
    {
        if($source instanceof CompositeStateSnapshot||$source instanceof SqlStateSnapshot||$source instanceof FileStateSnapshot){
            $domains=[StateStorageDomain::directory($this->directory,$this->directoryStat)];if($this->recoveryAudit!==null){$domains[]=$this->recoveryAudit->storageDomain();}if(!StateStorageDomain::disjoint($domains,$source->storageDomains())){throw new ConfigurationException('Keep the witness physically separate from all protected state and scratch domains.','configuration.state_independence');}
        }
    }
    /** Independently approved first provisioning only; never use to repair a missing deployed witness. */
    public function initialize(string $expectedDigest):void
    {
        self::digest($expectedDigest);if($this->recoveryAudit!==null&&!$this->recoveryAudit->unused()){throw new StorageException('A prior recovery audit prevents first provisioning; never reset lost authority.','account.recovery_audit_exists');}$this->locked(function($handle,Deadline $deadline)use($expectedDigest):void{
            if($this->recoveryAudit!==null&&!$this->recoveryAudit->unused()){throw new StorageException('A prior recovery audit prevents first provisioning; never reset lost authority.','account.recovery_audit_exists');}$digest=$this->snapshot($deadline);if(!hash_equals($expectedDigest,$digest)){throw new StorageException('First state differs from the independently approved digest.','account.witness_changed');}
            $state=['format'=>$this->format,'context'=>$this->binding,'revision'=>1,'status'=>'current','digest'=>$digest,'operation'=>bin2hex(random_bytes(32))];
            if($this->format===3){$state['generation']=$this->generation;$state['lineage']=str_repeat('0',64);}
            if($this->format>=2){$intent=StateOperation::initial($this->d()[5]);$state['intent']=$intent->metadata();$state['intent_digest']=$intent->binding();}$this->write($handle,$state,$deadline);
        },true);
    }
    /** Holds EX over the complete operation, including every SQL/store effect and the final snapshot. Never joins a host transaction. */
    public function work(callable $operation,callable $requestBudget,?StateOperation $intent=null,?callable $admission=null,?StateAccountConnection $lifecycle=null,?Deadline $operationDeadline=null)
    {
        if($this->format>=2&&($intent===null||$intent->metadata()['kind']!=='internal'||$intent->metadata()['scope']!==StateOperation::scope($this->d()[5]))){throw new ConfigurationException('Describe the exact internal operation before protected effects.','configuration.state_operation');}
        if($lifecycle!==null&&(!$lifecycle->boundToWitness($this)||$this->format<2||$intent===null||!preg_match('/\Aaccount\.(?:(?:registration|recovery|mailbox_recovery)\.(?:request|confirm|cancel)|address_change\.(?:confirm|cancel))\z/D',$intent->metadata()['action']))){throw new ConfigurationException('Use the exact complete native lifecycle declaration.','configuration.state_refusal');}
        $deadline=$this->preflight($requestBudget);
        if($operationDeadline!==null){$operationDeadline->check('account.operation_timeout');}
        return $this->locked(function($handle,Deadline $deadline)use($operation,$requestBudget,$intent,$admission,$lifecycle,$operationDeadline){
            $state=$this->read($handle);if($state['status']!=='current'){throw new StorageException('An unresolved operation blocks this authority.','account.witness_pending');}
            $before=$this->snapshot($deadline);if(!hash_equals($state['digest'],$before)){throw new StorageException('Protected state is stale or changed outside the witness.','account.witness_stale');}
            if($admission!==null){
                $allowed=$admission($before);$deadline->check('account.witness_timeout');
                if($this->snapshot($deadline)!==$before||$this->read($handle)!==$state){throw new StorageException('Admission changed protected state before effects.','account.witness_changed');}
                if($allowed===false){return null;}
                if($allowed instanceof StateOperation){
                    $v=$allowed->metadata();$old=$intent===null?null:$intent->metadata();
                    if($this->format<2||$lifecycle!==null||$old===null||$v['kind']!=='authorized'||$v['scope']!==$old['scope']||$v['action']!==$old['action']||!preg_match('/\A(?:account\.(?:registration|address_change|recovery|mailbox_recovery|factor_notices)\.(?:maintain|rotate)|account\.address_change\.(?:proposal|completion_proposal|request|complete)|outbox\.(?:rotate|claim_initial|current_claim|acknowledge|reject|dispatch|dispatch_rejected)|idempotency\.(?:initialize|maintain|execute|lookup)|leases\.(?:initialize|acquire|renew|verify|release|inspect|remove)|quarantine\.(?:enqueue|inspect|items|process|rescan|reject|read|remove)|proof\.(?:csrf|captcha)\.(?:issue|verify|revoke)|api\.keys\.(?:issue|rotate|revoke)|api\.credentials\.(?:issue|rotate|replace|all|revoke|revoke_all|authenticate|execute)|operations\.(?:begin|confirm|consume|revoke|revoke_all|execute)|links\.(?:issue|verify|all|revoke|revoke_all|execute)|password\.reset\.(?:issue|consume|revoke|execute)|hmac\.(?:verify|execute)|webhook\.(?:receive|processing\.(?:claim|execute|fail|retry)))\z/D',$v['action'])){throw new ConfigurationException('Native admission must describe its exact declared scope and action.','configuration.state_operation');}
                    $intent=$allowed;
                }
            }
            // The caller's budget includes admission and its complete source recheck.
            // Refuse before publishing pending when that budget is already exhausted.
            if($operationDeadline!==null){$operationDeadline->check('account.operation_timeout');}
            return $this->execute($handle,$deadline,$state,$operation,$requestBudget,$intent,$lifecycle===null?null:$lifecycle->refusalCheck());
        },false,$deadline);
    }
    /** Concrete read-only permission checks finish before the first pending write. */
    public function authorized(StateAccountPolicy $policy,StatePermission $permission,callable $operation,callable $requestBudget)
    {
        if(!$policy->boundTo($this)){throw new ConfigurationException('Use the exact configured witness for account permissions.','configuration.state_permission');}$r=$permission->definition();if(!$this->allowsScope($r['scope'])){throw new ConfigurationException('Use the exact permission scope.','configuration.state_scope');}
        $deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($policy,$permission,$operation,$requestBudget){
            $state=$this->read($handle);if($state['status']!=='current'){throw new StorageException('An unresolved operation blocks this authority.','account.witness_pending');}
            $d=$this->d();if(!$d[2] instanceof CompositeStateSnapshot||!$this->coversSnapshot($d[2])){throw new ConfigurationException('Account permissions require the exact concrete composite source.','configuration.state_permission');}
            $observed=$policy->now();$this->idle($deadline);$first=$d[2]->capture($policy->selectors($permission));$this->idle($deadline);
            if(!hash_equals($state['digest'],$first->digest())){throw new StorageException('Protected permission state is stale or changed.','account.witness_stale');}
            $selectors=$policy->completeSelectors($permission,$first,$observed);if($selectors===null){throw new SecurityException('Current account/session permission required.','account.state_denied');}
            $view=$d[2]->capture($selectors);$this->idle($deadline);
            if(!hash_equals($state['digest'],$view->digest())||!$this->coversSnapshot($d[2])){throw new StorageException('Protected permission state changed.','account.witness_stale');}
            $now=$policy->now();if($now<$observed){throw new StorageException('Permission clock moved backwards.','account.clock');}
            if(!hash_equals($state['digest'],$this->snapshot($deadline))){throw new StorageException('Permission dependencies changed protected state.','account.witness_stale');}
            if(!$policy->allows($permission,$view,$now)){throw new SecurityException('Current account/session permission required.','account.state_denied');}
            $deadline->check('account.witness_timeout');if($this->read($handle)!==$state){throw new StorageException('Current authority changed during permission checks.','account.witness_corrupt');}
            $intent=$this->format>=2?StateOperation::authorized($permission,$policy->binding(),$now):null;
            return $this->execute($handle,$deadline,$state,$operation,$requestBudget,$intent);
        },false,$deadline);
    }
    private function execute($handle,Deadline $deadline,array $state,callable $operation,callable $requestBudget,?StateOperation $intent,?\Closure $refusalCheck=null)
    {
            if($state['revision']>=PHP_INT_MAX-1){throw new StorageException('State witness revision is exhausted.','account.witness_capacity');}
            $pending=$state;unset($pending['key'],$pending['seal']);$pending['status']='pending';++$pending['revision'];$pending['operation']=bin2hex(random_bytes(32));
            if($this->format>=2){$pending['intent']=$intent->metadata();$pending['intent_digest']=$intent->binding();}
            // Durable pending is published BEFORE protected effects. A crash or rollback
            // never automatically restores an earlier current checkpoint.
            $sealedPending=null;$started=false;$returned=false;
            try{
                $this->write($handle,$pending,$deadline);$sealedPending=$this->read($handle);$started=true;$result=$operation();$returned=true;$after=$this->snapshot($deadline);$this->validateHandle($handle);
                if($this->read($handle)!==$sealedPending){throw new StorageException('Pending authority changed during protected work.','account.witness_corrupt');}
                $this->checkBudget($requestBudget,'final',$deadline);
                if($this->snapshot($deadline)!==$after||$this->read($handle)!==$sealedPending){throw new StorageException('Protected state changed during final budget checks.','account.witness_changed');}
                $current=$pending;$current['status']='current';$current['digest']=$after;$this->write($handle,$current,$deadline);return $result;
            }catch(\Throwable $error){
                if($refusalCheck!==null&&$refusalCheck()===true&&$started&&!$returned&&is_array($sealedPending)&&$error instanceof StateBudgetRefusal&&$error->confirmed($this->d()[0])){
                    $refused=false;
                    try{
                        if(hash_equals($state['digest'],$this->snapshot($deadline))&&$this->read($handle)===$sealedPending){
                            if(!hash_equals($state['digest'],$this->snapshot($deadline))||$this->read($handle)!==$sealedPending){throw new StorageException('Refusal state changed during confirmation.','account.witness_changed');}
                            // Finishing a proven no-effect refusal is bounded cleanup, not another business budget charge.
                            $current=$pending;$current['status']='current';$this->write($handle,$current,$deadline);$refused=true;
                        }
                    }catch(\Throwable $cleanup){throw new StorageException('Refusal completion is unknown; retain independent authority.','account.completion_unknown',$cleanup);}
                    if($refused){throw $error;}
                }
                throw new StorageException('State witness completion is unknown; retain the independent pending authority.','account.completion_unknown',$error);
            }
    }
    /** Signed, short-lived, exact unknown-operation selection; no approval consumed here. */
    public function retirementReview(StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateRetirementReview
    {
        if($this->format<2){throw new ConfigurationException('Semantic format2 is required for explicit unknown retirement.','configuration.state_retirement');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($control,$actor,$token):StateRetirementReview{
            $state=$this->read($handle);if($state['status']!=='pending'){throw new SecurityException('An exact pending operation is required.','account.retirement_state');}
            if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent approval state and authority.','configuration.state_independence');}
            $control->review($this->binding,$actor,$token);$now=$control->now();$observed=$this->snapshot($deadline);$d=$this->d();$v=['purpose'=>'retire_unknown','context'=>$this->binding,'revision'=>$state['revision'],'operation'=>$state['operation'],'before'=>$state['digest'],'observed'=>$observed,'intent'=>$state['intent_digest'],'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateRetirementReview.1.'.StateRetirementReview::encode($v)));if($this->read($handle)!==$state){throw new StorageException('Pending authority changed while reviewing.','account.witness_corrupt');}return new StateRetirementReview($v);
        },false,$deadline);
    }
    /** Independently reviewed mismatching current state; never invents an unknown transaction. */
    public function staleReview(StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateRetirementReview
    {
        if($this->format<2){throw new ConfigurationException('A semantic authority is required for stale retirement.','configuration.state_retirement');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($control,$actor,$token):StateRetirementReview{
            $state=$this->read($handle);if($state['status']!=='current'){throw new SecurityException('A current authority with a mismatching source is required.','account.stale_state');}
            if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent approval state and authority.','configuration.state_independence');}
            $control->review($this->binding,$actor,$token);$now=$control->now();$observed=$this->snapshot($deadline);if(hash_equals($state['digest'],$observed)){throw new SecurityException('A matching current authority must not use stale retirement.','account.stale_state');}$d=$this->d();$v=['purpose'=>'retire_stale','context'=>$this->binding,'revision'=>$state['revision'],'operation'=>$state['operation'],'before'=>$state['digest'],'observed'=>$observed,'intent'=>$state['intent_digest'],'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateStaleReview.1.'.StateRetirementReview::encode($v)));if($this->read($handle)!==$state){throw new StorageException('Current authority changed while reviewing.','account.witness_corrupt');}return new StateRetirementReview($v);
        },false,$deadline);
    }
    private function retirementSelection(StateRetirementReview $review,array $state,StateRetirementControl $control,Deadline $deadline,string $purpose):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();
        if($v['purpose']!==$purpose||!$d[1]->verify($v['key'],($purpose==='retire_stale'?'SoSecurity.Account.StateStaleReview.1.':'SoSecurity.Account.StateRetirementReview.1.').StateRetirementReview::encode($signed),hex2bin($v['seal']))||$this->format<2||$state['status']!==($purpose==='retire_stale'?'current':'pending')||$v['context']!==$this->binding||$v['revision']!==$state['revision']||$v['operation']!==$state['operation']||$v['before']!==$state['digest']||$v['intent']!==$state['intent_digest']||$v['control']!==$control->binding()){throw new SecurityException('Retirement selection does not match the exact purpose and authority.','account.retirement_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Retirement approval selection expired.','account.retirement_expired');}
        if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent approval state and authority.','configuration.state_independence');}
        if($this->snapshot($deadline)!==$v['observed']){throw new SecurityException('Observed unknown-result state changed; review again.','account.retirement_changed');}
    }
    /** Permanently retires the old authority. Preserves unknown outcome; never replays work or adopts a database. */
    public function retirePending(StateRetirementReview $review,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {return $this->retire($review,$control,$actor,$token,$grant,$requestBudget,'retire_unknown');}
    /** Permanently close a mismatching current authority under its separate exact approval purpose. */
    public function retireStale(StateRetirementReview $review,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {return $this->retire($review,$control,$actor,$token,$grant,$requestBudget,'retire_stale');}
    private function retire(StateRetirementReview $review,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget,string $purpose):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact retirement approval credentials.','account.retirement_input');}
        $deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$control,$actor,$token,$grant,$requestBudget,$purpose):array{
            $state=$this->read($handle);$this->retirementSelection($review,$state,$control,$deadline,$purpose);$this->checkBudget($requestBudget,'final',$deadline);$this->retirementSelection($review,$state,$control,$deadline,$purpose);
            if($this->read($handle)!==$state){throw new StorageException('Pending authority changed before approval.','account.witness_corrupt');}
            $permit=$control->consume($review,$actor,$token,$grant);$control->current($review,$actor,$token);$this->retirementSelection($review,$state,$control,$deadline,$purpose);
            if($this->read($handle)!==$state){throw new StorageException('Pending authority changed during independent approval.','account.witness_corrupt');}
            $closedAt=$control->now();if($closedAt>=$permit->expiresAt()){throw new SecurityException('Consumed retirement approval expired.','account.retirement_expired');}
            $closed=$state;unset($closed['key'],$closed['seal']);$closed['status']='closed';$closed['closure']=['review'=>$review->metadata(),'control'=>$control->binding(),'operator'=>$control->actorDigest($actor),'grant'=>$permit->id(),'closed_at'=>$closedAt];
            try{$this->write($handle,$closed,$deadline);$control->current($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Retirement approval expired during persistence.','account.retirement_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;}
            catch(\Throwable $error){throw new StorageException('Retirement completion is unknown; the old authority must remain blocked.','account.completion_unknown',$error);}
        },false,$deadline);
    }
    /** Creates only a configured reader; does not open, initialize, approve or replace any authority. */
    public function successorReader(StateSuccessorReview $review):self
    {
        $v=$review->metadata();if($v['context']!==$this->binding||$v['generation']===$this->generation){throw new ConfigurationException('Use the exact new generation selected for this authority.','configuration.state_successor');}$d=$this->d();$context=json_decode($this->context,true);
        return new self($d[0],$this->directory,$context[1],$context[2],$context[3],$d[1],$d[2],$d[3],$this->milliseconds,3,$v['generation'],$this->recoveryAudit);
    }
    /** Strong independent preview before snapshot access; no state is adopted. */
    public function successorReview(StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateSuccessorReview
    {
        if($this->format<2){throw new ConfigurationException('A semantic closed authority is required.','configuration.state_successor');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($control,$actor,$token):StateSuccessorReview{
            $state=$this->read($handle);if($state['status']!=='closed'){throw new SecurityException('Retire the exact authority before staging a successor.','account.successor_state');}
            if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent successor approval.','configuration.state_independence');}
            $control->reviewSuccessor($this->binding,$actor,$token);$now=$control->now();$observed=$this->snapshot($deadline);$d=$this->d();
            $v=['purpose'=>'stage_successor','context'=>$this->binding,'revision'=>$state['revision'],'predecessor'=>hash('sha256',self::json($state)),'observed'=>$observed,'intent'=>$state['intent_digest'],'control'=>$control->binding(),'generation'=>bin2hex(random_bytes(32)),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateSuccessorReview.1.'.StateSuccessorReview::encode($v)));if($this->read($handle)!==$state){throw new StorageException('Closed authority changed while reviewing.','account.witness_corrupt');}return new StateSuccessorReview($v);
        },false,$deadline);
    }
    private function successorSelection(StateSuccessorReview $review,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();
        if($this->format<2||!$d[1]->verify($v['key'],'SoSecurity.Account.StateSuccessorReview.1.'.StateSuccessorReview::encode($signed),hex2bin($v['seal']))||$state['status']!=='closed'||$v['context']!==$this->binding||$v['revision']!==$state['revision']||$v['predecessor']!==hash('sha256',self::json($state))||$v['intent']!==$state['intent_digest']||$v['control']!==$control->binding()||$v['generation']===$this->generation){throw new SecurityException('Successor selection does not match the exact closed authority.','account.successor_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Successor selection expired.','account.successor_expired');}
        if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent successor approval.','configuration.state_independence');}
        if($this->snapshot($deadline)!==$v['observed']){throw new SecurityException('Observed unknown-result state changed; review again.','account.successor_changed');}
    }
    /** Replace the SAME inode with a sealed QUARANTINED generation. No business callback and no current baseline. */
    public function stageSuccessor(StateSuccessorReview $review,LocalStateWitness $next,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact successor credentials.','account.successor_input');}
        $d=$this->d();$n=$next->d();$v=$review->metadata();
        if($next===$this||$next->busy||$next->format!==3||$next->generation!==$v['generation']||$next->path!==$this->path||$next->binding!==$this->binding||$d[0]!==$n[0]||$d[1]!==$n[1]||$d[2]!==$n[2]||$d[3]!==$n[3]||$this->recoveryAudit!==$next->recoveryAudit){throw new ConfigurationException('Use the exact same physical authority and dependencies for the selected new generation.','configuration.state_successor');}
        $deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$next,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->successorSelection($review,$state,$control,$deadline);$this->checkBudget($requestBudget,'final',$deadline);$this->successorSelection($review,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Closed authority changed before successor approval.','account.witness_corrupt');}
            $permit=$control->consumeSuccessor($review,$actor,$token,$grant);$control->currentSuccessor($review,$actor,$token);$this->successorSelection($review,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Closed authority changed during successor approval.','account.witness_corrupt');}
            $now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Successor approval expired.','account.successor_expired');}$v=$review->metadata();
            $intent=StateOperation::recovery($this->d()[5],$control->actorDigest($actor),$this->binding,$permit->intent()->fingerprint(),$control->binding(),$now);
            $staged=['format'=>3,'context'=>$this->binding,'revision'=>$state['revision']+1,'status'=>'quarantined','digest'=>$state['digest'],'operation'=>$v['nonce'],'generation'=>$v['generation'],'lineage'=>$v['predecessor'],'intent'=>$intent->metadata(),'intent_digest'=>$intent->binding(),'successor'=>['review'=>$v,'control'=>$control->binding(),'operator'=>$control->actorDigest($actor),'grant'=>$permit->id(),'staged_at'=>$now,'predecessor_operation'=>$state['operation'],'predecessor_intent'=>$state['intent']]];
            $next->busy=true;$next->lockOwner=$this->lockOwner;$next->lockDeadline=$deadline;
            try{
                $next->write($handle,$staged,$deadline);$control->currentSuccessor($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Successor approval expired during persistence.','account.successor_expired');}
                $result=$next->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Successor completion is unknown; keep every generation blocked.','account.completion_unknown',$error);}
            finally{$next->busy=false;$next->lockOwner=null;$next->lockDeadline=null;}
        },false,$deadline);
    }
    private function containmentState(array $state):int
    {
        if($this->format!==3||$state['status']!=='quarantined'){throw new SecurityException('An exact quarantined generation is required.','account.containment_state');}
        if(isset($state['remediation'])&&$state['remediation']['phase']!=='complete'){throw new StorageException('An unresolved containment blocks further recovery.','account.containment_pending');}
        $sequence=isset($state['remediation'])?$state['remediation']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('Containment history requires explicit maintenance.','account.witness_capacity');}return $sequence;
    }
    /** Strong independent selection of a fixed disabling plan. It cannot activate an account. */
    public function containmentReview(StateAccountContainment $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateContainmentReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact covered containment plan.','configuration.state_containment');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token):StateContainmentReview{
            $state=$this->read($handle);$sequence=$this->containmentState($state);if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent containment approval.','configuration.state_independence');}
            $control->reviewContainment($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>'contain_accounts','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateContainmentReview.1.'.StateContainmentReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Quarantined source changed during containment review.','account.containment_changed');}return new StateContainmentReview($v);
        },false,$deadline);
    }
    private function containmentSelection(StateContainmentReview $review,StateAccountContainment $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$sequence=$this->containmentState($state);
        if(!$plan->boundTo($this)||!$d[1]->verify($v['key'],'SoSecurity.Account.StateContainmentReview.1.'.StateContainmentReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Containment selection does not match the exact authority and account set.','account.containment_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Containment selection expired.','account.containment_expired');}
        if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent containment approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Selected account/source state changed; review again.','account.containment_changed');}$deadline->check('account.witness_timeout');
    }
    /** Scoped capability observation, not a caller-supplied approval. Foreign execution contexts cannot borrow it. */
    public function containmentActive(StateAccountContainment $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function containmentCurrent(StateAccountContainment $plan,string $operation):void
    {
        if(!$this->containmentActive($plan,$operation)){throw new SecurityException('An exact active containment context is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Containment authority changed before SQL commit.','account.witness_corrupt');}$d[2]->currentContainment($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Containment approval expired.','account.containment_expired');}
    }
    /** Fixed account disabling only. Durable pending precedes SQL; no arbitrary work callback is accepted. */
    public function containAccounts(StateContainmentReview $review,StateAccountContainment $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact containment credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact covered containment plan.','configuration.state_containment');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->containmentSelection($review,$plan,$state,$control,$deadline);$this->checkBudget($requestBudget,'final',$deadline);$this->containmentSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before containment approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);$pending['remediation']=['review'=>$v,'phase'=>'pending','operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'completed'=>null,'after'=>null];
            $manifest=$plan->manifest($v['nonce']);if(!StateAccountManifest::valid($manifest)||$manifest['observed']!==$v['observed']){throw new StorageException('Account source changed before sealing fixed effects.','account.containment_changed');}$pending['remediation']['manifest']=$manifest;
            // Budget the larger completed receipt before consuming approval or changing the authority.
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Containment receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeContainment($review,$actor,$token,$grant);$control->currentContainment($review,$actor,$token);$this->containmentSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during containment approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Containment approval expired.','account.containment_expired');}$pending['remediation']['grant']=$permit->id();$pending['remediation']['started']=$now;
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->containmentCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->contained($operation);$this->checkBudget($requestBudget,'final',$deadline);$this->containmentCurrent($plan,$operation);if($plan->contained($operation)!==$after){throw new StorageException('Contained source changed before final persistence.','account.containment_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentContainment($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Containment approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Account containment completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    /** Strong independent selection of a fixed disabling plan. It cannot activate an account. */
    public function factorContainmentReview(StateFactorContainment $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateFactorContainmentReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact covered containment plan.','configuration.state_containment');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token):StateFactorContainmentReview{
            $state=$this->read($handle);$sequence=$this->containmentState($state);if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent containment approval.','configuration.state_independence');}
            $control->reviewFactors($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>'contain_factors','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateFactorContainmentReview.1.'.StateFactorContainmentReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Quarantined source changed during containment review.','account.containment_changed');}return new StateFactorContainmentReview($v);
        },false,$deadline);
    }
    private function factorContainmentSelection(StateFactorContainmentReview $review,StateFactorContainment $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$sequence=$this->containmentState($state);
        if(!$plan->boundTo($this)||!$d[1]->verify($v['key'],'SoSecurity.Account.StateFactorContainmentReview.1.'.StateFactorContainmentReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Containment selection does not match the exact authority and factor set.','account.containment_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Containment selection expired.','account.containment_expired');}
        if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent containment approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Selected account/source state changed; review again.','account.containment_changed');}$deadline->check('account.witness_timeout');
    }
    /** Scoped capability observation, not a caller-supplied approval. Foreign execution contexts cannot borrow it. */
    public function factorContainmentActive(StateFactorContainment $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function factorContainmentCurrent(StateFactorContainment $plan,string $operation):void
    {
        if(!$this->factorContainmentActive($plan,$operation)){throw new SecurityException('An exact active containment context is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Containment authority changed before SQL commit.','account.witness_corrupt');}$d[2]->currentFactors($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Containment approval expired.','account.containment_expired');}
    }
    /** Fixed physical factor destruction only. Durable pending precedes files; no arbitrary work callback is accepted. */
    public function containFactors(StateFactorContainmentReview $review,StateFactorContainment $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact containment credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact covered containment plan.','configuration.state_containment');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->factorContainmentSelection($review,$plan,$state,$control,$deadline);$this->checkBudget($requestBudget,'final',$deadline);$this->factorContainmentSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before containment approval.','account.witness_corrupt');}
            $prepared=$plan->prepared();if($prepared['observed']!==$review->metadata()['observed']){throw new SecurityException('Physical effect manifest changed before persistence.','account.containment_changed');}$v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);$pending['remediation']=['review'=>$v,'phase'=>'pending','operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'completed'=>null,'after'=>null,'manifest'=>$prepared['manifest']];
            // Budget the larger completed receipt before consuming approval or changing the authority.
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Containment receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeFactors($review,$actor,$token,$grant);$control->currentFactors($review,$actor,$token);$this->factorContainmentSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during containment approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Containment approval expired.','account.containment_expired');}$pending['remediation']['grant']=$permit->id();$pending['remediation']['started']=$now;
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->factorContainmentCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->contained($operation);$this->checkBudget($requestBudget,'final',$deadline);$this->factorContainmentCurrent($plan,$operation);if($plan->contained($operation)!==$after){throw new StorageException('Contained source changed before final persistence.','account.containment_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentFactors($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Containment approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Factor containment completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    /** The immutable manifest was sealed before any original physical write. */
    public function factorContainmentManifest(StateFactorContainment $plan,string $operation,array $manifest):bool
    {
        if(!$this->factorContainmentActive($plan,$operation)){return false;}$d=($this->containment)();return ($d[8]['remediation']['manifest']??null)===$manifest;
    }
    private function resolutionState(array $state):int
    {
        if($this->format!==3||$state['status']!=='quarantined'||!isset($state['remediation'])||$state['remediation']['phase']!=='pending'||!StateFactorContainmentReview::valid($state['remediation']['review'])||!isset($state['remediation']['manifest'])){throw new SecurityException('An exact pending physical manifest is required.','account.factor_resolution_state');}
        $sequence=isset($state['remediation']['resolution'])?$state['remediation']['resolution']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('Resolution history exceeds its bound.','account.witness_capacity');}return $sequence;
    }
    public function factorResolutionReview(StateFactorResolution $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateFactorResolutionReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact physical resolution plan.','configuration.factor_resolution');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token):StateFactorResolutionReview{
            $state=$this->read($handle);$sequence=$this->resolutionState($state);if($state['remediation']['manifest']!==$plan->manifest()){throw new SecurityException('Resolution manifest differs from the persisted original effects.','account.factor_resolution_changed');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
            $control->reviewResolution($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>'resolve_factors','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateFactorResolutionReview.1.'.StateFactorResolutionReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Pending source changed during resolution review.','account.factor_resolution_changed');}return new StateFactorResolutionReview($v);
        },false,$deadline);
    }
    private function factorResolutionSelection(StateFactorResolutionReview $review,StateFactorResolution $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$sequence=$this->resolutionState($state);
        if(!$plan->boundTo($this)||$state['remediation']['manifest']!==$plan->manifest()||!$d[1]->verify($v['key'],'SoSecurity.Account.StateFactorResolutionReview.1.'.StateFactorResolutionReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Resolution selection differs from the exact pending authority.','account.factor_resolution_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution selection expired.','account.containment_expired');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Resolution bytes changed; review again.','account.factor_resolution_changed');}$deadline->check('account.witness_timeout');
    }
    public function factorResolutionActive(StateFactorResolution $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function factorResolutionCurrent(StateFactorResolution $plan,string $operation):void
    {
        if(!$this->factorResolutionActive($plan,$operation)){throw new SecurityException('An exact active physical resolution is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Resolution authority changed before physical commit.','account.witness_corrupt');}$d[2]->currentResolution($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Resolution approval expired.','account.containment_expired');}
    }
    /** New independent approval only; fixed persisted null envelopes, never original credentials or arbitrary work. */
    public function resolveFactors(StateFactorResolutionReview $review,StateFactorResolution $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact resolution credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact physical resolution plan.','configuration.factor_resolution');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->factorResolutionSelection($review,$plan,$state,$control,$deadline);$this->checkBudget($requestBudget,'final',$deadline);$this->factorResolutionSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before resolution approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);$pending['remediation']['resolution']=['review'=>$v,'operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'previous'=>$v['authority']];
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Resolution receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeResolution($review,$actor,$token,$grant);$control->currentResolution($review,$actor,$token);$this->factorResolutionSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during resolution approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired.','account.containment_expired');}$pending['remediation']['resolution']['grant']=$permit->id();$pending['remediation']['resolution']['started']=$now;
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->factorResolutionCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->contained($operation);$this->checkBudget($requestBudget,'final',$deadline);$this->factorResolutionCurrent($plan,$operation);if($plan->contained($operation)!==$after){throw new StorageException('Physical source changed before resolution persistence.','account.factor_resolution_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentResolution($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Physical resolution completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    private function accountResolutionState(array $state):int
    {
        if($this->format!==3||$state['status']!=='quarantined'||!isset($state['remediation'])||$state['remediation']['phase']!=='pending'||!StateContainmentReview::valid($state['remediation']['review'])||!isset($state['remediation']['manifest'])||!StateAccountManifest::valid($state['remediation']['manifest'])){throw new SecurityException('An exact pending account manifest is required.','account.account_resolution_state');}
        $sequence=isset($state['remediation']['resolution'])?$state['remediation']['resolution']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('Resolution history exceeds its bound.','account.witness_capacity');}return $sequence;
    }
    public function accountResolutionReview(StateAccountResolution $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateAccountResolutionReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact account resolution plan.','configuration.account_resolution');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token):StateAccountResolutionReview{
            $state=$this->read($handle);$sequence=$this->accountResolutionState($state);if($state['remediation']['manifest']!==$plan->manifest()){throw new SecurityException('Resolution manifest differs from the persisted original effects.','account.account_resolution_changed');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
            $control->reviewAccountResolution($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>'resolve_accounts','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateAccountResolutionReview.1.'.StateAccountResolutionReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Pending source changed during resolution review.','account.account_resolution_changed');}return new StateAccountResolutionReview($v);
        },false,$deadline);
    }
    private function accountResolutionSelection(StateAccountResolutionReview $review,StateAccountResolution $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$sequence=$this->accountResolutionState($state);
        if(!$plan->boundTo($this)||$state['remediation']['manifest']!==$plan->manifest()||!$d[1]->verify($v['key'],'SoSecurity.Account.StateAccountResolutionReview.1.'.StateAccountResolutionReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Resolution selection differs from the exact pending authority.','account.account_resolution_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution selection expired.','account.containment_expired');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Resolution bytes changed; review again.','account.account_resolution_changed');}$deadline->check('account.witness_timeout');
    }
    public function accountResolutionActive(StateAccountResolution $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function accountResolutionCurrent(StateAccountResolution $plan,string $operation):void
    {
        if(!$this->accountResolutionActive($plan,$operation)){throw new SecurityException('An exact active account resolution is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Resolution authority changed before account commit.','account.witness_corrupt');}$d[2]->currentAccountResolution($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Resolution approval expired.','account.containment_expired');}
    }
    /** New independent approval only; fixed persisted disabling results, never original credentials or arbitrary work. */
    public function resolveAccounts(StateAccountResolutionReview $review,StateAccountResolution $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact resolution credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact account resolution plan.','configuration.account_resolution');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->accountResolutionSelection($review,$plan,$state,$control,$deadline);$this->checkBudget($requestBudget,'final',$deadline);$this->accountResolutionSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before resolution approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);$pending['remediation']['resolution']=['review'=>$v,'operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'previous'=>$v['authority']];
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Resolution receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeAccountResolution($review,$actor,$token,$grant);$control->currentAccountResolution($review,$actor,$token);$this->accountResolutionSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during resolution approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired.','account.containment_expired');}$pending['remediation']['resolution']['grant']=$permit->id();$pending['remediation']['resolution']['started']=$now;
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->accountResolutionCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->contained($this,$operation);$this->checkBudget($requestBudget,'final',$deadline);$this->accountResolutionCurrent($plan,$operation);if($plan->contained($this,$operation)!==$after){throw new StorageException('Account source changed before resolution persistence.','account.account_resolution_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentAccountResolution($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Account resolution completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    private function credentialInstallationState(array $state,bool $resolution):int
    {
        if(!$resolution){return $this->containmentState($state);}
        if($this->format!==3||$state['status']!=='quarantined'||!isset($state['remediation'])||$state['remediation']['phase']!=='pending'||!StateCredentialInstallReview::valid($state['remediation']['review'])||$state['remediation']['review']['purpose']!=='install_credentials'||!StateCredentialInstallManifest::valid($state['remediation']['manifest']??null)){throw new SecurityException('An exact pending credential installation is required.','account.credential_installation_state');}
        $sequence=isset($state['remediation']['resolution'])?$state['remediation']['resolution']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('Installation resolution capacity exhausted.','account.witness_capacity');}return $sequence;
    }
    public function credentialInstallationReview(StateCredentialInstallation $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateCredentialInstallReview{return $this->credentialReview($plan,$control,$actor,$token,$requestBudget,false);}
    public function credentialResolutionReview(StateCredentialInstallation $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateCredentialInstallReview{return $this->credentialReview($plan,$control,$actor,$token,$requestBudget,true);}
    private function credentialReview(StateCredentialInstallation $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget,bool $resolution):StateCredentialInstallReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact account resolution plan.','configuration.credential_installation');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token,$resolution):StateCredentialInstallReview{
            $state=$this->read($handle);$sequence=$this->credentialInstallationState($state,$resolution);if($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state)){throw new SecurityException('Resolution manifest differs from the persisted original effects.','account.credential_installation_changed');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
            $control->reviewInstallation($this->binding,$actor,$token);if(!$resolution&&!$plan->candidateCurrent()){throw new SecurityException('The exact live confirmed candidate is required.','account.credentials_unconfirmed');}$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>$resolution?'resolve_credentials':'install_credentials','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$resolution?$now+120:min($now+120,$plan->manifest()['expires']),'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateCredentialInstallReview.1.'.StateCredentialInstallReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Pending source changed during resolution review.','account.credential_installation_changed');}return new StateCredentialInstallReview($v);
        },false,$deadline);
    }
    private function credentialInstallationSelection(StateCredentialInstallReview $review,StateCredentialInstallation $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$resolution=$v['purpose']==='resolve_credentials';$sequence=$this->credentialInstallationState($state,$resolution);
        if(!$plan->boundTo($this)||($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state))||!$d[1]->verify($v['key'],'SoSecurity.Account.StateCredentialInstallReview.1.'.StateCredentialInstallReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Resolution selection differs from the exact pending authority.','account.credential_installation_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution selection expired.','account.containment_expired');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Resolution bytes changed; review again.','account.credential_installation_changed');}$deadline->check('account.witness_timeout');
    }
    public function credentialInstallationActive(StateCredentialInstallation $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function credentialInstallationCurrent(StateCredentialInstallation $plan,string $operation):void
    {
        if(!$this->credentialInstallationActive($plan,$operation)){throw new SecurityException('An exact active account resolution is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Resolution authority changed before account commit.','account.witness_corrupt');}$d[2]->currentInstallation($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Resolution approval expired.','account.containment_expired');}
    }
    /** New independent approval only; fixed persisted disabling results, never original credentials or arbitrary work. */
    public function installCredentials(StateCredentialInstallReview $review,StateCredentialInstallation $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact resolution credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact account resolution plan.','configuration.credential_installation');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->credentialInstallationSelection($review,$plan,$state,$control,$deadline);$control->currentInstallation($review,$actor,$token);if($review->metadata()['purpose']==='install_credentials'&&!$plan->candidateCurrent()){throw new SecurityException('The exact live candidate changed.','account.credentials_unconfirmed');}$this->checkBudget($requestBudget,'final',$deadline);$this->credentialInstallationSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before resolution approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);if($v['purpose']==='install_credentials'){$pending['remediation']=['review'=>$v,'phase'=>'pending','operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'completed'=>null,'after'=>null,'manifest'=>$plan->manifest()];}else{$pending['remediation']['resolution']=['review'=>$v,'operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'previous'=>$v['authority']];}
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$future=$v;$future['purpose']='resolve_credentials';$future['sequence']=1000000;$future['issued']=PHP_INT_MAX-31536121;$future['expires']=PHP_INT_MAX-31536001;$largest['remediation']['resolution']=['review'=>$future,'operator'=>str_repeat('0',64),'grant'=>str_repeat('0',32),'started'=>PHP_INT_MAX-31536002,'previous'=>str_repeat('0',64)];if(isset($largest['recovery_audit'])){$largest['recovery_audit']['sequence']=256;}$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Resolution receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeInstallation($review,$actor,$token,$grant);$control->currentInstallation($review,$actor,$token);$this->credentialInstallationSelection($review,$plan,$state,$control,$deadline);if($v['purpose']==='install_credentials'&&!$plan->candidateCurrent()){throw new SecurityException('The exact live candidate changed before publication.','account.credentials_unconfirmed');}
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during resolution approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired.','account.containment_expired');}if($v['purpose']==='install_credentials'){$pending['remediation']['grant']=$permit->id();$pending['remediation']['started']=$now;}else{$pending['remediation']['resolution']['grant']=$permit->id();$pending['remediation']['resolution']['started']=$now;}
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->credentialInstallationCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->installed($this,$operation);$this->checkBudget($requestBudget,'final',$deadline);$this->credentialInstallationCurrent($plan,$operation);if($plan->installed($this,$operation)!==$after){throw new StorageException('Account source changed before resolution persistence.','account.credential_installation_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentInstallation($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Account resolution completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    private function validCredentialRemediation(array $state):bool
    {
        $r=$state['remediation'];$fields=['review','phase','operator','grant','started','completed','after','manifest'];if(isset($r['resolution'])){$fields[]='resolution';}if(array_keys($r)!==$fields||!StateCredentialInstallReview::valid($r['review'])||$r['review']['purpose']!=='install_credentials'||!StateCredentialInstallManifest::valid($r['manifest'])||!in_array($r['phase'],['pending','complete'],true)||!is_int($r['started'])){return false;}$v=$r['review'];$m=$r['manifest'];
        foreach(['operator','grant'] as $k){if(!is_string($r[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$r[$k])!==1){return false;}}
        if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$m['context']!==$state['context']||$m['generation']!==$state['generation']||$v['plan']!==hash('sha256','SoSecurity.Account.StateCredentialInstallation.1.'.StateCredentialInstallManifest::fingerprint($m))||$r['started']<$v['issued']||$r['started']>=$v['expires']){return false;}$started=$r['started'];
        if(isset($r['resolution'])){$q=$r['resolution'];if(!is_array($q)||array_keys($q)!==['review','operator','grant','started','previous']||!StateCredentialInstallReview::valid($q['review'])||$q['review']['purpose']!=='resolve_credentials'||!is_int($q['started'])){return false;}$v=$q['review'];foreach(['operator','grant','previous'] as $k){if(!is_string($q[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$q[$k])!==1){return false;}}if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$v['plan']!==$r['review']['plan']||$v['issued']<$r['started']||$q['started']<$v['issued']||$q['started']>=$v['expires']||$q['previous']!==$v['authority']){return false;}$started=$q['started'];}
        return $r['phase']==='pending'?($r['completed']===null&&$r['after']===null):(is_int($r['completed'])&&$r['completed']>=$started&&$r['completed']<$v['expires']&&is_string($r['after'])&&preg_match('/\A[a-f0-9]{64}\z/D',$r['after'])===1);
    }
    private function apiKeyRetirementState(array $state,bool $resolution):int
    {
        if(!$resolution){return $this->containmentState($state);}
        if($this->format!==3||$state['status']!=='quarantined'||!isset($state['remediation'])||$state['remediation']['phase']!=='pending'||!StateApiKeyReview::valid($state['remediation']['review'])||$state['remediation']['review']['purpose']!=='retire_api_keys'||!StateApiKeyManifest::valid($state['remediation']['manifest']??null)){throw new SecurityException('An exact pending API key retirement is required.','account.api_key_state');}
        $sequence=isset($state['remediation']['resolution'])?$state['remediation']['resolution']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('API retirement resolution capacity exhausted.','account.witness_capacity');}return $sequence;
    }
    public function apiKeyRetirementReview(StateApiKeyRetirement $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateApiKeyReview{return $this->apiKeyReview($plan,$control,$actor,$token,$requestBudget,false);}
    public function apiKeyResolutionReview(StateApiKeyRetirement $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateApiKeyReview{return $this->apiKeyReview($plan,$control,$actor,$token,$requestBudget,true);}
    private function apiKeyReview(StateApiKeyRetirement $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget,bool $resolution):StateApiKeyReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact API key retirement plan.','configuration.api_key_retirement');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token,$resolution):StateApiKeyReview{
            $state=$this->read($handle);$sequence=$this->apiKeyRetirementState($state,$resolution);if($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state)){throw new SecurityException('Resolution manifest differs from the persisted original effects.','account.api_key_changed');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
            $control->reviewApiKeys($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>$resolution?'resolve_api_keys':'retire_api_keys','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateApiKeyReview.1.'.StateApiKeyReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Pending source changed during resolution review.','account.api_key_changed');}return new StateApiKeyReview($v);
        },false,$deadline);
    }
    private function apiKeyRetirementSelection(StateApiKeyReview $review,StateApiKeyRetirement $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$resolution=$v['purpose']==='resolve_api_keys';$sequence=$this->apiKeyRetirementState($state,$resolution);
        if(!$plan->boundTo($this)||($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state))||!$d[1]->verify($v['key'],'SoSecurity.Account.StateApiKeyReview.1.'.StateApiKeyReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Resolution selection differs from the exact pending authority.','account.api_key_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution selection expired.','account.containment_expired');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Resolution bytes changed; review again.','account.api_key_changed');}$deadline->check('account.witness_timeout');
    }
    public function apiKeyRetirementActive(StateApiKeyRetirement $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function apiKeyRetirementCurrent(StateApiKeyRetirement $plan,string $operation):void
    {
        if(!$this->apiKeyRetirementActive($plan,$operation)){throw new SecurityException('An exact active API key retirement is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Resolution authority changed before epoch commit.','account.witness_corrupt');}$d[2]->currentApiKeys($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Resolution approval expired.','account.containment_expired');}
    }
    /** New independent approval only; fixed persisted API epoch results, never old bearer material or arbitrary work. */
    public function retireApiKeys(StateApiKeyReview $review,StateApiKeyRetirement $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact resolution credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact API key retirement plan.','configuration.api_key_retirement');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->apiKeyRetirementSelection($review,$plan,$state,$control,$deadline);$control->currentApiKeys($review,$actor,$token);$this->checkBudget($requestBudget,'final',$deadline);$this->apiKeyRetirementSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before resolution approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);if($v['purpose']==='retire_api_keys'){$pending['remediation']=['review'=>$v,'phase'=>'pending','operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'completed'=>null,'after'=>null,'manifest'=>$plan->manifest()];}else{$pending['remediation']['resolution']=['review'=>$v,'operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'previous'=>$v['authority']];}
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$future=$v;$future['purpose']='resolve_api_keys';$future['sequence']=1000000;$future['issued']=PHP_INT_MAX-31536121;$future['expires']=PHP_INT_MAX-31536001;$largest['remediation']['resolution']=['review'=>$future,'operator'=>str_repeat('0',64),'grant'=>str_repeat('0',32),'started'=>PHP_INT_MAX-31536002,'previous'=>str_repeat('0',64)];if(isset($largest['recovery_audit'])){$largest['recovery_audit']['sequence']=256;}$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Resolution receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeApiKeys($review,$actor,$token,$grant);$control->currentApiKeys($review,$actor,$token);$this->apiKeyRetirementSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during resolution approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired.','account.containment_expired');}if($v['purpose']==='retire_api_keys'){$pending['remediation']['grant']=$permit->id();$pending['remediation']['started']=$now;}else{$pending['remediation']['resolution']['grant']=$permit->id();$pending['remediation']['resolution']['started']=$now;}
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->apiKeyRetirementCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->installed($this,$operation);$this->checkBudget($requestBudget,'final',$deadline);$this->apiKeyRetirementCurrent($plan,$operation);if($plan->installed($this,$operation)!==$after){throw new StorageException('Account source changed before resolution persistence.','account.api_key_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentApiKeys($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('API key retirement completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    private function validApiKeyRemediation(array $state):bool
    {
        $r=$state['remediation'];$fields=['review','phase','operator','grant','started','completed','after','manifest'];if(isset($r['resolution'])){$fields[]='resolution';}if(array_keys($r)!==$fields||!StateApiKeyReview::valid($r['review'])||$r['review']['purpose']!=='retire_api_keys'||!StateApiKeyManifest::valid($r['manifest'])||!in_array($r['phase'],['pending','complete'],true)||!is_int($r['started'])){return false;}$v=$r['review'];$m=$r['manifest'];
        foreach(['operator','grant'] as $k){if(!is_string($r[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$r[$k])!==1){return false;}}
        if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$m['context']!==$state['context']||$m['generation']!==$state['generation']||$v['plan']!==hash('sha256','SoSecurity.Account.StateApiKeyRetirement.1.'.StateApiKeyManifest::fingerprint($m))||$r['started']<$v['issued']||$r['started']>=$v['expires']){return false;}$started=$r['started'];
        if(isset($r['resolution'])){$q=$r['resolution'];if(!is_array($q)||array_keys($q)!==['review','operator','grant','started','previous']||!StateApiKeyReview::valid($q['review'])||$q['review']['purpose']!=='resolve_api_keys'||!is_int($q['started'])){return false;}$v=$q['review'];foreach(['operator','grant','previous'] as $k){if(!is_string($q[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$q[$k])!==1){return false;}}if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$v['plan']!==$r['review']['plan']||$v['issued']<$r['started']||$q['started']<$v['issued']||$q['started']>=$v['expires']||$q['previous']!==$v['authority']){return false;}$started=$q['started'];}
        return $r['phase']==='pending'?($r['completed']===null&&$r['after']===null):(is_int($r['completed'])&&$r['completed']>=$started&&$r['completed']<$v['expires']&&is_string($r['after'])&&preg_match('/\A[a-f0-9]{64}\z/D',$r['after'])===1);
    }
    private function proofRetirementState(array $state,bool $resolution):int
    {
        if(!$resolution){return $this->containmentState($state);}
        if($this->format!==3||$state['status']!=='quarantined'||!isset($state['remediation'])||$state['remediation']['phase']!=='pending'||!StateProofReview::valid($state['remediation']['review'])||$state['remediation']['review']['purpose']!=='retire_proofs'||!StateProofManifest::valid($state['remediation']['manifest']??null)){throw new SecurityException('An exact pending Proof retirement is required.','account.proof_state');}
        $sequence=isset($state['remediation']['resolution'])?$state['remediation']['resolution']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('Proof retirement resolution capacity exhausted.','account.witness_capacity');}return $sequence;
    }
    public function proofRetirementReview(StateProofRetirement $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateProofReview{return $this->proofReview($plan,$control,$actor,$token,$requestBudget,false);}
    public function proofResolutionReview(StateProofRetirement $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateProofReview{return $this->proofReview($plan,$control,$actor,$token,$requestBudget,true);}
    private function proofReview(StateProofRetirement $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget,bool $resolution):StateProofReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact Proof retirement plan.','configuration.proof_retirement');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token,$resolution):StateProofReview{
            $state=$this->read($handle);$sequence=$this->proofRetirementState($state,$resolution);if($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state)){throw new SecurityException('Resolution manifest differs from the persisted original effects.','account.proof_changed');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
            $control->reviewProofs($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>$resolution?'resolve_proofs':'retire_proofs','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateProofReview.1.'.StateProofReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Pending source changed during resolution review.','account.proof_changed');}return new StateProofReview($v);
        },false,$deadline);
    }
    private function proofRetirementSelection(StateProofReview $review,StateProofRetirement $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$resolution=$v['purpose']==='resolve_proofs';$sequence=$this->proofRetirementState($state,$resolution);
        if(!$plan->boundTo($this)||($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state))||!$d[1]->verify($v['key'],'SoSecurity.Account.StateProofReview.1.'.StateProofReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Resolution selection differs from the exact pending authority.','account.proof_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution selection expired.','account.containment_expired');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Resolution bytes changed; review again.','account.proof_changed');}$deadline->check('account.witness_timeout');
    }
    public function proofRetirementActive(StateProofRetirement $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function proofRetirementCurrent(StateProofRetirement $plan,string $operation):void
    {
        if(!$this->proofRetirementActive($plan,$operation)){throw new SecurityException('An exact active Proof retirement is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Resolution authority changed before epoch commit.','account.witness_corrupt');}$d[2]->currentProofs($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Resolution approval expired.','account.containment_expired');}
    }
    /** New independent approval only; fixed persisted API epoch results, never old bearer material or arbitrary work. */
    public function retireProofs(StateProofReview $review,StateProofRetirement $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact resolution credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact Proof retirement plan.','configuration.proof_retirement');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->proofRetirementSelection($review,$plan,$state,$control,$deadline);$control->currentProofs($review,$actor,$token);$this->checkBudget($requestBudget,'final',$deadline);$this->proofRetirementSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before resolution approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);if($v['purpose']==='retire_proofs'){$pending['remediation']=['review'=>$v,'phase'=>'pending','operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'completed'=>null,'after'=>null,'manifest'=>$plan->manifest()];}else{$pending['remediation']['resolution']=['review'=>$v,'operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'previous'=>$v['authority']];}
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$future=$v;$future['purpose']='resolve_proofs';$future['sequence']=1000000;$future['issued']=PHP_INT_MAX-31536121;$future['expires']=PHP_INT_MAX-31536001;$largest['remediation']['resolution']=['review'=>$future,'operator'=>str_repeat('0',64),'grant'=>str_repeat('0',32),'started'=>PHP_INT_MAX-31536002,'previous'=>str_repeat('0',64)];if(isset($largest['recovery_audit'])){$largest['recovery_audit']['sequence']=256;}$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Resolution receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeProofs($review,$actor,$token,$grant);$control->currentProofs($review,$actor,$token);$this->proofRetirementSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during resolution approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired.','account.containment_expired');}if($v['purpose']==='retire_proofs'){$pending['remediation']['grant']=$permit->id();$pending['remediation']['started']=$now;}else{$pending['remediation']['resolution']['grant']=$permit->id();$pending['remediation']['resolution']['started']=$now;}
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->proofRetirementCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->installed($this,$operation);$this->checkBudget($requestBudget,'final',$deadline);$this->proofRetirementCurrent($plan,$operation);if($plan->installed($this,$operation)!==$after){throw new StorageException('Account source changed before resolution persistence.','account.proof_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentProofs($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('Proof retirement completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    private function validProofRemediation(array $state):bool
    {
        $r=$state['remediation'];$fields=['review','phase','operator','grant','started','completed','after','manifest'];if(isset($r['resolution'])){$fields[]='resolution';}if(array_keys($r)!==$fields||!StateProofReview::valid($r['review'])||$r['review']['purpose']!=='retire_proofs'||!StateProofManifest::valid($r['manifest'])||!in_array($r['phase'],['pending','complete'],true)||!is_int($r['started'])){return false;}$v=$r['review'];$m=$r['manifest'];
        foreach(['operator','grant'] as $k){if(!is_string($r[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$r[$k])!==1){return false;}}
        if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$m['context']!==$state['context']||$m['generation']!==$state['generation']||$v['count']!==count($m['entries'])||$v['plan']!==hash('sha256','SoSecurity.Account.StateProofRetirement.1.'.StateProofManifest::fingerprint($m))||$r['started']<$v['issued']||$r['started']>=$v['expires']){return false;}$started=$r['started'];
        if(isset($r['resolution'])){$q=$r['resolution'];if(!is_array($q)||array_keys($q)!==['review','operator','grant','started','previous']||!StateProofReview::valid($q['review'])||$q['review']['purpose']!=='resolve_proofs'||!is_int($q['started'])){return false;}$v=$q['review'];foreach(['operator','grant','previous'] as $k){if(!is_string($q[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$q[$k])!==1){return false;}}if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$v['plan']!==$r['review']['plan']||$v['issued']<$r['started']||$q['started']<$v['issued']||$q['started']>=$v['expires']||$q['previous']!==$v['authority']){return false;}$started=$q['started'];}
        return $r['phase']==='pending'?($r['completed']===null&&$r['after']===null):(is_int($r['completed'])&&$r['completed']>=$started&&$r['completed']<$v['expires']&&is_string($r['after'])&&preg_match('/\A[a-f0-9]{64}\z/D',$r['after'])===1);
    }
    private function workerHandoffState(array $state,bool $resolution):int
    {
        if(!$resolution){return $this->containmentState($state);}
        if($this->format!==3||$state['status']!=='quarantined'||!isset($state['remediation'])||$state['remediation']['phase']!=='pending'||!StateWorkerReview::valid($state['remediation']['review'])||$state['remediation']['review']['purpose']!=='handoff_workers'||!StateWorkerManifest::valid($state['remediation']['manifest']??null)){throw new SecurityException('An exact pending worker handoff is required.','account.worker_state');}
        $sequence=isset($state['remediation']['resolution'])?$state['remediation']['resolution']['review']['sequence']+1:1;if($sequence>1000000){throw new StorageException('worker handoff resolution capacity exhausted.','account.witness_capacity');}return $sequence;
    }
    public function workerHandoffReview(StateWorkerHandoff $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateWorkerReview{return $this->workerReview($plan,$control,$actor,$token,$requestBudget,false);}
    public function workerResolutionReview(StateWorkerHandoff $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget):StateWorkerReview{return $this->workerReview($plan,$control,$actor,$token,$requestBudget,true);}
    private function workerReview(StateWorkerHandoff $plan,StateRetirementControl $control,string $actor,string $token,callable $requestBudget,bool $resolution):StateWorkerReview
    {
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact worker handoff plan.','configuration.worker_handoff');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($plan,$control,$actor,$token,$resolution):StateWorkerReview{
            $state=$this->read($handle);$sequence=$this->workerHandoffState($state,$resolution);if($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state)){throw new SecurityException('Resolution manifest differs from the persisted original effects.','account.worker_changed');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
            $control->reviewWorkers($this->binding,$actor,$token);$now=$control->now();$observed=$plan->observed();$deadline->check('account.witness_timeout');$d=$this->d();
            $v=['purpose'=>$resolution?'resolve_workers':'handoff_workers','context'=>$this->binding,'generation'=>$this->generation,'revision'=>$state['revision'],'sequence'=>$sequence,'authority'=>hash('sha256',self::json($state)),'observed'=>$observed,'plan'=>$plan->binding(),'count'=>$plan->count(),'control'=>$control->binding(),'issued'=>$now,'expires'=>$now+120,'nonce'=>bin2hex(random_bytes(32)),'key'=>$d[1]->currentId()];
            $v['seal']=bin2hex($d[1]->sign('SoSecurity.Account.StateWorkerReview.1.'.StateWorkerReview::encode($v)));if($this->read($handle)!==$state||$this->snapshot($deadline)!==$observed){throw new StorageException('Pending source changed during resolution review.','account.worker_changed');}return new StateWorkerReview($v);
        },false,$deadline);
    }
    private function workerHandoffSelection(StateWorkerReview $review,StateWorkerHandoff $plan,array $state,StateRetirementControl $control,Deadline $deadline):void
    {
        $v=$review->metadata();$signed=$v;unset($signed['seal']);$d=$this->d();$now=$control->now();$resolution=$v['purpose']==='resolve_workers';$sequence=$this->workerHandoffState($state,$resolution);
        if(!$plan->boundTo($this)||($resolution?($state['remediation']['manifest']!==$plan->manifest()):!$plan->initialFor($state))||!$d[1]->verify($v['key'],'SoSecurity.Account.StateWorkerReview.1.'.StateWorkerReview::encode($signed),hex2bin($v['seal']))||$v['context']!==$this->binding||$v['generation']!==$this->generation||$v['revision']!==$state['revision']||$v['sequence']!==$sequence||$v['authority']!==hash('sha256',self::json($state))||$v['plan']!==$plan->binding()||$v['count']!==$plan->count()||$v['control']!==$control->binding()){throw new SecurityException('Resolution selection differs from the exact pending authority.','account.worker_changed');}
        if($now<$v['issued']||$now>=$v['expires']){throw new SecurityException('Resolution selection expired.','account.containment_expired');}if(!$control->independentOf($this)){throw new ConfigurationException('Use physically independent resolution approval.','configuration.state_independence');}
        if($plan->observed()!==$v['observed']){throw new SecurityException('Resolution bytes changed; review again.','account.worker_changed');}$deadline->check('account.witness_timeout');
    }
    public function workerHandoffActive(StateWorkerHandoff $plan,string $operation,?string $observed=null):bool
    {
        if(!$plan->boundTo($this)||$this->containment===null||!$this->busy||$this->lockOwner!==self::owner()){return false;}$d=($this->containment)();return $d[0]===$plan&&$d[1]===$operation&&is_resource($d[7])&&($observed===null||$observed===$d[6]);
    }
    public function workerHandoffCurrent(StateWorkerHandoff $plan,string $operation):void
    {
        if(!$this->workerHandoffActive($plan,$operation)){throw new SecurityException('An exact active worker handoff is required.','account.containment_context');}$d=($this->containment)();$this->validateHandle($d[7]);if($this->read($d[7])!==$d[8]){throw new StorageException('Resolution authority changed before epoch commit.','account.witness_corrupt');}$d[2]->currentWorkers($d[9],$d[3],$d[4]);if($d[2]->now()>=$d[5]){throw new SecurityException('Resolution approval expired.','account.containment_expired');}
    }
    /** New independent approval only; fixed persisted worker results, never old bearer material or arbitrary work. */
    public function handoffWorkers(StateWorkerReview $review,StateWorkerHandoff $plan,StateRetirementControl $control,string $actor,string $token,string $grant,callable $requestBudget):array
    {
        if(strlen($actor)<1||strlen($actor)>256||preg_match('//u',$actor)!==1||preg_match('/[\x00-\x1f\x7f]/',$actor)||\SoSecurity\Auth\SessionRegistry::reference($token)===null||\SoSecurity\Operation\State::reference($grant,'og1')===null){throw new \SoSecurity\Exception\ValidationException('Use bounded exact resolution credentials.','account.containment_input');}
        if(!$plan->boundTo($this)){throw new ConfigurationException('Use the exact worker handoff plan.','configuration.worker_handoff');}$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($review,$plan,$control,$actor,$token,$grant,$requestBudget):array{
            $state=$this->read($handle);$this->workerHandoffSelection($review,$plan,$state,$control,$deadline);$control->currentWorkers($review,$actor,$token);$this->checkBudget($requestBudget,'final',$deadline);$this->workerHandoffSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed before resolution approval.','account.witness_corrupt');}
            $v=$review->metadata();$pending=$state;unset($pending['key'],$pending['seal']);if($v['purpose']==='handoff_workers'){$pending['remediation']=['review'=>$v,'phase'=>'pending','operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'completed'=>null,'after'=>null,'manifest'=>$plan->manifest()];}else{$pending['remediation']['resolution']=['review'=>$v,'operator'=>$control->actorDigest($actor),'grant'=>str_repeat('0',32),'started'=>$control->now(),'previous'=>$v['authority']];}
            $largest=$pending;$largest['remediation']['phase']='complete';$largest['remediation']['completed']=PHP_INT_MAX-31536001;$largest['remediation']['after']=str_repeat('0',64);$future=$v;$future['purpose']='resolve_workers';$future['sequence']=1000000;$future['issued']=PHP_INT_MAX-31536121;$future['expires']=PHP_INT_MAX-31536001;$largest['remediation']['resolution']=['review'=>$future,'operator'=>str_repeat('0',64),'grant'=>str_repeat('0',32),'started'=>PHP_INT_MAX-31536002,'previous'=>str_repeat('0',64)];if(isset($largest['recovery_audit'])){$largest['recovery_audit']['sequence']=256;}$largest['key']=$this->d()[1]->currentId();$largest['seal']=str_repeat('0',64);if(strlen(self::json($largest))>$this->receiptLimit()){throw new StorageException('Resolution receipt exceeds its fixed authority bound.','account.witness_capacity');}
            $permit=$control->consumeWorkers($review,$actor,$token,$grant);$control->currentWorkers($review,$actor,$token);$this->workerHandoffSelection($review,$plan,$state,$control,$deadline);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during resolution approval.','account.witness_corrupt');}$now=$control->now();if($now>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired.','account.containment_expired');}if($v['purpose']==='handoff_workers'){$pending['remediation']['grant']=$permit->id();$pending['remediation']['started']=$now;}else{$pending['remediation']['resolution']['grant']=$permit->id();$pending['remediation']['resolution']['started']=$now;}
            try{
                $this->write($handle,$pending,$deadline);$sealed=$this->read($handle);$operation=$v['nonce'];$expires=$permit->expiresAt();$observed=$v['observed'];$this->containment=static function()use($plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review):array{return [$plan,$operation,$control,$actor,$token,$expires,$observed,$handle,$sealed,$review];};
                $this->workerHandoffCurrent($plan,$operation);$plan->apply($this,$operation,$deadline);$after=$plan->installed($this,$operation);$this->checkBudget($requestBudget,'final',$deadline);$this->workerHandoffCurrent($plan,$operation);if($plan->installed($this,$operation)!==$after){throw new StorageException('Account source changed before resolution persistence.','account.worker_changed');}
                $complete=$pending;$complete['remediation']['phase']='complete';$complete['remediation']['completed']=$control->now();$complete['remediation']['after']=$after;$this->containment=null;$this->write($handle,$complete,$deadline);$control->currentWorkers($review,$actor,$token);if($control->now()>=$permit->expiresAt()){throw new SecurityException('Resolution approval expired during persistence.','account.containment_expired');}$result=$this->read($handle);unset($result['key'],$result['seal']);return $result;
            }catch(\Throwable $error){throw new StorageException('worker handoff completion is unknown; keep this generation quarantined.','account.completion_unknown',$error);}
            finally{$this->containment=null;}
        },false,$deadline);
    }
    private function validWorkerRemediation(array $state):bool
    {
        $r=$state['remediation'];$fields=['review','phase','operator','grant','started','completed','after','manifest'];if(isset($r['resolution'])){$fields[]='resolution';}if(array_keys($r)!==$fields||!StateWorkerReview::valid($r['review'])||$r['review']['purpose']!=='handoff_workers'||!StateWorkerManifest::valid($r['manifest'])||!in_array($r['phase'],['pending','complete'],true)||!is_int($r['started'])){return false;}$v=$r['review'];$m=$r['manifest'];
        foreach(['operator','grant'] as $k){if(!is_string($r[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$r[$k])!==1){return false;}}
        if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$m['context']!==$state['context']||$m['generation']!==$state['generation']||$v['count']!==1||$v['plan']!==hash('sha256','SoSecurity.Account.StateWorkerHandoff.1.'.StateWorkerManifest::fingerprint($m))||$r['started']<$v['issued']||$r['started']>=$v['expires']){return false;}$started=$r['started'];
        if(isset($r['resolution'])){$q=$r['resolution'];if(!is_array($q)||array_keys($q)!==['review','operator','grant','started','previous']||!StateWorkerReview::valid($q['review'])||$q['review']['purpose']!=='resolve_workers'||!is_int($q['started'])){return false;}$v=$q['review'];foreach(['operator','grant','previous'] as $k){if(!is_string($q[$k])||preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$q[$k])!==1){return false;}}if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$v['plan']!==$r['review']['plan']||$v['issued']<$r['started']||$q['started']<$v['issued']||$q['started']>=$v['expires']||$q['previous']!==$v['authority']){return false;}$started=$q['started'];}
        return $r['phase']==='pending'?($r['completed']===null&&$r['after']===null):(is_int($r['completed'])&&$r['completed']>=$started&&$r['completed']<$v['expires']&&is_string($r['after'])&&preg_match('/\A[a-f0-9]{64}\z/D',$r['after'])===1);
    }
    private function validRemediation(array $state):bool
    {
        $r=$state['remediation'];if(!is_array($r)){return false;}if(StateWorkerReview::valid($r['review']??null)){return $this->validWorkerRemediation($state);}if(StateProofReview::valid($r['review']??null)){return $this->validProofRemediation($state);}if(StateApiKeyReview::valid($r['review']??null)){return $this->validApiKeyRemediation($state);}if(StateCredentialInstallReview::valid($r['review']??null)){return $this->validCredentialRemediation($state);}$fields=['review','phase','operator','grant','started','completed','after'];$factor=StateFactorContainmentReview::valid($r['review']??null);
        if(array_key_exists('manifest',$r)){
            $fields[]='manifest';if($factor){if(!StateFactorManifest::valid($r['manifest'])||count($r['manifest']['entries'])>$r['review']['count']){return false;}}
            else{if(!StateContainmentReview::valid($r['review']??null)||!StateAccountManifest::valid($r['manifest'])||count($r['manifest']['rows'])!==$r['review']['count']||$r['manifest']['plan']!==$r['review']['plan']||$r['manifest']['operation']!==$r['review']['nonce']||$r['manifest']['observed']!==$r['review']['observed']){return false;}}
            if(array_key_exists('resolution',$r)){$fields[]='resolution';}
        }
        if(array_keys($r)!==$fields||(!$factor&&!StateContainmentReview::valid($r['review']??null))||!in_array($r['phase'],['pending','complete'],true)||!is_int($r['started'])){return false;}$v=$r['review'];
        foreach(['operator','grant'] as $k){if(!is_string($r[$k])||!preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$r[$k])){return false;}}
        if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$r['started']<$v['issued']||$r['started']>=$v['expires']){return false;}
        if(isset($r['resolution'])){
            $q=$r['resolution'];if(!is_array($q)||array_keys($q)!==['review','operator','grant','started','previous']||!($factor?StateFactorResolutionReview::valid($q['review']):StateAccountResolutionReview::valid($q['review']))||!is_int($q['started'])){return false;}$v=$q['review'];
            foreach(['operator','grant','previous'] as $k){if(!is_string($q[$k])||!preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$q[$k])){return false;}}
            if($v['context']!==$state['context']||$v['generation']!==$state['generation']||$v['revision']!==$state['revision']||$v['count']!==count($r['manifest'][$factor?'entries':'rows'])||$v['issued']<$r['started']||$q['started']<$v['issued']||$q['started']>=$v['expires']||$q['previous']!==$v['authority']){return false;}
            $started=$q['started'];
        }else{$started=$r['started'];}
        return $r['phase']==='pending'?($r['completed']===null&&$r['after']===null):(is_int($r['completed'])&&$r['completed']>=$started&&$r['completed']<$v['expires']&&is_string($r['after'])&&preg_match('/\A[a-f0-9]{64}\z/D',$r['after'])===1);
    }
    private function validSuccessor(array $v):bool
    {
        $c=$v['successor'];if(!is_array($c)||array_keys($c)!==['review','control','operator','grant','staged_at','predecessor_operation','predecessor_intent']||!StateSuccessorReview::valid($c['review'])||!is_int($c['staged_at'])||$c['staged_at']<$c['review']['issued']||$c['staged_at']>=$c['review']['expires']){return false;}
        foreach(['control','operator','grant'] as $k){if(!is_string($c[$k])||!preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$c[$k])){return false;}}
        if(!is_string($c['predecessor_operation'])||!preg_match('/\A[a-f0-9]{64}\z/D',$c['predecessor_operation'])||!StateOperation::valid($c['predecessor_intent'])||$c['predecessor_intent']['scope']!==$v['intent']['scope']||StateOperation::digestOf($c['predecessor_intent'])!==$c['review']['intent']){return false;}
        $r=$c['review'];$i=$v['intent'];return $r['context']===$v['context']&&$r['revision']+1===$v['revision']&&$r['generation']===$v['generation']&&$r['predecessor']===$v['lineage']&&$r['nonce']===$v['operation']&&$r['control']===$c['control']&&$i['kind']==='recovery'&&$i['actor']===$c['operator']&&$i['target']===$v['context']&&$i['policy']===$c['control']&&$i['authorized_at']===$c['staged_at'];
    }
    private function validClosure(array $v):bool
    {
        $c=$v['closure'];if(!is_array($c)||array_keys($c)!==['review','control','operator','grant','closed_at']||!StateRetirementReview::valid($c['review'])||!is_int($c['closed_at'])||$c['closed_at']<$c['review']['issued']||$c['closed_at']>=$c['review']['expires']){return false;}
        foreach(['control','operator','grant'] as $k){if(!is_string($c[$k])||!preg_match($k==='grant'?'/\A[a-f0-9]{32}\z/D':'/\A[a-f0-9]{64}\z/D',$c[$k])){return false;}}
        $r=$c['review'];return $r['context']===$v['context']&&$r['revision']===$v['revision']&&$r['operation']===$v['operation']&&$r['before']===$v['digest']&&$r['intent']===$v['intent_digest']&&$r['control']===$c['control'];
    }
    /** Read-only candidate binding. It neither installs credentials nor grants recovery permission. */
    public function credentialSelection(StateAccountContainment $accounts,array $manifest,string $subject,StateBoundary $drafts,callable $requestBudget):array
    {
        if(!$accounts->boundTo($this)||!$accounts->acceptsManifest($manifest)){throw new ConfigurationException('Use the exact account plan and original containment manifest.','configuration.state_credentials');}$manifest=json_decode(json_encode($manifest),true,6);Guard::label($subject);$deadline=$this->preflight($requestBudget);
        return $this->locked(function($handle,Deadline $deadline)use($accounts,$manifest,$subject,$drafts):array{
            $state=$this->read($handle);$this->containmentState($state);if($this->recoveryAudit===null||!isset($state['recovery_audit'])||!$state['recovery_audit']['complete']||!$drafts->independentOf($this)){throw new ConfigurationException('Credential preparation needs complete anchored recovery history and independent protected draft storage.','configuration.state_credentials');}
            $found=false;$offset=0;do{$page=$this->recoveryAudit->page($this->binding,$state['recovery_audit'],$offset,$deadline);foreach($page['events'] as $event){$r=$event['after']['remediation']??null;if(is_array($r)&&$r['phase']==='complete'&&StateContainmentReview::valid($r['review'])&&($r['manifest']??null)===$manifest){$found=true;break;}}$offset=$page['offset'];}while(!$found&&$page['more']);if(!$found){throw new SecurityException('The exact account set lacks a completed audited containment.','account.credentials_changed');}
            $target=$accounts->credentialTarget($manifest,$subject);if($this->read($handle)!==$state){throw new StorageException('Recovery authority changed during credential selection.','account.credentials_changed');}return ['authority'=>hash('sha256',self::json($state)),'context'=>$this->binding,'generation'=>$this->generation,'plan'=>$accounts->binding(),'operation'=>$manifest['operation'],'scope'=>$target['scope'],'subject'=>$subject,'row'=>$target['row'],'observed'=>$target['observed']];
        },false,$deadline);
    }
    /** @internal Observation only: the native audit cannot manufacture this owning write scope. */
    public function recoveryAuditActive(StateRecoveryAudit $audit,string $before,string $after):bool
    {
        if(!$this->busy||$this->lockOwner!==self::owner()||$this->auditWrite===null||$this->recoveryAudit!==$audit){return false;}$v=($this->auditWrite)();return $v[0]===$audit&&$v[1]===$before&&$v[2]===$after;
    }
    /** Four newest-to-oldest transitions per page; changing the root invalidates an earlier cursor. */
    public function recoveryHistory(callable $requestBudget,?array $cursor=null):array
    {
        if($cursor!==null&&(array_keys($cursor)!==['authority','offset']||!is_string($cursor['authority'])||preg_match('/\A[a-f0-9]{64}\z/D',$cursor['authority'])!==1||!is_int($cursor['offset'])||$cursor['offset']<0||$cursor['offset']>255)){throw new \SoSecurity\Exception\ValidationException('Use a bounded exact recovery history cursor.','account.recovery_audit_cursor');}
        if($cursor!==null){$cursor=['authority'=>$cursor['authority'],'offset'=>$cursor['offset']];}
        $deadline=$this->preflight($requestBudget);return $this->locked(function($handle,Deadline $deadline)use($cursor):array{
            $state=$this->read($handle);$authority=hash('sha256',self::json($state));if($cursor!==null&&$cursor['authority']!==$authority){throw new SecurityException('Recovery history changed; restart from its exact root.','account.recovery_audit_cursor');}
            if($this->recoveryAudit===null||!isset($state['recovery_audit'])){throw new StorageException('No anchored durable recovery history exists.','account.recovery_audit_required');}$offset=$cursor['offset']??0;if($offset>=$state['recovery_audit']['sequence']){throw new \SoSecurity\Exception\ValidationException('Recovery cursor is outside the exact history.','account.recovery_audit_cursor');}$page=$this->recoveryAudit->page($this->binding,$state['recovery_audit'],$offset,$deadline);
            return ['authority'=>$authority,'anchor'=>$state['recovery_audit'],'events'=>$page['events'],'cursor'=>$page['more']?['authority'=>$authority,'offset'=>$page['offset']]:null];
        },false,$deadline);
    }
    /** Metadata only; no callback, provisioning or database adoption. */
    public function inspect(callable $requestBudget):array{$deadline=$this->preflight($requestBudget);return $this->locked(function($handle):array{$v=$this->read($handle);unset($v['key'],$v['seal']);return $v;},false,$deadline);}
    private function preflight(callable $budget):Deadline
    {
        if($this->busy){throw new StorageException('Nested state witness operation.','account.witness_nested');}$this->busy=true;$deadline=new Deadline($this->milliseconds);
        try{$this->checkBudget($budget,'public',$deadline);return $deadline;}finally{$this->busy=false;}
    }
    private function checkBudget(callable $budget,string $phase,Deadline $deadline):void
    {
        try{$allowed=$budget($phase);}catch(\Throwable $error){throw new DependencyException('Independent request budget unavailable.','account.witness_budget',$error);}$deadline->check('account.witness_timeout');if($allowed!==true){throw new SecurityException('Independent request budget denied.','account.witness_budget');}
    }
    private function locked(callable $body,bool $create=false,?Deadline $budget=null)
    {
        if($this->busy){throw new StorageException('Nested state witness operation.','account.witness_nested');}$owner=self::owner();$this->busy=true;$this->lockOwner=$owner;$handle=false;
        try{
            $deadline=$budget??new Deadline($this->milliseconds);$this->lockDeadline=$deadline;$this->checkDirectory();clearstatcache(true,$this->path);$before=@lstat($this->path);
            if($create){if($before!==false){throw new StorageException('State witness already exists.','account.witness_exists');}$handle=@fopen($this->path,'x+b');if($handle!==false&&!@chmod($this->path,0600)){throw new StorageException('Cannot secure state witness.','account.witness_io');}}
            else{if(!is_array($before)){throw new StorageException('Independent state witness is missing.','account.witness_missing');}$this->validateStat($before);$handle=@fopen($this->path,'r+b');}
            if($handle===false){throw new StorageException('Cannot open state witness.','account.witness_io');}$this->validateHandle($handle,$create?null:$before);
            while(true){$this->assertOwner();if(@flock($handle,LOCK_EX|LOCK_NB,$blocked)){break;}if(!$blocked){throw new StorageException('Cannot acquire witness authority.','account.witness_io');}$deadline->check('account.witness_timeout');usleep(1000);}
            $deadline->check('account.witness_timeout');$this->validateHandle($handle);return $body($handle,$deadline);
        }finally{try{if(is_resource($handle)){if(self::owner()===$owner){@flock($handle,LOCK_UN);}fclose($handle);}}finally{$this->busy=false;$this->lockOwner=null;$this->lockDeadline=null;}}
    }
    private static function owner():array
    {
        $pid=getmypid();if(!is_int($pid)||$pid<1){throw new StorageException('Cannot identify witness process.','account.witness_context');}$fiber=PHP_VERSION_ID>=80100&&class_exists('Fiber',false)?\Fiber::getCurrent():null;return [$pid,$fiber===null?null:spl_object_id($fiber)];
    }
    private function assertOwner():void{if(!$this->busy||$this->lockOwner!==self::owner()){throw new StorageException('Witness work belongs to a different execution context.','account.witness_context');}}
    private function checkDirectory():void
    {
        clearstatcache(true,$this->directory);$s=@lstat($this->directory);$b=$this->directoryStat;
        if(realpath($this->directory)!==$this->directory||!is_array($s)||$s['dev']!==$b['dev']||$s['ino']!==$b['ino']||$s['uid']!==$b['uid']||($s['mode']&0170077)!==0040000){throw new StorageException('Independent witness directory changed.','account.witness_corrupt');}
    }
    private function receiptLimit():int{return $this->format===3?16384:($this->format===2?4096:1024);}
    private function validateStat(array $s):void
    {
        if(($s['mode']&0170777)!==0100600||$s['nlink']!==1||$s['uid']!==$this->directoryStat['uid']||$s['size']>$this->receiptLimit()||($this->inode!==null&&$this->inode!==$s['dev'].':'.$s['ino'])){throw new StorageException('Invalid independent witness file.','account.witness_corrupt');}
    }
    private function validateHandle($handle,?array $before=null):void
    {
        $this->assertOwner();$this->checkDirectory();clearstatcache(true,$this->path);$named=@lstat($this->path);$opened=fstat($handle);
        if(!is_array($named)||!is_array($opened)){throw new StorageException('Witness disappeared.','account.witness_corrupt');}$this->validateStat($named);$this->validateStat($opened);
        foreach([$named,$before??$named] as $s){if($s['dev']!==$opened['dev']||$s['ino']!==$opened['ino']){throw new StorageException('Witness inode changed.','account.witness_corrupt');}}$this->inode=$opened['dev'].':'.$opened['ino'];
    }
    /** @phpstan-impure */
    private function read($handle):array
    {
        $this->validateHandle($handle);if(!rewind($handle)){throw new StorageException('Cannot seek state witness.','account.witness_io');}$limit=$this->receiptLimit();$raw=stream_get_contents($handle,$limit+1);$v=is_string($raw)?json_decode($raw,true,$this->format===3?12:6):null;$fields=['format','context','revision','status','digest','operation'];if($this->format===3){$fields[]='generation';$fields[]='lineage';}if($this->format>=2){$fields[]='intent';$fields[]='intent_digest';if(is_array($v)&&($v['status']??null)==='closed'){$fields[]='closure';}if($this->format===3&&is_array($v)&&($v['status']??null)==='quarantined'){$fields[]='successor';if(array_key_exists('remediation',$v)){$fields[]='remediation';}}}if($this->format>=2&&is_array($v)&&array_key_exists('recovery_audit',$v)){$fields[]='recovery_audit';}$fields[]='key';$fields[]='seal';
        if(!is_string($raw)||strlen($raw)>$limit||!is_array($v)||array_keys($v)!==$fields||$v['format']!==$this->format||$v['context']!==$this->binding||!is_int($v['revision'])||$v['revision']<1||!in_array($v['status'],$this->format===3?['current','pending','closed','quarantined']:($this->format===2?['current','pending','closed']:['current','pending']),true)||!is_string($v['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])){throw new StorageException('Invalid state witness.','account.witness_corrupt');}
        foreach(['digest','operation','seal'] as $key){if(!is_string($v[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$v[$key])){throw new StorageException('Invalid state witness digest.','account.witness_corrupt');}}
        if($this->format>=2&&(!StateOperation::valid($v['intent'])||$v['intent']['scope']!==StateOperation::scope($this->d()[5])||!is_string($v['intent_digest'])||!hash_equals(StateOperation::digestOf($v['intent']),$v['intent_digest'])||($v['intent']['kind']==='initial'&&($v['revision']!==1||!($v['status']==='current'||($v['status']==='closed'&&is_array($v['closure']??null)&&is_array($v['closure']['review']??null)&&($v['closure']['review']['purpose']??null)==='retire_stale')))))){throw new StorageException('Invalid persisted state operation.','account.witness_corrupt');}
        if($this->format===3){foreach(['generation','lineage'] as $key){if(!is_string($v[$key])||!preg_match('/\A[a-f0-9]{64}\z/D',$v[$key])){throw new StorageException('Invalid state generation.','account.witness_corrupt');}}}
        if($v['status']==='quarantined'&&!$this->validSuccessor($v)){throw new StorageException('Invalid successor isolation receipt.','account.witness_corrupt');}
        if(array_key_exists('remediation',$v)&&!$this->validRemediation($v)){throw new StorageException('Invalid account containment receipt.','account.witness_corrupt');}
        if($v['status']==='closed'&&!$this->validClosure($v)){throw new StorageException('Invalid closed authority receipt.','account.witness_corrupt');}
        $seal=$v['seal'];$signed=$v;unset($signed['seal']);$d=$this->d();if(!$d[1]->verify($v['key'],'SoSecurity.Account.LocalStateWitness.Seal.'.$this->format.'.'.self::json($signed),hex2bin($seal))||self::json($v)!==$raw){throw new StorageException('Invalid state witness seal.','account.witness_corrupt');}if($this->format===3&&$v['generation']!==$this->generation){throw new StorageException('This reader belongs to a different state generation.','account.witness_generation');}if(array_key_exists('recovery_audit',$v)){if($this->recoveryAudit===null||!StateRecoveryAudit::validAnchor($v['recovery_audit'])){throw new StorageException('Reload the exact required recovery audit.','account.recovery_audit_required');}$deadline=$this->lockDeadline??new Deadline($this->milliseconds);$this->recoveryAudit->verify($this->binding,$v['recovery_audit'],$deadline);if(in_array($v['status'],['closed','quarantined'],true)&&!$this->recoveryAudit->matchesHead($this->binding,$v['recovery_audit'],$v,$deadline)){throw new StorageException('Recovery root differs from its durable transition.','account.recovery_audit_corrupt');}}return $v;
    }
    private function write($handle,array $state,Deadline $deadline):void
    {
        $this->validateHandle($handle);$d=$this->d();$parent=$state['recovery_audit']??null;unset($state['recovery_audit']);
        if($this->recoveryAudit!==null&&in_array($state['status'],['closed','quarantined'],true)){
            if(!rewind($handle)){throw new StorageException('Cannot read the exact recovery predecessor.','account.witness_io');}$before=stream_get_contents($handle,16385);if(!is_string($before)||strlen($before)>16384){throw new StorageException('Invalid recovery predecessor.','account.recovery_audit_corrupt');}$previous=json_decode($before,true,12);if(!is_array($previous)){throw new StorageException('Invalid recovery predecessor.','account.recovery_audit_corrupt');}$parent=$previous['recovery_audit']??null;$after=self::json($state);$audit=$this->recoveryAudit;$this->auditWrite=static function()use($audit,$before,$after):array{return [$audit,$before,$after];};
            try{$parent=$audit->append($this,$before,$after,$parent,$deadline);}finally{$this->auditWrite=null;}
        }
        if($parent!==null){$state['recovery_audit']=$parent;}$state['key']=$d[1]->currentId();$state['seal']=bin2hex($d[1]->sign('SoSecurity.Account.LocalStateWitness.Seal.'.$this->format.'.'.self::json($state)));$raw=self::json($state);if(strlen($raw)>$this->receiptLimit()){throw new StorageException('Witness receipt exceeds its fixed bound.','account.witness_capacity');}$deadline->check('account.witness_timeout');
        if(!rewind($handle)||!ftruncate($handle,0)||fwrite($handle,$raw)!==strlen($raw)||!fflush($handle)){throw new StorageException('Cannot write state witness.','account.witness_io');}
        if(call_user_func($d[3],$handle)!==true){throw new StorageException('Witness stable storage flush was not confirmed.','account.witness_durability');}$deadline->check('account.witness_timeout');$this->validateHandle($handle);
        if($this->read($handle)!==$state){throw new StorageException('Witness changed during persistence.','account.witness_corrupt');}
    }
    public function __debugInfo():array{return ['state_witness'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload independent state authority.','configuration.state_witness');}
    public function __wakeup():void{throw new ConfigurationException('Reload independent state authority.','configuration.state_witness');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State witness is immutable.','configuration.immutable');}
}
