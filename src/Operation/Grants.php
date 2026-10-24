<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Prepare -> new reauthentication -> confirmation -> one-use consume. execute owns non-retried business SQL; store callbacks stay pure. */
final class Grants
{
    private $store;
    private $sessions;
    private $authorizer;
    private $guard;
    private $policy;
    private $clock;
    private $boundary;
    private $nativeDeadline;private $completedPermit;
    private $statePolicy;private $rolePolicy;private $stateBusy=false;private $admitted;
    private $addressPolicy;private $addressAuthorization;private $addressDeadline;
    public function __construct(AtomicStore $store,SessionRegistry $sessions,Authorizer $authorizer,callable $requestGuard,?Policy $policy = null,?Clock $clock = null,?\SoSecurity\Account\StateBoundary $boundary = null,?\SoSecurity\Account\StateAccountPolicy $statePolicy = null)
    {
        if(($boundary===null&&($sessions->requiresStateBoundary()||\SoSecurity\Storage\FileStateBoundary::protects($store)))||($boundary!==null&&!$sessions->boundTo($boundary))){throw new ConfigurationException('Protected grants require the exact session operation authority.','configuration.state_boundary');}
        $clock=$clock??new SystemClock();$role=$statePolicy===null?null:($sessions->operationRolePolicy($authorizer)??$sessions->operationSnapshotPolicy($authorizer,$statePolicy));
        if($statePolicy!==null&&($boundary===null||!$statePolicy->credentialContext($store,$sessions,$clock,$boundary)||$role===null)){throw new ConfigurationException('Use the exact native grant graph and a pure role or captured-facts policy without effectful audit.','configuration.state_permission');}$this->statePolicy=$statePolicy;$this->rolePolicy=$role;
        $this->boundary=$boundary;$this->store=$boundary===null?$store:$boundary->protect($store);$this->sessions=$sessions;$this->authorizer=$authorizer;$this->guard=$requestGuard;$this->policy=$policy ?? new Policy();$this->clock=$clock;
    }
    /** Explicit configuration adapter, never an authorization result. */
    public function forAddress(\SoSecurity\Account\StateAccountPolicy $policy):self
    {
        if($this->statePolicy!==null||$this->addressPolicy!==null||$this->boundary===null||$this->boundary->active()||!$policy->credentialContext($this->store,$this->sessions,$this->clock,$this->boundary)){throw new ConfigurationException('Use the exact ordinary grants graph outside an active address effect.','configuration.state_permission');}
        $authorization=$this->sessions->operationRolePolicy($this->authorizer)??$this->sessions->operationSnapshotPolicy($this->authorizer,$policy);
        if($authorization===null){throw new ConfigurationException('Use a matching pure role or captured-facts address policy without audit.','configuration.state_permission');}
        $copy=new self($this->store,$this->sessions,$this->authorizer,$this->guard,$this->policy,$this->clock,$this->boundary);$copy->addressPolicy=$policy;$copy->addressAuthorization=$authorization;return $copy;
    }
    /** Consume under the same already-started native address deadline. */
    public function consumeForAddress(string $scope,string $subject,string $sessionToken,Intent $intent,string $grant,\SoSecurity\Support\Deadline $deadline):?Permit
    {
        if($this->statePolicy!==null||$this->boundary===null||$this->addressDeadline!==null){throw new ConfigurationException('Use one native address proof consumption.','configuration.state_request_nested');}
        if(!in_array($intent->action(),['account.address.request','account.address.complete'],true)||$intent->resource()->type()!=='account'||$intent->resource()->scope()!==$scope||$intent->resource()->id()!==$subject||$intent->fields()!==['address']){throw new SecurityException('Use an exact address operation intent.','authorization.denied');}
        return $this->boundary->withAddressConsumption($deadline,function()use($scope,$subject,$sessionToken,$intent,$grant,$deadline):?Permit{
            $this->addressDeadline=$deadline;
            try{$permit=$this->consumeInternal($scope,$subject,$sessionToken,$intent,$grant);$deadline->check('account.timeout');return $permit;}
            finally{$this->addressDeadline=null;}
        });
    }
    /** Read-only return check after address SQL has finished; never consumes or restores a proof. */
    public function addressCompletion(\SoSecurity\Account\StateAccountPolicy $policy,Permit $permit,\SoSecurity\Auth\VerifiedSession $before,\SoSecurity\Auth\Account $after,?string $token,\SoSecurity\Support\Deadline $deadline):void
    {
        $role=$this->addressPolicy===null?$this->sessions->operationRolePolicy($this->authorizer):$this->addressAuthorization;
        if($this->statePolicy!==null||$this->boundary===null||$this->addressDeadline!==null||!$policy->credentialContext($this->store,$this->sessions,$this->clock,$this->boundary)||$role===null||($this->addressPolicy!==null&&!hash_equals($this->addressPolicy->binding(),$policy->binding()))){throw new ConfigurationException('Use the exact native address return policy.','configuration.state_permission');}
        $intent=$permit->intent();$scope=$after->scope();$subject=$after->subject();
        if(!in_array($intent->action(),['account.address.request','account.address.complete'],true)||$intent->resource()->type()!=='account'||$intent->resource()->scope()!==$scope||$intent->resource()->id()!==$subject||$intent->fields()!==['address']||($token===null)!==($intent->action()==='account.address.complete')||$before->account()->scope()!==$scope||$before->account()->subject()!==$subject||!hash_equals($before->account()->fingerprint(),$permit->account()->fingerprint())){throw new SecurityException('Use the exact consumed address intent.','authorization.denied');}
        $this->boundary->withAddressConsumption($deadline,function()use($policy,$permit,$before,$after,$token,$deadline,$role,$intent,$scope,$subject):void{
            $seen=$this->finished($before->authenticatedAt(),$permit->expiresAt());$expected=$policy->activePolicyDigest($this->boundary);$deadline->check('account.timeout');
            $view=$policy->credentialView($scope,$subject,$token,$expected);$current=$view===null?null:$view['session'];
            if($view===null||!hash_equals($view['account']->fingerprint(),$after->fingerprint())){throw new SecurityException('Address completion identity changed.','operation.changed');}
            if($token!==null&&($current===null||$current->id()!==$before->id()||$current->createdAt()!==$before->createdAt()||$current->authenticatedAt()!==$before->authenticatedAt()||$current->method()!==$before->method()||$current->expiresAt()<$before->expiresAt())){throw new SecurityException('Address completion session changed.','operation.changed');}
            $deadline->check('account.timeout');$decision=$role instanceof \SoSecurity\Authorization\SnapshotPolicy?$role->evaluate($policy,$expected,$view['account'],$intent->action(),$intent->resource(),$intent->fields()):$role->decide($view['account'],$intent->action(),$intent->resource(),$intent->fields());
            $deadline->check('account.timeout');if($decision===null||!$decision->allowed()||array_diff($intent->fields(),$decision->fields())){throw new SecurityException('Address completion authorization denied.','authorization.denied');}
            $at=$this->finished($seen,$permit->expiresAt());if(!$this->policy->accepts($before,$at)||($current!==null&&!$this->policy->accepts($current,$at))){throw new SecurityException('Address completion authentication expired.','operation.authentication');}
        });
    }
    private function proofStore(string $scope):\SoSecurity\Storage\ProofEpochStore{return new \SoSecurity\Storage\ProofEpochStore($this->store,'operations',$scope);}
    /** Fixed scope-wide epoch description, not write authority. No identity provider or callbacks are executed. */
    public function stateRetirementEpoch(\SoSecurity\Storage\FileStore $store,Clock $clock,string $scope,string $epoch):?array
    {
        if(($this->store!==$store&&(!$this->store instanceof \SoSecurity\Account\WitnessedStore||!$this->store->protects($store)))||$this->clock!==$clock){return null;}
        return \SoSecurity\Storage\ProofEpochStore::retirement($store,'operations',$scope,$epoch,$this->policy->fingerprint());
    }
    public function recoveryContext(SessionRegistry $sessions,\SoSecurity\Account\StateBoundary $boundary,\SoSecurity\Account\StateAccountPolicy $policy):bool
    {
        return $this->addressPolicy===null&&$this->statePolicy===null&&$this->boundary===$boundary&&$this->sessions===$sessions&&$this->store instanceof \SoSecurity\Account\WitnessedStore&&$this->store->boundTo($boundary)&&$policy->recoveryClock($this->clock)&&$this->policy->minimumStrength()===2&&$this->policy->maximumAge()<=300&&$this->policy->ttl()<=120&&!array_diff($this->policy->methods(),['totp','webauthn']);
    }
    public function policy(): Policy { return $this->policy; }
    public function stateContext(SessionRegistry $sessions,\SoSecurity\Account\StateBoundary $boundary,Clock $clock):bool
    {
        return $this->statePolicy===null&&$this->boundary===$boundary&&$this->sessions===$sessions&&$this->store instanceof \SoSecurity\Account\WitnessedStore&&$this->store->boundTo($boundary)&&($this->clock===$clock||($this->clock instanceof SystemClock&&$clock instanceof SystemClock));
    }
    /** Pure admission for the exact ordinary grants object used inside native address effects. */
    public function addressAdmission(\SoSecurity\Account\StateAccountPolicy $policy,string $scope,string $subject,string $token,Intent $intent,?string $grant,string $expected):?array
    {
        $role=$this->addressPolicy===null?$this->sessions->operationRolePolicy($this->authorizer):$this->addressAuthorization;
        if($this->statePolicy!==null||$this->boundary===null||$this->boundary->active()||!$policy->credentialContext($this->store,$this->sessions,$this->clock,$this->boundary)||$role===null||($this->addressPolicy!==null&&!hash_equals($this->addressPolicy->binding(),$policy->binding()))){throw new ConfigurationException('Use the exact covered grants store and a pure role or captured-facts policy for address admission.','configuration.state_permission');}
        State::context($scope,$subject,$this->now());if(SessionRegistry::reference($token)===null){throw new SecurityException('Current address authentication required.','operation.authentication');}
        try{$allowed=($this->guard)();}catch(\Throwable $error){throw new DependencyException('Operation request protection unavailable.','operation.request_unavailable');}if($allowed!==true){throw new SecurityException('Operation request protection failed.','operation.request_denied');}
        $view=$policy->credentialView($scope,$subject,$token,$expected);if($view===null||$view['session']===null){throw new SecurityException('Current address authentication required.','operation.authentication');}$session=$view['session'];$at=$this->now();
        if($session->expiresAt()<=$at||$session->createdAt()>$at||$session->authenticatedAt()>$at||SessionRegistry::strength($session->method())<1||($grant!==null&&!$this->policy->accepts($session,$at))){throw new SecurityException('Recent approved address authentication required.','operation.authentication');}
        if($intent->resource()->scope()!==$scope){throw new SecurityException('Address object scope denied.','authorization.denied');}$decision=$role instanceof \SoSecurity\Authorization\SnapshotPolicy?$role->evaluate($policy,$expected,$session->account(),$intent->action(),$intent->resource(),$intent->fields()):$role->decide($session->account(),$intent->action(),$intent->resource(),$intent->fields());
        if($decision===null||!$decision->allowed()||array_diff($intent->fields(),$decision->fields())){throw new SecurityException('Address object or field authorization denied.','authorization.denied');}$reference=null;$entry=null;
        if($grant!==null){
            $reference=State::reference($grant,'og1');if($reference===null){return null;}$raw=$policy->credentialBytes(State::context($scope,$subject,$at),$expected);$context=\SoSecurity\Storage\ProofEpochStore::context('operations',$scope);$marker=\SoSecurity\Storage\ProofEpochStore::markerBytes($policy->credentialBytes(\SoSecurity\Storage\ProofEpochStore::key($context),$expected),$context);
            $state=State::read(\SoSecurity\Storage\ProofEpochStore::payload($raw===null?null:\SoSecurity\Storage\Codec::decode($raw,$at),$marker,$context),$this->policy,$at);$live=State::prepare($state,$this->policy,$at);$entry=$live['entries'][$reference['id']]??null;
            if($entry===null||$entry['phase']!=='granted'||!hash_equals($entry['digest'],$reference['digest'])||!hash_equals($entry['account'],$session->account()->fingerprint())||$entry['session']!==$session->id()||$entry['created']!==$session->createdAt()||!hash_equals($entry['session_digest'],hash('sha256',$token))){return null;}
            // A genuine proof with mismatched intent is still consumed by the original effect path.
        }
        $end=$this->now();if($end<$at){throw new StorageException('Address grant admission clock moved backwards.','operation.clock');}
        if($session->expiresAt()<=$end||($grant!==null&&!$this->policy->accepts($session,$end))||($entry!==null&&$entry['expires']<=$end)){return null;}
        return ['session'=>$session,'reference'=>$reference,'until'=>$entry===null?$session->expiresAt():min($session->expiresAt(),$entry['expires']),'policy'=>hash('sha256','SoSecurity.Operation.AddressAdmission.1.'.json_encode([$policy->binding(),$this->policy->fingerprint(),$role->fingerprint()]))];
    }
    public function begin(string $scope,string $subject,string $sessionToken,Intent $intent): Confirmation
    {
        return $this->nativeCall('begin',func_get_args());
    }
    private function beginInternal(string $scope,string $subject,string $sessionToken,Intent $intent): Confirmation
    {
        $this->guard();$facts=$this->facts($scope,$subject,$sessionToken,$intent,false);$now=$facts['now'];$key=State::context($scope,$subject,$now);
        $id=bin2hex(random_bytes(16));$token='oc1.'.$id.'.'.bin2hex(random_bytes(32));$reference=State::reference($token,'oc1');
        $entry=['phase'=>'pending','digest'=>$reference['digest'],'intent'=>$intent->fingerprint(),'account'=>$facts['account'],'session'=>$facts['session'],
            'created'=>$facts['created'],'session_digest'=>$facts['session_digest'],'issued'=>$now,'expires'=>min($now+$this->policy->ttl(),$facts['expires']),
            'authenticated'=>$facts['authenticated'],'method'=>$facts['method']];
        $this->proofStore($scope)->transact($key,function ($state) use ($now,$id,$entry) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);
            if (count($state['entries']) >= $this->policy->capacity() || isset($state['entries'][$id])) { throw new SecurityException('Pending operation capacity reached.','operation.capacity'); }
            $state['entries'][$id]=$entry;return State::change($state,null);
        });
        $this->finish($scope,$subject,$sessionToken,$intent,$facts,$entry,$reference,'pending',false);
        return new Confirmation($token,$intent,$entry['expires']);
    }
    public function confirm(string $scope,string $subject,string $sessionToken,Intent $intent,string $confirmation): ?Grant
    {
        return $this->nativeCall('confirm',func_get_args());
    }
    private function confirmInternal(string $scope,string $subject,string $sessionToken,Intent $intent,string $confirmation): ?Grant
    {
        $this->guard();$reference=State::reference($confirmation,'oc1');if ($reference===null) { return null; }
        $facts=$this->facts($scope,$subject,$sessionToken,$intent,true);$now=$facts['now'];$key=State::context($scope,$subject,$now);
        $token='og1.'.$reference['id'].'.'.bin2hex(random_bytes(32));$grantReference=State::reference($token,'og1');
        $entry=$this->proofStore($scope)->transact($key,function ($state) use ($now,$reference,$grantReference,$facts,$intent) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$reference['id']] ?? null;
            if ($entry===null || $entry['phase']!=='pending' || !hash_equals($entry['digest'],$reference['digest']) || !State::matches($entry,$facts)) { return State::change($state,null); }
            if (!hash_equals($entry['intent'],$intent->fingerprint())) { unset($state['entries'][$reference['id']]);return State::change($state,null); }
            if (hash_equals($entry['session_digest'],$facts['session_digest']) || $facts['authenticated']<$entry['issued']) { return State::change($state,null); }
            $entry['phase']='granted';$entry['digest']=$grantReference['digest'];$entry['session_digest']=$facts['session_digest'];
            $entry['authenticated']=$facts['authenticated'];$entry['method']=$facts['method'];
            $entry['expires']=min($entry['expires'],$facts['expires'],$facts['authenticated']+$this->policy->maximumAge());
            $state['entries'][$reference['id']]=$entry;return State::change($state,$entry);
        });
        if ($entry===null) { $this->finished($now);return null; }
        $this->finish($scope,$subject,$sessionToken,$intent,$facts,$entry,$grantReference,'granted',true);
        return new Grant($token,$entry['expires']);
    }
    public function consume(string $scope,string $subject,string $sessionToken,Intent $intent,string $grant): ?Permit
    {
        return $this->nativeCall('consume',func_get_args());
    }
    private function consumeInternal(string $scope,string $subject,string $sessionToken,Intent $intent,string $grant): ?Permit
    {
        $this->guard();$reference=State::reference($grant,'og1');if ($reference===null) { return null; }
        $facts=$this->facts($scope,$subject,$sessionToken,$intent,true);$now=$facts['now'];$key=State::context($scope,$subject,$now);
        $entry=$this->proofStore($scope)->transact($key,function ($state) use ($now,$reference,$facts,$intent) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$reference['id']] ?? null;
            if ($entry===null || $entry['phase']!=='granted' || !hash_equals($entry['digest'],$reference['digest']) || !State::matches($entry,$facts)
                || !hash_equals($entry['session_digest'],$facts['session_digest'])) { return State::change($state,null); }
            // The real bound credential is burned even when its operation data was tampered with.
            unset($state['entries'][$reference['id']]);
            if (!hash_equals($entry['intent'],$intent->fingerprint()) || $entry['authenticated']!==$facts['authenticated'] || $entry['method']!==$facts['method']) { return State::change($state,null); }
            $entry['expires']=min($entry['expires'],$facts['expires']);return State::change($state,$entry);
        });
        if ($entry===null) { $this->finished($now);return null; }
        $after=$this->finish($scope,$subject,$sessionToken,$intent,$facts,$entry,$reference,'granted',true);
        return new Permit($reference['id'],$intent,$after['authority']->account(),$after['session'],$after['method'],$after['authenticated'],$entry['expires']);
    }
    /** Current-session cancellation; request guard and current subject authentication are still mandatory. */
    public function revoke(string $scope,string $subject,string $sessionToken,string $id): bool
    {
        return $this->nativeCall('revoke',func_get_args())===true;
    }
    private function revokeInternal(string $scope,string $subject,string $sessionToken,string $id): bool
    {
        $this->guard();if (!State::hex($id,32)) { return false; }$facts=$this->facts($scope,$subject,$sessionToken,null,false);$now=$facts['now'];
        $result=$this->proofStore($scope)->transact(State::context($scope,$subject,$now),function ($state) use ($now,$facts,$id) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$id] ?? null;
            $exists=$entry!==null && State::matches($entry,$facts);if ($exists) { unset($state['entries'][$id]); }return State::change($state,$exists);
        });$this->finished($now);return $result;
    }
    /** Explicit subject-wide cancellation by a current authenticated account. Does not authorize business work. */
    public function revokeAll(string $scope,string $subject,string $sessionToken): void
    {
        $this->nativeCall('revokeAll',func_get_args());
    }
    private function revokeAllInternal(string $scope,string $subject,string $sessionToken): void
    {
        $this->guard();$facts=$this->facts($scope,$subject,$sessionToken,null,false);$now=$facts['now'];
        $this->proofStore($scope)->transact(State::context($scope,$subject,$now),function ($state) use ($now) { State::read($state,$this->policy,$now);return new Change(null,0,null); });$this->finished($now);
    }
    /** Native owned business unit. prepare reads server rows only; work uses the supplied PDO and permit once. */
    public function execute(string $scope,string $subject,string $sessionToken,string $grant,\PDO $connection,array $tables,callable $prepare,callable $work)
    {
        if($this->statePolicy===null||!$this->statePolicy->credentialSqlContext($connection,$tables)){throw new ConfigurationException('Declare exact native grant business PDO and complete tables.','configuration.state_business');}
        $names=array_keys($tables);sort($names);
        return $this->nativeCall('execute',[$scope,$subject,$sessionToken,$grant],function()use($scope,$subject,$sessionToken,$grant,$connection,$work){
            $permit=$this->consumeInternal($scope,$subject,$sessionToken,$this->admitted['intent'],$grant);if($permit===null){return null;}$this->completedPermit=$permit;$seen=$this->now();$unit=new \SoSecurity\Support\SqlTransaction($connection,$this->clock,30000);
            $live=function()use($permit,&$seen):void{$now=$this->now();if($now<$seen){throw new StorageException('Operation clock moved backwards.','operation.clock');}$seen=$now;if($permit->expiresAt()<=$now){throw new SecurityException('Operation expired during business commit.','operation.expired');}};
            return $unit->run(function()use($unit,$work,$connection,$permit){return $unit->invoke($work,[$connection,$permit],'operation.business_unavailable');},null,$live,$live,$this->nativeDeadline);
        },function(\SoSecurity\Auth\VerifiedSession $session)use($connection,$prepare):Intent{
            $localConnection=$connection;$localSession=$session;
            try{$intent=$prepare($localConnection,$localSession);}catch(SecurityException $e){throw $e;}catch(ConfigurationException $e){throw $e;}catch(\SoSecurity\Exception\ValidationException $e){throw $e;}catch(\Throwable $e){throw new DependencyException('Business intent loading unavailable.','operation.business_unavailable');}
            if(!$intent instanceof Intent){throw new ConfigurationException('Load a validated server business intent.','configuration.state_business');}return $intent;
        },$names);
    }
    private function nativeCall(string $method,array $args,?callable $effect=null,?callable $prepare=null,array $tables=[])
    {
        if($this->addressPolicy!==null){throw new ConfigurationException('Use the address adapter only through native address proof consumption.','configuration.state_permission');}
        $call=$method.'Internal';if($this->statePolicy===null){return $this->$call(...$args);}
        if($this->stateBusy||$this->boundary->active()){throw new ConfigurationException('Enter native grant requests once without an outer effect context.','configuration.state_request_nested');}$scope=$args[0];$this->boundary->assertScope($scope);State::context($scope,$args[1],$this->now());
        if(SessionRegistry::reference($args[2])===null){throw new SecurityException('Current operation session required.','operation.authentication');}$copy=[];foreach($args as $value){$copy[]=$value;}$args=$copy;$this->nativeDeadline=new \SoSecurity\Support\Deadline(30000);$this->completedPermit=null;$this->stateBusy=true;
        try{
            $work=$effect??function()use($call,$args){return $this->$call(...$args);};
            $result=$this->boundary->run('operations.'.($method==='revokeAll'?'revoke_all':$method),function()use($work){$this->nativeReview();return $work();},function(string $expected)use($method,$args,$prepare,$tables){return $this->nativeAdmission($method,$args,$expected,$prepare,$tables);},null,$this->nativeDeadline);
            $authority=$method==='execute'?$this->completedPermit:$result;
            if($authority instanceof Confirmation||$authority instanceof Grant||$authority instanceof Permit){$this->completion($method,$args,$authority->expiresAt());}
            return $result;
        }finally{$this->admitted=null;$this->completedPermit=null;$this->nativeDeadline=null;$this->stateBusy=false;}
    }
    /** Recheck returned authority without consuming or restoring a proof. */
    private function completion(string $method,array $args,int $expires):void
    {
        $admitted=$this->admitted;$this->admitted=null;$seen=$this->now();$current=null;$strong=$method!=='begin';
        $this->boundary->run('operations.'.$method.'_check',static function():void{throw new ConfigurationException('Operation completion is read only.','configuration.state_business');},function(string $expected)use($args,$admitted,$strong,$expires,&$seen,&$current):bool{
            $this->finished($seen,$expires);
            try{$allowed=($this->guard)();}catch(\Throwable $error){throw new DependencyException('Operation request protection unavailable.','operation.request_unavailable');}
            if($allowed!==true){throw new SecurityException('Operation request protection failed.','operation.request_denied');}
            $view=$this->statePolicy->credentialView($args[0],$args[1],$args[2],$expected);$current=$view===null?null:$view['session'];$old=$admitted['session'];
            if($current===null||$current->id()!==$old->id()||$current->createdAt()!==$old->createdAt()||$current->authenticatedAt()!==$old->authenticatedAt()||$current->method()!==$old->method()||!hash_equals($current->account()->fingerprint(),$old->account()->fingerprint())){throw new SecurityException('Current operation authentication required.','operation.authentication');}
            $intent=$admitted['intent'];
            if(!$intent instanceof Intent){throw new ConfigurationException('Current admitted intent required.','configuration.state_business');}
            $decision=$this->nativeDecision($current->account(),$intent->action(),$intent->resource(),$intent->fields(),$expected);
            if($decision===null||!$decision->allowed()||array_diff($intent->fields(),$decision->fields())){throw new SecurityException('Operation object or field authorization denied.','authorization.denied');}
            $seen=$this->finished($seen,$expires);
            if($current->expiresAt()<=$seen||($strong&&!$this->policy->accepts($current,$seen))){throw new SecurityException('Recent approved authentication required.','operation.authentication');}
            return false;
        },null,$this->nativeDeadline);
        $this->nativeDeadline->check('account.operation_timeout');$now=$this->finished($seen,$expires);
        if($current===null||$current->expiresAt()<=$now||($strong&&!$this->policy->accepts($current,$now))){throw new SecurityException('Recent approved authentication required.','operation.authentication');}
    }
    /** Pure native view and RolePolicy decision before pending; exact mismatches may intentionally burn a bound proof. */
    private function nativeAdmission(string $method,array $a,string $expected,?callable $prepare,array $tables)
    {
        $scope=$a[0];$subject=$a[1];$now=$this->now();
        try{$allowed=($this->guard)();}catch(\Throwable $e){throw new DependencyException('Operation request protection unavailable.','operation.request_unavailable');}if($allowed!==true){throw new SecurityException('Operation request protection failed.','operation.request_denied');}
        $view=$this->statePolicy->credentialView($scope,$subject,$a[2],$expected);if($view===null||$view['session']===null){throw new SecurityException('Current operation authentication required.','operation.authentication');}$session=$view['session'];$strong=in_array($method,['confirm','consume','execute'],true);$at=$this->now();
        if($at<$now){throw new StorageException('Operation clock moved backwards.','operation.clock');}if($session->expiresAt()<=$at||($strong&&!$this->policy->accepts($session,$at))){throw new SecurityException('Recent approved authentication required.','operation.authentication');}
        $intent=$prepare!==null?$prepare($session):(in_array($method,['begin','confirm','consume'],true)?$a[3]:null);
        if($intent!==null){if($intent->resource()->scope()!==$scope){throw new SecurityException('Operation resource scope denied.','authorization.denied');}$d=$this->nativeDecision($session->account(),$intent->action(),$intent->resource(),$intent->fields(),$expected);if($d===null||!$d->allowed()||array_diff($intent->fields(),$d->fields())){throw new SecurityException('Operation object or field authorization denied.','authorization.denied');}}
        $raw=$this->statePolicy->credentialBytes(State::context($scope,$subject,$at),$expected);$context=\SoSecurity\Storage\ProofEpochStore::context('operations',$scope);$marker=\SoSecurity\Storage\ProofEpochStore::markerBytes($this->statePolicy->credentialBytes(\SoSecurity\Storage\ProofEpochStore::key($context),$expected),$context);$state=State::read(\SoSecurity\Storage\ProofEpochStore::payload($raw===null?null:\SoSecurity\Storage\Codec::decode($raw,$at),$marker,$context),$this->policy,$at);$live=State::prepare($state,$this->policy,$at);$reference=null;$entry=null;
        if($method==='begin'){if(count($live['entries'])>=$this->policy->capacity()){throw new SecurityException('Pending operation capacity reached.','operation.capacity');}if(!$this->statePolicy->credentialCapacity(State::context($scope,$subject,$at),$expected)){throw new SecurityException('Operation physical snapshot capacity reached.','operation.capacity');}}
        elseif(in_array($method,['confirm','consume','execute'],true)){
            $reference=State::reference($a[$method==='execute'?3:4],$method==='confirm'?'oc1':'og1');if($reference===null){return false;}$entry=$live['entries'][$reference['id']]??null;
            if($entry===null||$entry['phase']!==($method==='confirm'?'pending':'granted')||!hash_equals($entry['digest'],$reference['digest'])||!hash_equals($entry['account'],$session->account()->fingerprint())||$entry['session']!==$session->id()||$entry['created']!==$session->createdAt()){return false;}
            if($method==='confirm'){if(hash_equals($entry['intent'],$intent->fingerprint())&&(hash_equals($entry['session_digest'],hash('sha256',$a[2]))||$session->authenticatedAt()<$entry['issued'])){return false;}}
            elseif(!hash_equals($entry['session_digest'],hash('sha256',$a[2]))){return false;}
        }elseif($method==='revoke'){
            if(!State::hex($a[3],32)){return false;}$reference=['id'=>$a[3]];$entry=$live['entries'][$a[3]]??null;if($entry===null||!hash_equals($entry['account'],$session->account()->fingerprint())||$entry['session']!==$session->id()||$entry['created']!==$session->createdAt()){return false;}
        }elseif(!$live['entries']){return false;}
        $end=$this->now();if($end<$at){throw new StorageException('Operation clock moved backwards.','operation.clock');}if($session->expiresAt()<=$end||($strong&&!$this->policy->accepts($session,$end))){throw new SecurityException('Recent approved authentication required.','operation.authentication');}if($entry!==null&&$entry['expires']<=$end){return false;}
        $this->admitted=['session'=>$session,'session_digest'=>hash('sha256',$a[2]),'intent'=>$intent,'observed'=>$expected];
        $policy=hash('sha256','SoSecurity.Operation.Admission.Policy.1.'.json_encode([$this->statePolicy->binding(),$this->policy->fingerprint(),$this->rolePolicy->fingerprint()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $request=hash('sha256','SoSecurity.Operation.Admission.Request.1.'.json_encode(['entry'=>$method,'actor'=>$subject,'identity'=>$view['fingerprint'],'session'=>SessionRegistry::reference($a[2]),'intent'=>$intent===null?null:$intent->fingerprint(),'reference'=>$reference,'tables'=>$tables,'observed'=>$expected,'policy'=>$policy],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        return \SoSecurity\Account\StateOperation::operation('operations.'.($method==='revokeAll'?'revoke_all':$method),$scope,$subject,$request,$policy,$end);
    }
    private function nativeDecision(\SoSecurity\Auth\Account $actor,string $action,\SoSecurity\Authorization\Resource $resource,array $fields,string $expected):?\SoSecurity\Authorization\Decision
    {
        if(!$this->rolePolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){return $this->rolePolicy->decide($actor,$action,$resource,$fields);}
        if($this->nativeDeadline===null){throw new ConfigurationException('Use the active native policy budget.','configuration.state_business');}
        $this->nativeDeadline->check('account.operation_timeout');
        $decision=$this->rolePolicy->evaluate($this->statePolicy,$expected,$actor,$action,$resource,$fields);
        $this->nativeDeadline->check('account.operation_timeout');return $decision;
    }
    /** A captured policy is observed afresh before proof consumption or any business effect. */
    private function nativeReview():void
    {
        if(!$this->rolePolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){return;}
        if($this->admitted===null){throw new ConfigurationException('Use the exact captured operation admission.','configuration.state_business');}
        $a=$this->admitted;$intent=$a['intent'];if($intent===null){return;}
        $decision=$this->nativeDecision($a['session']->account(),$intent->action(),$intent->resource(),$intent->fields(),$a['observed']);
        if($decision===null||!$decision->allowed()||array_diff($intent->fields(),$decision->fields())){throw new SecurityException('Operation object or field authorization denied.','authorization.denied');}
    }
    private function guard(): void
    {
        if($this->addressPolicy!==null&&$this->addressDeadline===null){throw new ConfigurationException('Use the active native address deadline.','configuration.state_permission');}
        if($this->addressDeadline!==null){$this->addressDeadline->check('account.timeout');}
        if($this->admitted!==null){$this->boundary->assertActive();return;}
        if($this->boundary!==null){$this->boundary->assertActive();}
        elseif(\SoSecurity\Storage\FileStateBoundary::protects($this->store)){throw new \SoSecurity\Storage\StorageException('Protected grants require their active operation authority.','account.state_required');}
        try { $allowed=($this->guard)(); }catch (\Throwable $e) { throw new DependencyException('Operation request protection unavailable.','operation.request_unavailable'); }
        if ($allowed!==true) { throw new SecurityException('Operation request protection failed.','operation.request_denied'); }
    }
    private function facts(string $scope,string $subject,string $token,?Intent $intent,bool $strong): array
    {
        if($this->addressDeadline!==null){$this->addressDeadline->check('account.timeout');}
        State::context($scope,$subject,$this->now());
        try { $session=$this->sessions->verify($scope,$subject,$token); }
        catch (\Throwable $e) { throw new DependencyException('Operation authentication authority unavailable.','operation.authentication_unavailable'); }
        if ($session===null) { throw new SecurityException('Current operation authentication required.','operation.authentication'); }
        if($this->admitted!==null){$a=$this->admitted;if($session->id()!==$a['session']->id()||$session->createdAt()!==$a['session']->createdAt()||$session->authenticatedAt()!==$a['session']->authenticatedAt()||$session->method()!==$a['session']->method()||!hash_equals($session->account()->fingerprint(),$a['session']->account()->fingerprint())||!hash_equals(hash('sha256',$token),$a['session_digest'])||($intent!==null&&($a['intent']===null||!hash_equals($intent->fingerprint(),$a['intent']->fingerprint())))){throw new SecurityException('Admitted operation authority changed.','operation.changed');}}
        elseif ($intent!==null) {
            if($this->addressPolicy===null){$this->authorizer->assertAllowed($scope,$session->account(),$intent->action(),$intent->resource(),$intent->fields());}
            else{
                $this->addressDeadline->check('account.timeout');$expected=$this->addressPolicy->activePolicyDigest($this->boundary);
                $view=$this->addressPolicy->credentialView($scope,$subject,$token,$expected);$current=$view===null?null:$view['session'];
                if($current===null||$current->id()!==$session->id()||$current->createdAt()!==$session->createdAt()||$current->authenticatedAt()!==$session->authenticatedAt()||$current->method()!==$session->method()||!hash_equals($current->account()->fingerprint(),$session->account()->fingerprint())){throw new SecurityException('Current address operation authority changed.','operation.changed');}
                $this->addressDeadline->check('account.timeout');$policy=$this->addressAuthorization;
                $decision=$policy instanceof \SoSecurity\Authorization\SnapshotPolicy?$policy->evaluate($this->addressPolicy,$expected,$current->account(),$intent->action(),$intent->resource(),$intent->fields()):$policy->decide($current->account(),$intent->action(),$intent->resource(),$intent->fields());
                $this->addressDeadline->check('account.timeout');if($decision===null||!$decision->allowed()||array_diff($intent->fields(),$decision->fields())){throw new SecurityException('Address object or field authorization denied.','authorization.denied');}
            }
        }
        $now=$this->now();
        if ($session->expiresAt()<=$now || $session->createdAt()>$now || $session->authenticatedAt()>$now || ($strong && !$this->policy->accepts($session,$now))) {
            throw new SecurityException('Recent approved authentication required.','operation.authentication');
        }
        if($this->addressDeadline!==null){$this->addressDeadline->check('account.timeout');}
        return ['authority'=>$session,'now'=>$now,'account'=>$session->account()->fingerprint(),'session'=>$session->id(),'created'=>$session->createdAt(),
            'session_digest'=>hash('sha256',$token),'authenticated'=>$session->authenticatedAt(),'method'=>$session->method(),'expires'=>$session->expiresAt()];
    }
    private function finish(string $scope,string $subject,string $sessionToken,Intent $intent,array $before,array $entry,array $reference,string $phase,bool $strong): array
    {
        try {
            $this->finished($before['now'],$entry['expires']);$after=$this->facts($scope,$subject,$sessionToken,$intent,$strong);$this->finished($before['now'],$entry['expires']);
            foreach (['account','session','created','session_digest','authenticated','method'] as $field) {
                if ($before[$field]!==$after[$field]) { throw new SecurityException('Operation authority changed.','operation.changed'); }
            }
            if ($after['expires']<$entry['expires']) { throw new SecurityException('Operation session deadline changed.','operation.changed'); }
            return $after;
        } catch (\Throwable $e) {
            // Exact-token cleanup never removes a later phase, another session, or a replacement record.
            $this->drop($scope,$subject,$reference,$phase,max($before['now'],$this->now()));throw $e;
        }
    }
    private function drop(string $scope,string $subject,array $reference,string $phase,int $now): void
    {
        $this->proofStore($scope)->transact(State::context($scope,$subject,$now),function ($state) use ($reference,$phase,$now) {
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$reference['id']] ?? null;
            if ($entry!==null && $entry['phase']===$phase && hash_equals($entry['digest'],$reference['digest'])) { unset($state['entries'][$reference['id']]); }
            return State::change($state,null);
        });
    }
    private function finished(int $started,?int $expires = null): int
    {
        $now=$this->now();if ($now<$started) { throw new StorageException('Operation clock moved backwards during I/O.','operation.clock'); }
        if ($expires!==null && $expires<=$now) { throw new SecurityException('Operation authorization expired during I/O.','operation.expired'); }return $now;
    }
    private function now(): int
    {
        $now=$this->clock->now();if ($now<0 || $now>PHP_INT_MAX-86400) { throw new StorageException('Invalid operation clock.','operation.clock'); }return $now;
    }
    public function __sleep(): array { throw new ConfigurationException('Rebuild operation authorization services from trusted configuration.','configuration.operation_serialization'); }
    public function __debugInfo(): array { return ['operation_authorizations'=>'[redacted]']; }
}
