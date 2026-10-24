<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SystemClock;

/** Retained, revocable fixed-origin signed URLs. Verification consumes one-time links atomically. */
final class Links
{
    private $store;
    private $keys;
    private $site;
    private $policy;
    private $guard;
    private $clock;
    private $boundary;private $statePolicy;private $sessions;private $rolePolicy;private $nativePolicy;private $busy=false;private $admitted;private $nativeDeadline;
    /** Guard(operation, Target, requestMethod): strict true; host owns issuer authorization and request policy. */
    public function __construct(AtomicStore $store,HmacKeys $keys,string $site,Policy $policy,callable $requestGuard,?Clock $clock=null,?\SoSecurity\Account\StateBoundary $boundary=null,?\SoSecurity\Account\StateAccountPolicy $statePolicy=null,?\SoSecurity\Auth\SessionRegistry $sessions=null,?\SoSecurity\Authorization\Authorizer $authorizer=null)
    {
        Guard::label($site);if(strlen($site)>128||!preg_match('//u',$site)){throw new ConfigurationException('Invalid signed-link site.','configuration.link');}
        $clock=$clock??new SystemClock();$role=$sessions===null||$authorizer===null?null:($sessions->operationRolePolicy($authorizer)??($statePolicy===null?null:$sessions->operationSnapshotPolicy($authorizer,$statePolicy)));
        if($statePolicy!==null&&($boundary===null||$sessions===null||!$statePolicy->linkContext($store,$sessions,$clock,$boundary,$site)||$role===null||$requestGuard instanceof \SoSecurity\Account\StateRequestGuard)){throw new ConfigurationException('Use the exact native link graph, site and a pure role or captured-facts policy without effectful audit.','configuration.state_permission');}
        if($statePolicy===null&&($sessions!==null||$authorizer!==null)){throw new ConfigurationException('Supply native link authority as one complete graph.','configuration.state_permission');}
        $this->boundary=$boundary;$this->statePolicy=$statePolicy;$this->sessions=$sessions;$this->rolePolicy=$role;
        $this->nativePolicy=$statePolicy===null?null:hash('sha256','SoSecurity.Link.Native.Policy.1.'.json_encode([$statePolicy->binding(),$role->fingerprint(),$policy->fingerprint(),$site,$keys->currentId(),bin2hex($keys->sign('SoSecurity.Link.Native.Key.1.'.$site))],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        if($boundary!==null){$store=$boundary->protect($store);}
        $this->store=$store;$this->keys=$keys;$this->site=$site;$this->policy=$policy;$this->guard=$requestGuard;$this->clock=$clock;
    }
    private function proofStore(Target $target):\SoSecurity\Storage\ProofEpochStore{return new \SoSecurity\Storage\ProofEpochStore($this->store,'links',$this->epochScope($target->resource()->scope()));}
    private function epochScope(string $scope):string{Guard::label($scope);return hash('sha256',json_encode([$this->site,$scope],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    /** All purposes/resources in this site's scope, including old paths and versions. */
    public function stateRetirementEpoch(\SoSecurity\Storage\FileStore $store,Clock $clock,string $scope,string $epoch):?array
    {
        if(($this->store!==$store&&(!$this->store instanceof \SoSecurity\Account\WitnessedStore||!$this->store->protects($store)))||$this->clock!==$clock){return null;}
        return \SoSecurity\Storage\ProofEpochStore::retirement($store,'links',$this->epochScope($scope),$epoch,$this->policy->fingerprint());
    }
    public function policy():Policy {return $this->policy;}
    public function issue(Target $target,bool $oneTime=false,?int $ttl=null,string $binding=''):IssuedLink
    {
        $this->legacyEntry();return $this->issueInternal($target,$oneTime,$ttl,$binding);
    }
    private function issueInternal(Target $target,bool $oneTime=false,?int $ttl=null,string $binding=''):IssuedLink
    {
        $this->guard('issue',$target,'POST');$binding=Encoding::binding($binding);$ttl=$ttl ?? $this->policy->ttl();
        if($ttl<1||$ttl>$this->policy->maximumTtl()){throw new ConfigurationException('Invalid signed-link lifetime.','configuration.link');}
        $now=$this->now();$parts=['key_id'=>$this->keys->currentId(),'id'=>bin2hex(random_bytes(16)),'issued'=>$now,'expires'=>$now+$ttl,'mode'=>$oneTime?'o':'r'];
        $token='sl1.'.$parts['key_id'].'.'.$parts['id'].'.'.$now.'.'.$parts['expires'].'.'.$parts['mode'].'.'.Encoding::base64($this->keys->sign(Encoding::message($this->site,$this->policy,$target,$parts,$binding)));
        $url=Encoding::prefix($this->policy,$target).$token;
        if(strlen($url)>2048){throw new ConfigurationException('Signed URL exceeds 2 KiB.','configuration.link_target');}
        $entry=['digest'=>hash('sha256',$token),'target'=>$target->fingerprint(),'issued'=>$now,'expires'=>$parts['expires'],'one_time'=>$oneTime,'key_id'=>$parts['key_id']];$key=State::key($this->site,$target);
        $this->proofStore($target)->transact($key,function($state)use($now,$parts,$entry){
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);
            if(count($state['entries'])>=$this->policy->capacity()||isset($state['entries'][$parts['id']])){throw new SecurityException('Signed-link capacity reached.','link.capacity');}
            $state['entries'][$parts['id']]=$entry;return State::change($state,null);
        });
        $this->finish($target,$key,$parts['id'],$entry['digest'],$now,$parts['expires']);
        return new IssuedLink($url,$parts['id'],$target,$now,$parts['expires'],$oneTime);
    }
    /** Supply current server-loaded target and actual method; HEAD never consumes a GET link. */
    public function verify(Target $target,string $url,string $method='GET',string $binding=''):?VerifiedLink
    {
        $this->legacyEntry();return $this->verifyInternal($target,$url,$method,$binding);
    }
    private function verifyInternal(Target $target,string $url,string $method='GET',string $binding=''):?VerifiedLink
    {
        $this->guard('verify',$target,$method);$binding=Encoding::binding($binding);
        if($method!==$target->method()){return null;}$parts=Encoding::parse($url,$this->policy,$target);if($parts===null){return null;}
        if(!$this->keys->verify($parts['key_id'],Encoding::message($this->site,$this->policy,$target,$parts,$binding),$parts['mac'])){return null;}
        $now=$this->now();$key=State::key($this->site,$target);
        $entry=$this->proofStore($target)->transact($key,function($state)use($now,$parts,$target){
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$parts['id']] ?? null;
            if($entry===null||!hash_equals($entry['digest'],$parts['digest'])||!hash_equals($entry['target'],$target->fingerprint())||$entry['issued']>$now){return State::change($state,null);}
            if($entry['issued']!==$parts['issued']||$entry['expires']!==$parts['expires']||$entry['key_id']!==$parts['key_id']||$entry['one_time']!==($parts['mode']==='o')){throw new StorageException('Signed-link record differs from authenticated envelope.','storage.corrupt');}
            if($entry['one_time']){unset($state['entries'][$parts['id']]);}return State::change($state,$entry);
        });
        if($entry===null){$this->finished($now);return null;}
        $this->finish($target,$key,$parts['id'],$parts['digest'],$now,$entry['expires']);
        return new VerifiedLink($parts['id'],$target,$entry['issued'],$entry['expires'],$entry['one_time']);
    }
    /** Per-purpose/resource management, including earlier versions/paths/bindings of that resource. */
    public function revoke(Target $target,string $id):bool
    {
        $this->legacyEntry();return $this->revokeInternal($target,$id);
    }
    private function revokeInternal(Target $target,string $id):bool
    {
        $this->guard('revoke',$target,'POST');if(!State::hex($id,32)){return false;}$now=$this->now();
        $result=$this->proofStore($target)->transact(State::key($this->site,$target),function($state)use($now,$id){$state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$exists=isset($state['entries'][$id]);unset($state['entries'][$id]);return State::change($state,$exists);});$this->finished($now);return $result;
    }
    public function revokeAll(Target $target):void
    {
        $this->legacyEntry();$this->revokeAllInternal($target);
    }
    private function revokeAllInternal(Target $target):void
    {
        $this->guard('revoke_all',$target,'POST');$now=$this->now();
        $this->proofStore($target)->transact(State::key($this->site,$target),function($state)use($now){State::read($state,$this->policy,$now);return new Change(null,0,null);});$this->finished($now);
    }
    /** Bounded metadata snapshot at read time; no URL/parameters/binding and no verification authority. */
    public function all(Target $target):array
    {
        $this->legacyEntry();return $this->allInternal($target);
    }
    private function allInternal(Target $target):array
    {
        $this->guard('all',$target,'GET');$now=$this->now();
        $entries=$this->proofStore($target)->transact(State::key($this->site,$target),function($state)use($now){$state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);return State::change($state,$state['entries']);});$this->finished($now);
        $result=[];foreach($entries as $id=>$entry){$result[]=['id'=>$id,'issued_at'=>$entry['issued'],'expires_at'=>$entry['expires'],'one_time'=>$entry['one_time'],'key_id'=>$entry['key_id'],'target_fingerprint'=>$entry['target']];}return $result;
    }
    private function guard(string $operation,Target $target,string $method):void
    {
        \SoSecurity\Storage\FileStateBoundary::assertStoreActive($this->store);if($this->boundary!==null){$this->boundary->assertScope($target->resource()->scope());$this->boundary->assertActive();}
        if($this->admitted!==null){$expected=$this->admitted['entry']==='execute'?'verify':$this->admitted['entry'];if($expected!==$operation||$target->fingerprint()!==$this->admitted['target']->fingerprint()){throw new ConfigurationException('Use the exact admitted native link operation.','configuration.state_request_nested');}$this->nativeLive($this->now());return;}
        $this->requestGuard($operation,$target,$method);
    }
    private function requestGuard(string $operation,Target $target,string $method):void
    {
        try{$allowed=($this->guard)($operation,$target,$method);}catch(\Throwable $error){throw new DependencyException('Signed-link request protection unavailable.','link.request_unavailable');}
        if($allowed!==true){throw new SecurityException('Signed-link request protection failed.','link.request_denied');}
    }
    private function finish(Target $target,string $key,string $id,string $digest,int $started,int $expires):void
    {
        try{$this->finished($started,$expires);}catch(\Throwable $error){
            try{$now=$this->now();}catch(\Throwable $clockError){$now=$started;}$now=max($started,$now);
            $this->proofStore($target)->transact($key,function($state)use($id,$digest,$now){$state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);if(isset($state['entries'][$id])&&hash_equals($state['entries'][$id]['digest'],$digest)){unset($state['entries'][$id]);}return State::change($state,null);});throw $error;
        }
    }
    private function finished(int $started,?int $expires=null):void
    {
        $now=$this->now();$this->nativeLive($now);if($now<$started){throw new StorageException('Signed-link clock moved backwards during I/O.','link.clock');}
        if($expires!==null&&$expires<=$now){throw new SecurityException('Signed link expired during I/O.','link.expired');}
    }
    private function legacyEntry():void{if($this->statePolicy!==null){throw new ConfigurationException('Use native For methods with an authoritative server target loader.','configuration.state_link_entry');}}
    public function issueFor(string $scope,string $subject,string $sessionToken,\PDO $connection,array $tables,callable $prepare,bool $oneTime=false,?int $ttl=null,string $binding=''):IssuedLink{return $this->nativeCall('issue',$scope,$subject,$sessionToken,$connection,$tables,$prepare,['one_time'=>$oneTime,'ttl'=>$ttl,'binding'=>$binding]);}
    public function verifyFor(string $scope,\PDO $connection,array $tables,callable $prepare,string $url,string $method='GET',string $binding=''):?VerifiedLink{return $this->nativeCall('verify',$scope,null,null,$connection,$tables,$prepare,['url'=>$url,'method'=>$method,'binding'=>$binding]);}
    public function allFor(string $scope,string $subject,string $sessionToken,\PDO $connection,array $tables,callable $prepare):array{$v=$this->nativeCall('all',$scope,$subject,$sessionToken,$connection,$tables,$prepare,[]);return $v??[];}
    public function revokeFor(string $scope,string $subject,string $sessionToken,\PDO $connection,array $tables,callable $prepare,string $id):bool{return $this->nativeCall('revoke',$scope,$subject,$sessionToken,$connection,$tables,$prepare,['id'=>$id])===true;}
    public function revokeAllFor(string $scope,string $subject,string $sessionToken,\PDO $connection,array $tables,callable $prepare):void{$this->nativeCall('revoke_all',$scope,$subject,$sessionToken,$connection,$tables,$prepare,[]);}
    /** work is invoked once in an owned SQL transaction; return data, never emit or perform external effects. */
    public function withVerification(string $scope,\PDO $connection,array $tables,callable $prepare,string $url,callable $work,string $method='GET',string $binding='')
    {return $this->nativeCall('execute',$scope,null,null,$connection,$tables,$prepare,['url'=>$url,'method'=>$method,'binding'=>$binding],$work);}
    private function nativeLive(int $now):void
    {
        if($this->admitted===null){return;}if($now<$this->admitted['started']){throw new StorageException('Native link clock moved backwards.','link.clock');}$s=$this->admitted['session'];if($s!==null&&$s->expiresAt()<=$now){throw new SecurityException('Link management session expired.','link.authentication');}
    }
    private function nativeCall(string $entry,string $scope,?string $subject,?string $token,\PDO $connection,array $tables,callable $prepare,array $options,?callable $work=null)
    {
        if($this->statePolicy===null||!$this->statePolicy->credentialSqlContext($connection,$tables)){throw new ConfigurationException('Use the native link graph, exact PDO and complete declared business tables.','configuration.state_business');}
        if($this->busy||$this->boundary->active()){throw new ConfigurationException('Enter native link requests once without an outer effect context.','configuration.state_request_nested');}$this->boundary->assertScope($scope);
        if(!$this->statePolicy->recoveryRegistry($this->sessions,$scope)){throw new ConfigurationException('Use the native link policy scope.','configuration.state_scope');}
        if($subject!==null){Guard::label($subject);if(preg_match('//u',$subject)!==1||$token===null||\SoSecurity\Auth\SessionRegistry::reference($token)===null){throw new SecurityException('Current link management session required.','link.authentication');}}
        if(isset($options['binding'])){Encoding::binding($options['binding']);}
        if($entry==='issue'){$options['ttl']=$options['ttl']??$this->policy->ttl();if($options['ttl']<1||$options['ttl']>$this->policy->maximumTtl()){throw new ConfigurationException('Invalid signed-link lifetime.','configuration.link');}}
        if($entry==='revoke'&&!State::hex($options['id'],32)){return false;}if(isset($options['url'])&&(strlen($options['url'])>2048||strlen($options['method'])>16)){return null;}
        $names=array_keys($tables);sort($names);$deadline=new \SoSecurity\Support\Deadline(30000);$expires=null;$this->nativeDeadline=$deadline;$this->busy=true;
        try{$result=$this->boundary->run('links.'.$entry,function()use($entry,$connection,$options,$work,$deadline,&$expires){
            $target=$this->admitted['target'];
            $this->nativeReview($entry,$target);
            if($entry==='issue'){return $this->issueInternal($target,$options['one_time'],$options['ttl'],$options['binding']);}
            if($entry==='all'){return $this->allInternal($target);}if($entry==='revoke'){return $this->revokeInternal($target,$options['id']);}if($entry==='revoke_all'){$this->revokeAllInternal($target);return null;}
            $verified=$this->verifyInternal($target,$options['url'],$options['method'],$options['binding']);if($verified!==null){$expires=$verified->expiresAt();}if($entry==='verify'||$verified===null){return $verified;}
            $unit=new \SoSecurity\Support\SqlTransaction($connection,$this->clock,30000);$seen=$this->now();
            $live=function()use($verified,&$seen):void{$now=$this->now();$this->nativeLive($now);if($now<$seen){throw new StorageException('Signed-link business clock moved backwards.','link.clock');}$seen=$now;if($verified->expiresAt()<=$now){throw new SecurityException('Signed link expired during business commit.','link.expired');}};
            return $unit->run(function()use($unit,$connection,$verified,$work){return $unit->invoke($work,[$connection,$verified],'link.business_unavailable');},null,$live,$live,$deadline);
        },function(string $expected)use($entry,$scope,$subject,$token,$connection,$names,$prepare,$options){return $this->nativeAdmission($entry,$scope,$subject,$token,$connection,$names,$prepare,$options,$expected);},null,$deadline);
            if($this->admitted!==null){
                if($result instanceof IssuedLink){$expires=$result->expiresAt();}
                $this->completion($entry,$scope,$subject,$token,$options,$expires,$deadline);
            }
            return $result;
        }
        finally{$this->admitted=null;$this->nativeDeadline=null;$this->busy=false;}
    }
    /** No replay or ledger writes: final authority for the original admitted target. */
    private function completion(string $entry,string $scope,?string $subject,?string $token,array $options,?int $expires,\SoSecurity\Support\Deadline $deadline):void
    {
        $this->boundary->run('links.'.$entry.'_check',static function():void{throw new ConfigurationException('Signed-link completion is read only.','configuration.state_business');},function(string $expected)use($entry,$scope,$subject,$token,$options,$expires):bool{
            $admitted=$this->admitted;$this->finished($admitted['started'],$expires);$target=$admitted['target'];
            if($subject!==null){
                $view=$this->statePolicy->credentialView($scope,$subject,$token,$expected);$current=$view===null?null:$view['session'];$old=$admitted['session'];
                if($current===null||$old===null||$current->id()!==$old->id()||$current->createdAt()!==$old->createdAt()||$current->authenticatedAt()!==$old->authenticatedAt()||$current->method()!==$old->method()||!hash_equals($current->account()->fingerprint(),$old->account()->fingerprint())){throw new SecurityException('Current link management authentication required.','link.authentication');}
                $fields=$entry==='issue'?['target','one_time','ttl','binding']:($entry==='revoke'?['id']:[]);
                $decision=$this->nativeDecision($current->account(),$entry,$target,$fields,$expected);
                if($decision===null||!$decision->allowed()||array_diff($fields,$decision->fields())){throw new SecurityException('Link object or fields denied.','authorization.denied');}$this->admitted['session']=$current;
            }
            $this->requestGuard($entry==='execute'?'verify':$entry,$target,$options['method']??($entry==='all'?'GET':'POST'));
            $this->finished($admitted['started'],$expires);return false;
        },null,$deadline);
        $deadline->check('account.operation_timeout');$this->finished($this->admitted['started'],$expires);
    }
    private function nativeAdmission(string $entry,string $scope,?string $subject,?string $token,\PDO $connection,array $tables,callable $prepare,array $options,string $expected)
    {
        $started=$this->now();$session=null;
        if($subject!==null){$view=$this->statePolicy->credentialView($scope,$subject,$token,$expected);if($view===null||$view['session']===null){throw new SecurityException('Current link management authentication required.','link.authentication');}$session=$view['session'];}
        $localConnection=$connection;$localSession=$session;
        try{$target=$prepare($localConnection,$localSession);}catch(SecurityException $e){throw $e;}catch(ConfigurationException $e){throw $e;}catch(\SoSecurity\Exception\ValidationException $e){throw $e;}catch(\Throwable $e){throw new DependencyException('Current server link target unavailable.','link.business_unavailable');}
        if(!$target instanceof Target){throw new ConfigurationException('Load a validated server Target.','configuration.state_business');}if($target->resource()->scope()!==$scope){throw new SecurityException('Link resource scope denied.','authorization.denied');}
        $fields=$entry==='issue'?['target','one_time','ttl','binding']:($entry==='revoke'?['id']:[]);
        if($session!==null){$decision=$this->nativeDecision($session->account(),$entry,$target,$fields,$expected);if($decision===null||!$decision->allowed()||array_diff($fields,$decision->fields())){throw new SecurityException('Link object or fields denied.','authorization.denied');}}
        $this->requestGuard($entry==='execute'?'verify':$entry,$target,$options['method']??($entry==='all'?'GET':'POST'));
        $parts=null;$binding=isset($options['binding'])?Encoding::binding($options['binding']):null;
        if($entry==='verify'||$entry==='execute'){
            if($options['method']!==$target->method()){return false;}$parts=Encoding::parse($options['url'],$this->policy,$target);if($parts===null||!$this->keys->verify($parts['key_id'],Encoding::message($this->site,$this->policy,$target,$parts,$binding),$parts['mac'])){return false;}
        }
        $at=$this->now();$key=State::key($this->site,$target);$context=\SoSecurity\Storage\ProofEpochStore::context('links',$this->epochScope($scope));$marker=\SoSecurity\Storage\ProofEpochStore::markerBytes($this->statePolicy->credentialBytes(\SoSecurity\Storage\ProofEpochStore::key($context),$expected),$context);$raw=$this->statePolicy->credentialBytes($key,$expected);
        $state=State::prepare(State::read(\SoSecurity\Storage\ProofEpochStore::payload($raw===null?null:\SoSecurity\Storage\Codec::decode($raw,$at),$marker,$context),$this->policy,$at),$this->policy,$at);
        if($entry==='issue'&&count($state['entries'])>=$this->policy->capacity()){throw new SecurityException('Signed-link capacity reached.','link.capacity');}
        if($entry==='issue'&&!$this->statePolicy->credentialCapacity($key,$expected)){throw new SecurityException('Signed-link physical snapshot capacity reached.','link.capacity');}
        if($parts!==null){$record=$state['entries'][$parts['id']]??null;if($record===null||!hash_equals($record['digest'],$parts['digest'])||!hash_equals($record['target'],$target->fingerprint())||$record['issued']>$at){return false;}if($record['issued']!==$parts['issued']||$record['expires']!==$parts['expires']||$record['key_id']!==$parts['key_id']||$record['one_time']!==($parts['mode']==='o')){throw new StorageException('Signed-link ledger differs from its authenticated envelope.','storage.corrupt');}}
        if($entry==='revoke'&&!isset($state['entries'][$options['id']])){return false;}if(($entry==='all'||$entry==='revoke_all')&&!$state['entries']){return false;}
        $end=$this->now();if($end<$started){throw new StorageException('Native link clock moved backwards.','link.clock');}if($session!==null&&$session->expiresAt()<=$end){throw new SecurityException('Current link management session expired.','link.authentication');}if($parts!==null&&($parts['issued']>$end||$parts['expires']<=$end)){return false;}
        $this->admitted=['entry'=>$entry,'target'=>$target,'session'=>$session,'started'=>$started,'observed'=>$expected];$parameters=['entry'=>$entry,'actor'=>$subject,'session'=>$token===null?null:\SoSecurity\Auth\SessionRegistry::reference($token),'target'=>$target->fingerprint(),'one_time'=>$options['one_time']??null,'ttl'=>$options['ttl']??null,'binding'=>$binding,'proof'=>$parts===null?($options['id']??null):$parts['digest'],'tables'=>$tables,'observed'=>$expected,'policy'=>$this->nativePolicy];$request=hash('sha256','SoSecurity.Link.Native.Request.1.'.json_encode($parameters,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        return \SoSecurity\Account\StateOperation::link('links.'.$entry,$scope,$subject,$target->fingerprint(),$request,$this->nativePolicy,$end);
    }
    private function nativeDecision(\SoSecurity\Auth\Account $actor,string $entry,Target $target,array $fields,string $expected):?\SoSecurity\Authorization\Decision
    {
        if(!$this->rolePolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){return $this->rolePolicy->decide($actor,'links.'.$entry,$target->resource(),$fields);}
        if($this->nativeDeadline===null){throw new ConfigurationException('Use the active native policy budget.','configuration.state_business');}
        $this->nativeDeadline->check('account.operation_timeout');
        $decision=$this->rolePolicy->evaluate($this->statePolicy,$expected,$actor,'links.'.$entry,$target->resource(),$fields);
        $this->nativeDeadline->check('account.operation_timeout');return $decision;
    }
    /** Management policy only; bearer verification keeps its explicit signed-target authority. */
    private function nativeReview(string $entry,Target $target):void
    {
        if(!$this->rolePolicy instanceof \SoSecurity\Authorization\SnapshotPolicy||$this->admitted['session']===null){return;}
        $fields=$entry==='issue'?['target','one_time','ttl','binding']:($entry==='revoke'?['id']:[]);
        $decision=$this->nativeDecision($this->admitted['session']->account(),$entry,$target,$fields,$this->admitted['observed']);
        if($decision===null||!$decision->allowed()||array_diff($fields,$decision->fields())){throw new SecurityException('Link object or fields denied.','authorization.denied');}
    }
    private function now():int {try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Signed-link clock unavailable.','link.clock');}if($now<0||$now>PHP_INT_MAX-86400){throw new StorageException('Invalid signed-link clock.','link.clock');}return $now;}
    public function __debugInfo():array {return ['signed_links'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild signed-link services from trusted configuration.','configuration.link_serialization');}
}
