<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Auth\IdentityState;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SystemClock;

/** Opt-in account-bound credentials. All management uses actual registry sessions; bearer reads never infer Cookies. */
final class CredentialRegistry
{
    private $store;
    private $sessions;
    private $identities;
    private $keys;
    private $site;
    private $guard;
    private $scopeProvider;
    private $policy;
    private $clock;
    // The audit sub-budget gates admission and its writer; the caller budget also covers completion.
    private $nativeAudit;private $nativeAuditBinding;private $auditPlan;private $auditDeadline;private $auditAdmissionDeadline;private $auditSeen=0;
    private $managementAuthorization;
    private $managementSubject;
    private $boundary;
    private $statePolicy;private $managementPolicy;private $stateBusy=false;private $admitted;
    /** Identity/factor adapters MUST match the SessionRegistry's trusted authority. No I/O in construction. */
    public function __construct(AtomicStore $store,SessionRegistry $sessions,IdentityProvider $identities,HmacKeys $keys,string $site,callable $requestGuard,callable $scopeProvider,?CredentialPolicy $policy=null,?Clock $clock=null,?SecondFactor $factor=null,?Authorizer $managementAuthorization=null,?callable $managementSubject=null,?\SoSecurity\Account\StateBoundary $boundary=null,?\SoSecurity\Account\StateAccountPolicy $statePolicy=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)){throw new ConfigurationException('Credential site must be UTF-8.','configuration.api_credentials');}
        if(($managementAuthorization===null)!==($managementSubject===null)){throw new ConfigurationException('Delegated credential management needs both trusted operator resolution and object authorization.','configuration.api_credential_management');}
        $clock=$clock??new SystemClock();if(($boundary===null&&($sessions->requiresStateBoundary()||\SoSecurity\Storage\FileStateBoundary::protects($store)))||($boundary!==null&&(!$boundary->semanticAuthority()||!$sessions->credentialRegistryContext($identities,$factor,$clock,$boundary)))){throw new ConfigurationException('Use the exact protected credential authentication graph.','configuration.state_boundary');}
        if($statePolicy!==null&&($boundary===null||!$statePolicy->credentialContext($store,$sessions,$clock,$boundary))){throw new ConfigurationException('Use this exact native API account source.','configuration.state_permission');}$this->statePolicy=$statePolicy;if($statePolicy!==null&&$managementAuthorization!==null){$this->managementPolicy=$managementAuthorization->stateRolePolicy($identities);if($this->managementPolicy===null){$audited=$managementAuthorization->stateAuditedPolicy($identities,$statePolicy)??$managementAuthorization->stateSnapshotPolicy($identities,$statePolicy);if($audited===null){throw new ConfigurationException('Use the same native identity source, a fixed or explicitly declared snapshot policy, and exactly covered audit storage.','configuration.api_credential_management');}$this->managementPolicy=$audited['policy'];$this->nativeAudit=$audited['audit'];$this->nativeAuditBinding=$audited['binding'];}}
        $this->boundary=$boundary;$this->store=$boundary===null?$store:$boundary->protect($store);$this->sessions=$sessions;$this->identities=new IdentityState($identities,$factor);$this->keys=$keys;$this->site=$site;$this->guard=$requestGuard;$this->scopeProvider=$scopeProvider;$this->policy=$policy ?? new CredentialPolicy();$this->clock=$clock;$this->managementAuthorization=$managementAuthorization;$this->managementSubject=$managementSubject;
    }
    public function policy():CredentialPolicy {return $this->policy;}
    private function stateAdmission(string $scope):void
    {
        if($this->boundary===null){if($this->sessions->requiresStateBoundary()||\SoSecurity\Storage\FileStateBoundary::protects($this->store)){throw new ConfigurationException('Protected credential services require their exact declared boundary.','configuration.state_boundary');}return;}
        $this->boundary->assertScope($scope);$this->boundary->assertActive();
    }
    /** Pure fixed retirement coordinates, no authority or read/write of a live ledger. */
    public function stateRetirementEpoch(\SoSecurity\Storage\FileStore $store,Clock $clock,string $scope,string $subject,string $epoch,int $at):?array
    {
        if(($this->store!==$store&&(!$this->store instanceof \SoSecurity\Account\WitnessedStore||!$this->store->protects($store)))||$this->clock!==$clock){return null;}
        if(preg_match('/\A[a-f0-9]{32}\z/D',$epoch)!==1||$at<0||$at>PHP_INT_MAX-31536001){throw new ConfigurationException('Use an exact managed credential retirement epoch.','configuration.api_key_retirement');}$root=CredentialState::root($this->site,$scope,$subject);$key=CredentialState::key($this->site,$root);$context=hash('sha256','SoSecurity.Api.Credentials.Retirement.1.'.json_encode([$this->site,$scope,$this->policy->fingerprint(),$store->snapshotReference(CredentialState::key($this->site,CredentialState::root($this->site,$scope,'state-credential-context')))]));$identity=hash('sha256','SoSecurity.Api.Credentials.RetiredIdentity.1.'.json_encode([$this->site,$scope,$subject,$epoch]));
        return ['context'=>$context,'key'=>$key,'reference'=>$store->snapshotReference($key),'after'=>\SoSecurity\Storage\Codec::encode(new Change(CredentialState::empty($scope,$subject,$identity,$this->policy,$at,$epoch),0,true))];
    }
    private function now():int
    {
        try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('API credential clock unavailable.','api_credentials.clock');}if($now<0||$now>PHP_INT_MAX-31536000){throw new StorageException('Invalid API credential clock.','api_credentials.clock');}return $now;
    }
    private function deadline():Deadline
    {
        $deadline=new Deadline($this->policy->ioMilliseconds());if($this->auditDeadline!==null){$deadline->restrictTo($this->auditDeadline);}return $deadline;
    }
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('api_credentials.timeout');$now=$this->now();if($now<$seen){throw new StorageException('API credential clock moved backwards.','api_credentials.clock');}$seen=$now;return $now;
    }
    private function protect(string $operation,?Account $account,array $metadata):void
    {
        if($this->admitted!==null){$this->boundary->assertActive();return;}
        try{$allowed=($this->guard)($operation,$account,$metadata);}catch(\Throwable $error){throw new DependencyException('API credential request protection unavailable.','api_credentials.request_unavailable');}
        if($allowed!==true){throw new SecurityException('API credential request protection denied.','api_credentials.denied');}
    }
    private function identity(string $scope,string $subject):?array
    {
        try{$identity=$this->identities->load($scope,$subject);return $identity!==null&&$identity['mfa_required']&&$identity['factor']===null?null:$identity;}catch(\Throwable $error){throw new DependencyException('API credential identity authority unavailable.','api_credentials.identity_unavailable');}
    }
    private function capabilities(Account $account):array
    {
        if($this->admitted!==null){$this->boundary->assertActive();if(!hash_equals($this->admitted['account'],$account->fingerprint())){throw new StorageException('Admitted credential owner changed.','api_credentials.changed');}return $this->admitted['scopes'];}
        try{$scopes=($this->scopeProvider)($account);if(!is_array($scopes)){throw new \RuntimeException('Invalid scope-provider result.');}$scopes=CredentialEncoding::scopes($scopes,true);}
        catch(\Throwable $error){throw new DependencyException('API credential scope authority unavailable.','api_credentials.scopes_unavailable');}
        return array_values(array_intersect($scopes,$this->policy->allowedScopes()));
    }
    private function actor(string $scope,string $subject,string $token,string $operation,Deadline $deadline,int &$seen):array
    {
        CredentialState::root($this->site,$scope,$subject);$this->tick($deadline,$seen);
        $manager=$subject;
        if($this->admitted!==null){$manager=$this->admitted['manager'];}
        elseif($this->managementSubject!==null){
            try{$manager=($this->managementSubject)($scope);if(!is_string($manager)){throw new \RuntimeException('Invalid operator subject.');}CredentialState::root($this->site,$scope,$manager);}catch(\Throwable $error){throw new DependencyException('API credential operator unavailable.','api_credentials.management_unavailable');}
        }
        try{$session=$this->sessions->verify($scope,$manager,$token);}catch(\Throwable $error){throw new DependencyException('API credential management authentication unavailable.','api_credentials.identity_unavailable');}
        if($session===null){throw new SecurityException('Current management session required.','api_credentials.denied');}
        $now=$this->tick($deadline,$seen);$sensitive=in_array($operation,['issue','rotate','replace'],true);$minimum=$manager===$subject?$this->policy->minimumStrength():max($this->policy->minimumStrength(),$this->policy->delegatedMinimumStrength());
        if($sensitive&&(!$session->recent($this->policy->freshAge(),$now,$minimum)||!in_array($session->method(),$this->policy->methods(),true))){throw new SecurityException('Recent configured authentication required.','api_credentials.reauthentication');}
        $identity=$this->identity($scope,$subject);if($identity===null||($manager===$subject&&!hash_equals($session->account()->fingerprint(),$identity['account']->fingerprint()))){throw new SecurityException('Management identity changed.','api_credentials.denied');}
        $this->authorizeManagement($scope,$subject,$manager,$session->account(),$operation,$identity);
        $scopes=$this->capabilities($identity['account']);$this->tick($deadline,$seen);
        try{$current=$this->sessions->verify($scope,$manager,$token);}catch(\Throwable $error){throw new DependencyException('API credential management authentication unavailable.','api_credentials.identity_unavailable');}
        $now=$this->tick($deadline,$seen);
        if($current===null||$current->id()!==$session->id()||!hash_equals($session->account()->fingerprint(),$current->account()->fingerprint())||($sensitive&&(!$current->recent($this->policy->freshAge(),$now,$minimum)||!in_array($current->method(),$this->policy->methods(),true)))){throw new SecurityException('Management session changed during I/O.','api_credentials.denied');}
        $latest=$this->identity($scope,$subject);if($latest===null||!hash_equals($identity['fingerprint'],$latest['fingerprint'])){throw new SecurityException('Credential owner changed during management I/O.','api_credentials.denied');}$this->authorizeManagement($scope,$subject,$manager,$current->account(),$operation,$latest);$this->tick($deadline,$seen);
        if($this->admitted===null){
            // Identity and object-policy I/O can outlive the first capability observation.
            $scopes=array_values(array_intersect($scopes,$this->capabilities($latest['account'])));$this->tick($deadline,$seen);
            try{$final=$this->sessions->verify($scope,$manager,$token);}catch(\Throwable $error){throw new DependencyException('API credential management authentication unavailable.','api_credentials.identity_unavailable');}
            $now=$this->tick($deadline,$seen);
            if($final===null||$final->id()!==$current->id()||!hash_equals($current->account()->fingerprint(),$final->account()->fingerprint())||($sensitive&&(!$final->recent($this->policy->freshAge(),$now,$minimum)||!in_array($final->method(),$this->policy->methods(),true)))){throw new SecurityException('Management session changed during scope I/O.','api_credentials.denied');}
            $completed=$this->identity($scope,$subject);if($completed===null||!hash_equals($identity['fingerprint'],$completed['fingerprint'])){throw new SecurityException('Credential owner changed during scope I/O.','api_credentials.denied');}
            $this->authorizeManagement($scope,$subject,$manager,$final->account(),$operation,$completed);$this->tick($deadline,$seen);$current=$final;
        }
        $now=$this->tick($deadline,$seen);if($current->expiresAt()<=$now||($sensitive&&!$current->recent($this->policy->freshAge(),$now,$minimum))){throw new SecurityException('Management authentication expired during final authority I/O.','api_credentials.denied');}
        return ['session'=>$current,'identity'=>$identity,'scopes'=>$scopes];
    }
    private function authorizeManagement(string $scope,string $owner,string $manager,Account $actor,string $operation,array $identity):void
    {
        if($this->admitted!==null){$this->boundary->assertActive();return;}
        if($owner===$manager){return;}
        if($this->managementAuthorization===null){throw new SecurityException('Cross-account credential management is disabled.','api_credentials.denied');}
        $resource=new Resource($scope,'api_credential_owner',$owner,$identity['fingerprint'],['owner'=>$owner]);
        $this->managementAuthorization->assertAllowed($scope,$actor,'api.credentials.'.$operation,$resource);
    }
    private function sameActor(array $before,array $after):void
    {
        if($before['session']->id()!==$after['session']->id()||!hash_equals($before['session']->account()->fingerprint(),$after['session']->account()->fingerprint())||!hash_equals($before['identity']['fingerprint'],$after['identity']['fingerprint'])){throw new SecurityException('Management authority changed during I/O.','api_credentials.denied');}
    }
    private function entitlement(array $scopes,array $allowed):void
    {
        if(array_diff($scopes,$allowed)){throw new SecurityException('Requested credential capability is not currently granted.','api_credentials.scope_denied');}
    }
    /** Capture the epoch before protection I/O. Authorized issue may initialize empty bookkeeping, never a credential. */
    private function snapshot(string $scope,string $root,int $now,?array $initial=null):?array
    {
        return $this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$now,$initial){$state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now) ?? $initial;return new Change($state,0,$state);});
    }
    private function record(string $name,array $scopes,array $identity,int $created,int $issued,int $expires,int $generation,?int $lastUsed,string $issuer,?string $creator=null):array
    {
        return ['name'=>$name,'scopes'=>$scopes,'created'=>$created,'issued'=>$issued,'expires'=>$expires,'generation'=>$generation,'key_id'=>$this->keys->currentId(),'identity'=>$identity['fingerprint'],'policy'=>$this->policy->fingerprint(),'digest'=>'','claims'=>'','last_used'=>$lastUsed,'creator'=>$creator ?? $issuer,'issuer'=>$issuer];
    }
    private function signedRecord(string $scope,string $subject,string $root,string $epoch,string $id,array $record):array
    {
        $secret=bin2hex(random_bytes(32));$record['claims']=CredentialState::claims($this->site,$scope,$subject,$root,$epoch,$id,$record);$token=CredentialEncoding::create($this->keys,$this->site,$scope,$root,$epoch,$id,$record,$secret);$record['digest']=hash('sha256',$token);return [$record,$token];
    }
    private function lifetime(?int $ttl):int
    {
        $ttl=$ttl ?? $this->policy->ttl();if($ttl<1||$ttl>$this->policy->maximumTtl()){throw new ValidationException('Credential lifetime exceeds configured policy.','api_credentials.ttl');}return $ttl;
    }
    public function issue(string $scope,string $subject,string $sessionToken,string $name,array $scopes,?int $ttl=null):IssuedCredential
    {
        return $this->stateCall('issue',func_get_args());
    }
    private function issueInternal(string $scope,string $subject,string $sessionToken,string $name,array $scopes,?int $ttl=null):IssuedCredential
    {
        $this->stateAdmission($scope);
        $name=CredentialEncoding::name($name);$scopes=CredentialEncoding::scopes($scopes);$ttl=$this->lifetime($ttl);$root=CredentialState::root($this->site,$scope,$subject);$deadline=$this->deadline();$seen=$this->now();
        $actor=$this->actor($scope,$subject,$sessionToken,'issue',$deadline,$seen);$this->entitlement($scopes,$actor['scopes']);$now=$this->tick($deadline,$seen);$initial=CredentialState::empty($scope,$subject,$actor['identity']['fingerprint'],$this->policy,$now,bin2hex(random_bytes(16)));$before=$this->snapshot($scope,$root,$now,$initial);
        $this->protect('issue',$actor['session']->account(),['owner'=>$subject,'name'=>$name,'scopes'=>$scopes,'ttl'=>$ttl]);$after=$this->actor($scope,$subject,$sessionToken,'issue',$deadline,$seen);$this->sameActor($actor,$after);$this->entitlement($scopes,$after['scopes']);$now=$this->tick($deadline,$seen);
        $epoch=$before===null||!hash_equals($before['identity'],$after['identity']['fingerprint'])?bin2hex(random_bytes(16)):$before['epoch'];$id=bin2hex(random_bytes(16));
        $issuer=CredentialState::root($this->site,$scope,$after['session']->account()->subject());list($record,$token)=$this->signedRecord($scope,$subject,$root,$epoch,$id,$this->record($name,$scopes,$after['identity'],$now,$now,$now+$ttl,1,null,$issuer));
        $this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$subject,$root,$before,$after,$epoch,$now,$id,$record){
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);
            if(($before===null&&$state!==null)||($before!==null&&($state===null||!hash_equals($before['epoch'],$state['epoch'])||!hash_equals($before['identity'],$state['identity'])))){throw new SecurityException('Credential epoch changed before issuance.','api_credentials.changed');}
            if($state===null||!hash_equals($state['identity'],$after['identity']['fingerprint'])){$state=CredentialState::empty($scope,$subject,$after['identity']['fingerprint'],$this->policy,$now,$epoch);}
            $state=CredentialState::prune($state,$now);if(count($state['entries'])>=$this->policy->capacity()||isset($state['entries'][$id])){throw new SecurityException('Managed credential capacity exhausted.','api_credentials.capacity');}$state['entries'][$id]=$record;return new Change($state,0,null);
        });
        return $this->issued($scope,$subject,$sessionToken,'issue',$actor,$root,$record,$token,$deadline,$seen);
    }
    public function rotate(string $scope,string $subject,string $sessionToken,string $id,int $expectedGeneration):?IssuedCredential
    {
        return $this->stateCall('rotate',func_get_args());
    }
    private function rotateInternal(string $scope,string $subject,string $sessionToken,string $id,int $expectedGeneration):?IssuedCredential
    {
        $this->stateAdmission($scope);
        return $this->replacement($scope,$subject,$sessionToken,$id,$expectedGeneration,null,null,null,'rotate');
    }
    /** Replaces capabilities/name and optionally shortens expiry; always rotates the secret and never extends expiry. */
    public function replace(string $scope,string $subject,string $sessionToken,string $id,int $expectedGeneration,string $name,array $scopes,?int $ttl=null):?IssuedCredential
    {
        return $this->stateCall('replace',func_get_args());
    }
    private function replaceInternal(string $scope,string $subject,string $sessionToken,string $id,int $expectedGeneration,string $name,array $scopes,?int $ttl=null):?IssuedCredential
    {
        $this->stateAdmission($scope);
        $name=CredentialEncoding::name($name);$scopes=CredentialEncoding::scopes($scopes);if($ttl!==null){$this->lifetime($ttl);}return $this->replacement($scope,$subject,$sessionToken,$id,$expectedGeneration,$name,$scopes,$ttl,'replace');
    }
    private function replacement(string $scope,string $subject,string $sessionToken,string $id,int $generation,?string $name,?array $scopes,?int $ttl,string $operation):?IssuedCredential
    {
        CredentialEncoding::id($id);CredentialEncoding::version($generation);$root=CredentialState::root($this->site,$scope,$subject);$deadline=$this->deadline();$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,$operation,$deadline,$seen);$before=$this->snapshot($scope,$root,$this->tick($deadline,$seen));$old=$before['entries'][$id] ?? null;
        $this->protect($operation,$actor['session']->account(),['owner'=>$subject,'id'=>$id,'generation'=>$generation,'name'=>$name,'scopes'=>$scopes,'ttl'=>$ttl]);$after=$this->actor($scope,$subject,$sessionToken,$operation,$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);
        if($old===null||$old['generation']!==$generation||$old['expires']<=$now||!hash_equals($before['identity'],$after['identity']['fingerprint'])){return null;}
        if($generation===PHP_INT_MAX){throw new StorageException('Credential generation exhausted.','api_credentials.capacity');}$scopes=$scopes ?? $old['scopes'];$name=$name ?? $old['name'];$this->entitlement($scopes,$after['scopes']);$expires=$ttl===null?$old['expires']:min($old['expires'],$now+$ttl);
        $issuer=CredentialState::root($this->site,$scope,$after['session']->account()->subject());list($record,$token)=$this->signedRecord($scope,$subject,$root,$before['epoch'],$id,$this->record($name,$scopes,$after['identity'],$old['created'],$now,$expires,$generation+1,$old['last_used'],$issuer,$old['creator']));
        $changed=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$now,$before,$id,$old,$record){
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,false);}$state=CredentialState::prune($state,$now);$current=$state['entries'][$id] ?? null;
            if(!hash_equals($state['epoch'],$before['epoch'])||!hash_equals($state['identity'],$before['identity'])||$current===null||$current['generation']!==$old['generation']||!hash_equals($current['digest'],$old['digest'])){return new Change($state,0,false);}$state['entries'][$id]=$record;return new Change($state,0,true);
        });
        if(!$changed){return null;}return $this->issued($scope,$subject,$sessionToken,$operation,$actor,$root,$record,$token,$deadline,$seen);
    }
    private function issued(string $scope,string $subject,string $sessionToken,string $operation,array $actor,string $root,array $record,string $token,Deadline $deadline,int &$seen):IssuedCredential
    {
        $parts=CredentialEncoding::parse($token);
        try{
            $after=$this->actor($scope,$subject,$sessionToken,$operation,$deadline,$seen);$this->sameActor($actor,$after);$this->entitlement($record['scopes'],$after['scopes']);$now=$this->tick($deadline,$seen);
            $live=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$parts,$now){$state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,false);}$state=CredentialState::prune($state,$now);return new Change($state,0,CredentialState::matches($state,$parts));});
            $this->tick($deadline,$seen);if(!$live||$seen>=$record['expires']){throw new SecurityException('Issued credential changed or expired during I/O.','api_credentials.changed');}
            return new IssuedCredential($token,CredentialState::info($parts['id'],$record));
        }catch(\Throwable $error){$this->discard($scope,$root,$parts,$seen);throw $error;}
    }
    /** Caller authorizes this metadata query; returned values are not reusable credential authority. */
    public function all(string $scope,string $subject,string $sessionToken):array
    {
        return $this->stateCall('all',func_get_args());
    }
    private function allInternal(string $scope,string $subject,string $sessionToken):array
    {
        $this->stateAdmission($scope);
        $root=CredentialState::root($this->site,$scope,$subject);$deadline=$this->deadline();$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,'all',$deadline,$seen);$this->protect('all',$actor['session']->account(),['owner'=>$subject]);$after=$this->actor($scope,$subject,$sessionToken,'all',$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);$epoch=bin2hex(random_bytes(16));
        $rows=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$subject,$root,$after,$now,$epoch){
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,[]);}
            if(!hash_equals($state['identity'],$after['identity']['fingerprint'])){$state=CredentialState::empty($scope,$subject,$after['identity']['fingerprint'],$this->policy,$now,$epoch);}$state=CredentialState::prune($state,$now);return new Change($state,0,$state['entries']);
        });
        $final=$this->actor($scope,$subject,$sessionToken,'all',$deadline,$seen);$this->sameActor($actor,$final);$result=[];foreach($rows as $id=>$row){$result[]=CredentialState::info($id,$row);}return $result;
    }
    /** Revokes every generation of this management ID, scoped to the actual signed-in subject. */
    public function revoke(string $scope,string $subject,string $sessionToken,string $id):bool
    {
        return $this->stateCall('revoke',func_get_args());
    }
    private function revokeInternal(string $scope,string $subject,string $sessionToken,string $id):bool
    {
        $this->stateAdmission($scope);
        CredentialEncoding::id($id);$root=CredentialState::root($this->site,$scope,$subject);$deadline=$this->deadline();$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,'revoke',$deadline,$seen);$this->protect('revoke',$actor['session']->account(),['owner'=>$subject,'id'=>$id]);$after=$this->actor($scope,$subject,$sessionToken,'revoke',$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);
        $result=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$id,$now){$state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now,false);if($state===null){return new Change(null,0,false);}$state=CredentialState::prune($state,$now);$exists=isset($state['entries'][$id]);unset($state['entries'][$id]);return new Change($state,0,$exists);});
        $final=$this->actor($scope,$subject,$sessionToken,'revoke',$deadline,$seen);$this->sameActor($actor,$final);return $result;
    }
    /** Explicit revoke-all also installs the current policy on a valid old-format-policy ledger, invalidating all tokens. */
    public function revokeAll(string $scope,string $subject,string $sessionToken):int
    {
        return $this->stateCall('revokeAll',func_get_args());
    }
    private function revokeAllInternal(string $scope,string $subject,string $sessionToken):int
    {
        $this->stateAdmission($scope);
        $root=CredentialState::root($this->site,$scope,$subject);$deadline=$this->deadline();$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,'revoke_all',$deadline,$seen);$this->protect('revoke_all',$actor['session']->account(),['owner'=>$subject]);$after=$this->actor($scope,$subject,$sessionToken,'revoke_all',$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);$epoch=bin2hex(random_bytes(16));
        $count=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$subject,$root,$now,$after,$epoch){$state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now,false);$count=$state===null?0:count(CredentialState::prune($state,$now)['entries']);return new Change(CredentialState::empty($scope,$subject,$after['identity']['fingerprint'],$this->policy,$now,$epoch),0,$count);});
        $final=$this->actor($scope,$subject,$sessionToken,'revoke_all',$deadline,$seen);$this->sameActor($actor,$final);return $count;
    }
    public function fromAuthorization(string $scope,$header,string $requiredScope):?VerifiedCredential
    {
        return $this->stateCall('fromAuthorization',[$scope,$header,$requiredScope]);
    }
    private function fromAuthorizationInternal(string $scope,$header,string $requiredScope,?Deadline $operationDeadline=null):?VerifiedCredential
    {
        $this->stateAdmission($scope);
        $token=is_string($header)&&strlen($header)<=520&&preg_match('/\ABearer ([A-Za-z0-9._-]+)\z/iD',$header,$match)?$match[1]:null;return $this->authenticateInternal($scope,$token,$requiredScope,$operationDeadline);
    }
    /**
     * Native protected business unit. prepare must only read server-owned rows and return a validated Intent.
     * work uses this exact PDO and Intent; no DDL, transaction control, external effects or implicit retries.
     * All table writers must share this witness. A returned result is usable only after this call succeeds.
     */
    public function withAuthorization(string $scope,$header,string $requiredScope,\PDO $connection,array $tables,\SoSecurity\Authorization\RolePolicy $businessPolicy,callable $prepare,callable $work)
    {
        return $this->withBusinessAuthorization($scope,$header,$requiredScope,$connection,$tables,$businessPolicy,$prepare,$work);
    }
    /** Captured custom policy checked at admission, before effects, and before returning committed results. */
    public function withSnapshotAuthorization(string $scope,$header,string $requiredScope,\PDO $connection,array $tables,\SoSecurity\Authorization\SnapshotPolicy $businessPolicy,callable $prepare,callable $work)
    {
        return $this->withBusinessAuthorization($scope,$header,$requiredScope,$connection,$tables,$businessPolicy,$prepare,$work);
    }
    private function withBusinessAuthorization(string $scope,$header,string $requiredScope,\PDO $connection,array $tables,\SoSecurity\Authorization\PolicyProvider $businessPolicy,callable $prepare,callable $work)
    {
        if(!$businessPolicy instanceof \SoSecurity\Authorization\RolePolicy&&!$businessPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){throw new ConfigurationException('Use a supported business policy.','configuration.authorization_state');}
        if($this->statePolicy===null||!$this->statePolicy->credentialSqlContext($connection,$tables)){throw new ConfigurationException('Use the native protected graph and its complete declared business SQL tables.','configuration.state_business');}
        if($businessPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy&&!$businessPolicy->matches($this->statePolicy)){throw new ConfigurationException('Use the exact captured business policy source.','configuration.authorization_state');}
        if($this->stateBusy||$this->boundary->active()){throw new ConfigurationException('Enter native API requests once, without an outer effect context.','configuration.state_request_nested');}
        $this->boundary->assertScope($scope);CredentialEncoding::scopes([$requiredScope]);if(!in_array($requiredScope,$this->policy->allowedScopes(),true)){throw new ConfigurationException('Protected route requires a configured credential scope.','configuration.api_credential_scope');}
        if(!is_string($header)||strlen($header)>520||preg_match('//u',$header)!==1){$header=null;}
        $names=array_keys($tables);sort($names);$intent=null;$observed=null;$deadline=$this->deadline();$this->stateBusy=true;
        try{$result=$this->boundary->run('api.credentials.execute',function()use($scope,$header,$requiredScope,$connection,$work,$businessPolicy,&$intent,&$observed,$deadline){
            if($businessPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){
                $this->assertBusinessDecision($businessPolicy,$this->admitted['proof']->account(),$intent,$observed);
            }
            $proof=$this->fromAuthorizationInternal($scope,$header,$requiredScope,$deadline);if($proof===null){return null;}
            $seen=$this->now();$unit=new \SoSecurity\Support\SqlTransaction($connection,$this->clock,$this->policy->ioMilliseconds());
            $live=function()use($proof,&$seen):void{
                $now=$this->now();if($now<$seen){throw new StorageException('Business authorization clock moved backwards.','api_credentials.clock');}$seen=$now;
                if($proof->expiresAt()<=$now){throw new SecurityException('Business authorization expired during the owned transaction.','api_credentials.denied');}
            };
            return $unit->run(function()use($unit,$connection,$proof,$intent,$work){return $unit->invoke($work,[$connection,$proof,$intent],'api_credentials.business_unavailable');},null,$live,$live,$deadline);
        },function(string $expected)use($scope,$header,$requiredScope,$connection,$names,$businessPolicy,$prepare,&$intent,&$observed){
            if($this->nativeAdmission('fromAuthorization',[$scope,$header,$requiredScope],true,$expected)===false){return false;}
            $admitted=$this->admitted;$proof=$admitted['proof'];$at=$this->now();
            // Detached arguments also prevent a reference-declaring host callback from replacing local authority.
            $prepareConnection=$connection;$prepareProof=$proof;
            try{$candidate=$prepare($prepareConnection,$prepareProof);}catch(SecurityException $error){throw $error;}catch(ConfigurationException $error){throw $error;}catch(ValidationException $error){throw $error;}catch(\Throwable $error){throw new DependencyException('Business resource loading unavailable.','api_credentials.business_unavailable');}
            if(!$candidate instanceof \SoSecurity\Operation\Intent||$candidate->resource()->scope()!==$scope){throw new ConfigurationException('Load a same-scope server resource and validated business intent.','configuration.state_business');}
            $this->assertBusinessDecision($businessPolicy,$proof->account(),$candidate,$expected);$observed=$expected;
            $end=$this->now();if($end<$at||$at<$admitted['at']){throw new StorageException('Business admission clock moved backwards.','api_credentials.clock');}if($proof->expiresAt()<=$end){return false;}$intent=$candidate;
            return $this->nativeIntent('execute',$scope,$proof->account()->subject(),$proof->account()->subject(),$admitted['identity'],$admitted['identity'],['digest'=>$admitted['credential']],['required_scope'=>$requiredScope,'intent'=>$intent->fingerprint(),'business_policy'=>$businessPolicy->fingerprint(),'tables'=>$names],$admitted['scopes'],$expected,$end);
        },null,$deadline);
            if($intent!==null){$review=null;
                if($businessPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){$review=function(string $expected,VerifiedCredential $proof)use($businessPolicy,$intent):void{$this->assertBusinessDecision($businessPolicy,$proof->account(),$intent,$expected);};}
                $this->currentBearer('execute_check','fromAuthorization',[$scope,$header,$requiredScope],$deadline,$review);}
            return $result;
        }finally{$this->admitted=null;$this->stateBusy=false;}
    }
    private function assertBusinessDecision(\SoSecurity\Authorization\PolicyProvider $policy,\SoSecurity\Auth\Account $actor,?\SoSecurity\Operation\Intent $intent,?string $expected):void
    {
        if($intent===null||$expected===null){throw new ConfigurationException('Captured business admission required.','configuration.state_business');}
        $decision=$policy instanceof \SoSecurity\Authorization\SnapshotPolicy?$policy->evaluate($this->statePolicy,$expected,$actor,$intent->action(),$intent->resource(),$intent->fields()):$policy->decide($actor,$intent->action(),$intent->resource(),$intent->fields());
        if($decision===null||!$decision->allowed()||array_diff($intent->fields(),$decision->fields())){throw new SecurityException('Business object or field authorization denied.','authorization.denied');}
    }
    public function authenticate(string $scope,$token,string $requiredScope):?VerifiedCredential
    {
        return $this->stateCall('authenticate',[$scope,$token,$requiredScope]);
    }
    private function authenticateInternal(string $scope,$token,string $requiredScope,?Deadline $operationDeadline=null):?VerifiedCredential
    {
        $this->stateAdmission($scope);
        Guard::label($scope);if(!preg_match('//u',$scope)){throw new ConfigurationException('Credential scope must be UTF-8.','configuration.api_credentials');}CredentialEncoding::scopes([$requiredScope]);if(!in_array($requiredScope,$this->policy->allowedScopes(),true)){throw new ConfigurationException('Protected route requires a configured credential scope.','configuration.api_credential_scope');}
        $deadline=$operationDeadline??$this->deadline();$seen=$this->now();$this->protect('authenticate',null,['required_scope'=>$requiredScope]);$parts=CredentialEncoding::parse($token);$this->tick($deadline,$seen);
        if($parts===null||!$this->keys->verify($parts['key_id'],CredentialEncoding::message($this->site,$scope,$parts),$parts['mac'])){return null;}$root=$parts['root'];$now=$this->tick($deadline,$seen);
        $proof=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$parts,$requiredScope,$now){
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,null);}$state=CredentialState::prune($state,$now);$record=$state['entries'][$parts['id']] ?? null;
            $valid=CredentialState::matches($state,$parts)&&$parts['issued']<=$now&&$record!==null&&in_array($requiredScope,$record['scopes'],true);
            return new Change($state,0,$valid?['subject'=>$state['subject'],'identity'=>$state['identity'],'record'=>$record]:null);
        });
        try{
            $now=$this->tick($deadline,$seen);if($parts['expires']<=$now){$this->discard($scope,$root,$parts,$now);return null;}if($proof===null){return null;}
            $identity=$this->identity($scope,$proof['subject']);$now=$this->tick($deadline,$seen);
            if($identity===null||!hash_equals($proof['identity'],$identity['fingerprint'])){$this->invalidate($scope,$root,$parts['epoch'],$proof['identity'],$now);return null;}
            $allowed=$this->capabilities($identity['account']);$now=$this->tick($deadline,$seen);if($parts['expires']<=$now){$this->discard($scope,$root,$parts,$now);return null;}if(!in_array($requiredScope,$allowed,true)){return null;}
            $record=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$parts,$proof,$requiredScope,$now){
                $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,null);}$state=CredentialState::prune($state,$now);
                if(!CredentialState::matches($state,$parts)||!hash_equals($state['identity'],$proof['identity'])||!in_array($requiredScope,$state['entries'][$parts['id']]['scopes'],true)){return new Change($state,0,null);}
                $state['entries'][$parts['id']]['last_used']=$now;return new Change($state,0,$state['entries'][$parts['id']]);
            });
            if($record===null){$this->tick($deadline,$seen);return null;}$fresh=$this->identity($scope,$proof['subject']);$now=$this->tick($deadline,$seen);
            if($fresh===null||!hash_equals($proof['identity'],$fresh['fingerprint'])){$this->invalidate($scope,$root,$parts['epoch'],$proof['identity'],$now);return null;}
            $effective=array_values(array_intersect($record['scopes'],$allowed,$this->capabilities($fresh['account'])));$now=$this->tick($deadline,$seen);
            if($parts['expires']<=$now){$this->discard($scope,$root,$parts,$now);return null;}if(!in_array($requiredScope,$effective,true)){return null;}
            // Provider/capability I/O may race credential revocation; recheck the exact generation afterwards.
            $live=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$parts,$proof,$requiredScope,$now){
                $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,false);}$state=CredentialState::prune($state,$now);
                return new Change($state,0,CredentialState::matches($state,$parts)&&hash_equals($state['identity'],$proof['identity'])&&in_array($requiredScope,$state['entries'][$parts['id']]['scopes'],true));
            });
            $now=$this->tick($deadline,$seen);if(!$live){return null;}if($parts['expires']<=$now){$this->discard($scope,$root,$parts,$now);return null;}
            return new VerifiedCredential($fresh['account'],CredentialState::info($parts['id'],$record),$effective);
        }catch(\Throwable $error){$this->discardIfTimeInvalid($scope,$root,$parts,$seen);throw $error;}
    }
    private function discardIfTimeInvalid(string $scope,string $root,array $parts,int $seen):void
    {
        try{$now=$this->now();}catch(\Throwable $clockError){$this->discard($scope,$root,$parts,$seen);return;}
        if($now<$seen||$now>=$parts['expires']){$this->discard($scope,$root,$parts,max($seen,$now));}
    }
    /** Exact cleanup cannot remove a concurrently rotated replacement or a new account epoch. */
    private function discard(string $scope,string $root,array $parts,int $floor):void
    {
        $this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$parts,$floor){
            $at=is_array($state)&&isset($state['seen'])&&is_int($state['seen'])?max($floor,$state['seen']):$floor;
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$at);if($state===null){return new Change(null,0,null);}$state=CredentialState::prune($state,$at);if(CredentialState::matches($state,$parts)){unset($state['entries'][$parts['id']]);}return new Change($state,0,null);
        });
    }
    private function invalidate(string $scope,string $root,string $epoch,string $fingerprint,int $now):void
    {
        $replacement=bin2hex(random_bytes(16));$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$epoch,$fingerprint,$now,$replacement){
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,null);}$state=CredentialState::prune($state,$now);
            if(hash_equals($epoch,$state['epoch'])&&hash_equals($fingerprint,$state['identity'])){$state['epoch']=$replacement;$state['entries']=[];}return new Change($state,0,null);
        });
    }
    /** Native factory requests enter directly; a manually opened effect context cannot substitute for admission. */
    private function stateCall(string $method,array $args)
    {
        $call=$method.'Internal';if($this->statePolicy===null){return $this->$call(...$args);}
        if($this->stateBusy||$this->boundary->active()){throw new ConfigurationException('Enter native API requests once, without an outer effect context.','configuration.state_request_nested');}$this->boundary->assertScope($args[0]);$bearer=in_array($method,['authenticate','fromAuthorization'],true);$scope=$args[0];
        if($bearer){Guard::label($scope);if(!preg_match('//u',$scope)){throw new ConfigurationException('Credential scope must be UTF-8.','configuration.api_credentials');}CredentialEncoding::scopes([$args[2]]);if(!in_array($args[2],$this->policy->allowedScopes(),true)){throw new ConfigurationException('Protected route requires a configured credential scope.','configuration.api_credential_scope');}if(!is_string($args[1])||strlen($args[1])>520||preg_match('//u',$args[1])!==1){$args[1]=null;}}
        else{
            CredentialState::root($this->site,$scope,$args[1]);if(\SoSecurity\Auth\SessionRegistry::reference($args[2])===null){throw new SecurityException('Current management session required.','api_credentials.denied');}
            if($method==='issue'){$args[3]=CredentialEncoding::name($args[3]);$args[4]=CredentialEncoding::scopes($args[4]);$args[5]=$this->lifetime($args[5]??null);}
            if(in_array($method,['rotate','replace','revoke'],true)){CredentialEncoding::id($args[3]);}if(in_array($method,['rotate','replace'],true)){CredentialEncoding::version($args[4]);}
            if($method==='replace'){$args[5]=CredentialEncoding::name($args[5]);$args[6]=CredentialEncoding::scopes($args[6]);if(isset($args[7])){$this->lifetime($args[7]);}}
        }
        // Input arrays may contain references. Detach the bounded native arguments before any host callback.
        $json=json_encode($args);if($json===false){throw new ValidationException('Use bounded UTF-8 API request inputs.','api_credentials.input');}$args=json_decode($json,true);$bearerDeadline=$bearer?$this->deadline():null;$this->stateBusy=true;
        try{
            if(($this->nativeAudit!==null||$this->managementPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy)&&!$bearer){$this->auditDeadline=$this->deadline();$this->auditAdmissionDeadline=$this->deadline();$this->auditSeen=0;$this->tick($this->auditDeadline,$this->auditSeen);}
            $result=$this->boundary->run('api.credentials.'.($bearer?'authenticate':($method==='revokeAll'?'revoke_all':$method)),function()use($call,$args,$bearer,$bearerDeadline):array{
                if($this->auditPlan!==null){$this->auditCurrent($this->auditPlan['expected'],'before');if($this->auditPlan['writer']!==null){($this->auditPlan['writer'])();}if(!$this->auditPlan['allowed']){return ['denied'=>true,'value'=>null];}}
                $internal=$args;if($bearer){$internal[]=$bearerDeadline;}return ['denied'=>false,'value'=>$this->$call(...$internal)];
            },function(string $expected)use($method,$args,$bearer){return $this->nativeAdmission($method,$args,$bearer,$expected);},null,$bearerDeadline??$this->auditAdmissionDeadline,$bearerDeadline??$this->auditDeadline);
            if($result===null){return null;}
            if($bearerDeadline!==null&&$result['value'] instanceof VerifiedCredential){
                $current=$this->currentBearer('authenticate_check',$method,$args,$bearerDeadline);
                $effective=array_values(array_intersect($result['value']->scopes(),$current->scopes()));
                if(!in_array($args[2],$effective,true)){throw new SecurityException('Current bearer capability required.','api_credentials.denied');}
                return new VerifiedCredential($current->account(),$current->metadata(),$effective);
            }
            if($this->auditPlan!==null){$this->boundary->run('api.credentials.audit_check',static function():void{throw new ConfigurationException('Audit completion is read only.','configuration.audit_state');},function(string $expected):bool{$this->auditCurrent($expected,'return');return false;},null,$this->auditDeadline);}
            if($this->auditPlan!==null){$this->auditTime();}elseif($this->auditDeadline!==null){$this->tick($this->auditDeadline,$this->auditSeen);}
            if($result['denied']){throw new SecurityException('Authorization denied.','authorization.denied');}return $result['value'];
        }finally{$this->admitted=null;$this->auditPlan=null;$this->auditDeadline=null;$this->auditAdmissionDeadline=null;$this->stateBusy=false;}
    }
    /** Read-only completion; no replay, last-use update, or cached entitlement reuse. */
    private function currentBearer(string $operation,string $method,array $args,Deadline $deadline,?callable $review=null):VerifiedCredential
    {
        $this->admitted=null;$completedProof=null;$checkedAt=0;
        $this->boundary->run('api.credentials.'.$operation,static function():void{throw new ConfigurationException('Bearer completion checks are read only.','configuration.state_business');},function(string $expected)use($method,$args,$review,&$completedProof,&$checkedAt):bool{
            if($this->nativeAdmission($method,$args,true,$expected)===false){throw new SecurityException('Bearer authority changed before return.','api_credentials.denied');}
            $completedProof=$this->admitted['proof'];$checkedAt=$this->admitted['at'];if($review!==null){$review($expected,$completedProof);}return false;
        },null,$deadline);
        if(!$completedProof instanceof VerifiedCredential){throw new ConfigurationException('Current bearer credential proof required.','configuration.state_business');}
        $now=$this->tick($deadline,$checkedAt);
        if($completedProof->expiresAt()<=$now){throw new SecurityException('Bearer credential expired before return.','api_credentials.denied');}
        return $completedProof;
    }
    /** @return false|\SoSecurity\Account\StateOperation */
    private function nativeAdmission(string $method,array $a,bool $bearer,string $expected)
    {
        $scope=$a[0];$now=$this->now();$action=$method==='revokeAll'?'revoke_all':$method;
        if($bearer){
            $this->protect('authenticate',null,['required_scope'=>$a[2]]);$token=$a[1];if($method==='fromAuthorization'){$token=is_string($token)&&preg_match('/\ABearer ([A-Za-z0-9._-]+)\z/iD',$token,$match)?$match[1]:null;}$parts=CredentialEncoding::parse($token);if($parts===null||!$this->keys->verify($parts['key_id'],CredentialEncoding::message($this->site,$scope,$parts),$parts['mac'])||$parts['issued']>$now||$parts['expires']<=$now){return false;}
            $raw=$this->statePolicy->credentialBytes(CredentialState::key($this->site,$parts['root']),$expected);$state=CredentialState::read($raw===null?null: \SoSecurity\Storage\Codec::decode($raw,$now),$this->policy,$this->site,$scope,$parts['root'],$now);if($state===null||!CredentialState::matches($state,$parts)||!in_array($a[2],$state['entries'][$parts['id']]['scopes'],true)){return false;}
            $identity=$this->statePolicy->credentialView($scope,$state['subject'],null,$expected);if($identity===null||!hash_equals($state['identity'],$identity['fingerprint'])){return false;}$allowed=$this->capabilities($identity['account']);$end=$this->now();if($end<$now){throw new StorageException('API admission clock moved backwards.','api_credentials.clock');}if(!in_array($a[2],$allowed,true)||$parts['expires']<=$end){return false;}$this->admitted=['manager'=>$state['subject'],'account'=>$identity['account']->fingerprint(),'scopes'=>$allowed,'proof'=>new VerifiedCredential($identity['account'],CredentialState::info($parts['id'],$state['entries'][$parts['id']]),array_values(array_intersect($state['entries'][$parts['id']]['scopes'],$allowed))),'identity'=>$identity['fingerprint'],'credential'=>$parts['digest'],'at'=>$end];return $this->nativeIntent($method,$scope,$state['subject'],$state['subject'],$identity['fingerprint'],$identity['fingerprint'],['digest'=>$parts['digest']],['required_scope'=>$a[2]],$allowed,$expected,$end);
        }
        $subject=$a[1];$manager=$subject;if($this->managementSubject!==null){try{$manager=($this->managementSubject)($scope);if(!is_string($manager)){throw new \RuntimeException('Invalid operator.');}CredentialState::root($this->site,$scope,$manager);}catch(\Throwable $error){throw new DependencyException('API credential operator unavailable.','api_credentials.management_unavailable');}}
        $pair=$this->statePolicy->credentialPair($scope,$manager,$a[2],$subject,$expected);$actor=$pair['actor'];if($actor===null||$actor['session']===null){throw new SecurityException('Current management session required.','api_credentials.denied');}$identity=$pair['target'];if($identity===null){throw new SecurityException('Management identity changed.','api_credentials.denied');}$session=$actor['session'];$minimum=$manager===$subject?$this->policy->minimumStrength():max($this->policy->minimumStrength(),$this->policy->delegatedMinimumStrength());
        if(in_array($method,['issue','rotate','replace'],true)&&(!$session->recent($this->policy->freshAge(),$this->now(),$minimum)||!in_array($session->method(),$this->policy->methods(),true))){throw new SecurityException('Recent configured authentication required.','api_credentials.reauthentication');}
        $metadata=$this->nativeMetadata($method,$a,$subject);
        if($manager!==$subject){if($this->managementPolicy===null){throw new SecurityException('Cross-account credential management is disabled.','api_credentials.denied');}$decision=$this->managementDecision($actor['account'],'api.credentials.'.$action,new Resource($scope,'api_credential_owner',$subject,$identity['fingerprint'],['owner'=>$subject]),$expected);if($this->managementPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){if($this->auditDeadline!==null){$this->tick($this->auditDeadline,$this->auditSeen);}}if($decision===null||!$decision->allowed()){
            if($this->nativeAudit===null){throw new SecurityException('Authorization denied.','authorization.denied');}
            $this->protect($action,$actor['account'],$metadata);$this->admitted=['manager'=>$manager,'account'=>$identity['account']->fingerprint(),'scopes'=>[]];
            $this->prepareAudit($method,$a,$actor,$identity,$manager,$metadata,[],false,$expected);
            return $this->nativeIntent($method,$scope,$manager,$subject,$actor['fingerprint'],$identity['fingerprint'],\SoSecurity\Auth\SessionRegistry::reference($a[2]),$metadata,[],$expected,$this->now());
        }}$allowed=$this->capabilities($identity['account']);$root=CredentialState::root($this->site,$scope,$subject);$raw=$this->statePolicy->credentialBytes(CredentialState::key($this->site,$root),$expected);$state=CredentialState::read($raw===null?null: \SoSecurity\Storage\Codec::decode($raw,$now),$this->policy,$this->site,$scope,$root,$now,!in_array($method,['revoke','revokeAll'],true));
        $this->protect($action,$actor['account'],$metadata);
        if($method==='issue'){$this->entitlement($a[4],$allowed);$live=$state!==null&&hash_equals($state['identity'],$identity['fingerprint'])?CredentialState::prune($state,$now)['entries']:[];if(count($live)>=$this->policy->capacity()){throw new SecurityException('Managed credential capacity exhausted.','api_credentials.capacity');}if(!$this->statePolicy->credentialCapacity(CredentialState::key($this->site,$root),$expected)){throw new SecurityException('Managed credential physical snapshot capacity reached.','api_credentials.capacity');}}
        if(in_array($method,['rotate','replace'],true)){$old=$state['entries'][$a[3]]??null;if($old===null||$old['generation']!==$a[4]||$old['expires']<=$now||!hash_equals($state['identity'],$identity['fingerprint'])){return false;}if($a[4]===PHP_INT_MAX){throw new StorageException('Credential generation exhausted.','api_credentials.capacity');}$this->entitlement($method==='replace'?$a[6]:$old['scopes'],$allowed);}
        $end=$this->now();if($end<$now){throw new StorageException('API admission clock moved backwards.','api_credentials.clock');}if($session->expiresAt()<=$end){throw new SecurityException('Current management session required.','api_credentials.denied');}if(in_array($method,['issue','rotate','replace'],true)&&!$session->recent($this->policy->freshAge(),$end,$minimum)){throw new SecurityException('Recent configured authentication required.','api_credentials.reauthentication');}
        $this->admitted=['manager'=>$manager,'account'=>$identity['account']->fingerprint(),'scopes'=>$allowed];if($manager!==$subject&&($this->nativeAudit!==null||$this->managementPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy)){$this->prepareAudit($method,$a,$actor,$identity,$manager,$metadata,$allowed,true,$expected);}return $this->nativeIntent($method,$scope,$manager,$subject,$actor['fingerprint'],$identity['fingerprint'],\SoSecurity\Auth\SessionRegistry::reference($a[2]),$metadata,$allowed,$expected,$end);
    }
    private function nativeMetadata(string $method,array $a,string $subject):array
    {
        $metadata=['owner'=>$subject];if($method==='issue'){$metadata+=['name'=>$a[3],'scopes'=>$a[4],'ttl'=>$a[5]];}
        elseif(in_array($method,['rotate','replace'],true)){$metadata+=['id'=>$a[3],'generation'=>$a[4],'name'=>$method==='replace'?$a[5]:null,'scopes'=>$method==='replace'?$a[6]:null,'ttl'=>$method==='replace'?($a[7]??null):null];}
        elseif($method==='revoke'){$metadata['id']=$a[3];}
        return $metadata;
    }
    private function prepareAudit(string $method,array $a,array $actor,array $owner,string $manager,array $metadata,array $scopes,bool $allowed,string $expected):void
    {
        $writer=$this->nativeAudit===null?null:$this->statePolicy->prepareCredentialAudit($this->nativeAudit,$manager,$allowed,$this->auditAdmissionDeadline);
        $this->auditPlan=['method'=>$method,'action'=>$method==='revokeAll'?'revoke_all':$method,'scope'=>$a[0],'owner'=>$a[1],'token'=>$a[2],'manager'=>$manager,'actor'=>$actor,'identity'=>$owner,'metadata'=>$metadata,'scopes'=>$scopes,'allowed'=>$allowed,'expected'=>$expected,'writer'=>$writer];
        $this->auditCurrent($expected,'admission');
    }
    private function auditTime():int
    {
        $plan=$this->auditPlan;if($plan===null||$this->auditDeadline===null){throw new ConfigurationException('Exact audit completion required.','configuration.audit_state');}
        $now=$this->tick($this->auditDeadline,$this->auditSeen);$session=$plan['actor']['session'];
        if($session->expiresAt()<=$now||(in_array($plan['method'],['issue','rotate','replace'],true)&&!$session->recent($this->policy->freshAge(),$now,max($this->policy->minimumStrength(),$this->policy->delegatedMinimumStrength())))){throw new SecurityException('Audited authentication expired before return.','api_credentials.reauthentication');}return $now;
    }
    private function auditCurrent(string $expected,string $phase):void
    {
        $plan=$this->auditPlan;if($plan===null||$this->auditDeadline===null){throw new ConfigurationException('Exact audit admission required.','configuration.audit_state');}
        $this->tick($this->auditDeadline,$this->auditSeen);$operation=$this->nativeAudit===null?'management_current':'audit_current';$actor=$plan['actor']['account'];$metadata=['operation'=>$plan['action'],'phase'=>$phase]+$plan['metadata'];
        try{$allowed=($this->guard)($operation,$actor,$metadata);}catch(\Throwable $error){throw new DependencyException('Current audited request protection unavailable.','api_credentials.request_unavailable');}
        if($allowed!==true){throw new SecurityException('Current audited request protection denied.','api_credentials.denied');}
        if($plan['allowed']){
            $owner=$plan['identity']['account'];try{$scopes=($this->scopeProvider)($owner);if(!is_array($scopes)){throw new \RuntimeException('Invalid scopes.');}$scopes=CredentialEncoding::scopes($scopes,true);}catch(\Throwable $error){throw new DependencyException('Current audited scopes unavailable.','api_credentials.scopes_unavailable');}
            if(array_values(array_intersect($scopes,$this->policy->allowedScopes()))!==$plan['scopes']){throw new SecurityException('Audited capability authority changed.','api_credentials.scope_denied');}
        }
        $pair=$this->statePolicy->credentialPair($plan['scope'],$plan['manager'],$plan['token'],$plan['owner'],$expected);$current=$pair['actor'];$owner=$pair['target'];$now=$this->tick($this->auditDeadline,$this->auditSeen);
        if($current===null||$owner===null||$current['session']===null||!hash_equals($plan['actor']['fingerprint'],$current['fingerprint'])||!hash_equals($plan['identity']['fingerprint'],$owner['fingerprint'])||$current['session']->id()!==$plan['actor']['session']->id()||$current['session']->expiresAt()<=$now){throw new SecurityException('Audited management authority changed.','api_credentials.denied');}
        if(in_array($plan['method'],['issue','rotate','replace'],true)&&(!$current['session']->recent($this->policy->freshAge(),$now,max($this->policy->minimumStrength(),$this->policy->delegatedMinimumStrength()))||!in_array($current['session']->method(),$this->policy->methods(),true))){throw new SecurityException('Audited management authentication expired.','api_credentials.reauthentication');}
        $decision=$this->managementDecision($current['account'],'api.credentials.'.$plan['action'],new Resource($plan['scope'],'api_credential_owner',$plan['owner'],$owner['fingerprint'],['owner'=>$plan['owner']]),$expected);
        if(($decision!==null&&$decision->allowed())!==$plan['allowed']){throw new SecurityException('Audited object authorization changed.','authorization.denied');}
        $this->auditTime();
    }
    private function managementDecision(\SoSecurity\Auth\Account $actor,string $action,Resource $resource,string $expected):?\SoSecurity\Authorization\Decision
    {
        if($this->managementPolicy instanceof \SoSecurity\Authorization\SnapshotPolicy){return $this->managementPolicy->evaluate($this->statePolicy,$expected,$actor,$action,$resource);}
        return $this->managementPolicy->decide($actor,$action,$resource);
    }
    private function nativeIntent(string $method,string $scope,string $actor,string $target,string $actorIdentity,string $targetIdentity,array $credential,array $parameters,array $allowed,string $observed,int $authorizedAt):\SoSecurity\Account\StateOperation
    {
        $policyData=[$this->site,$scope,$this->statePolicy->binding(),$this->policy->fingerprint(),$this->managementPolicy===null?null:$this->managementPolicy->fingerprint(),$this->keys->currentId()];if($this->nativeAuditBinding!==null){$policyData[]=$this->nativeAuditBinding;}if($this->auditPlan!==null){$parameters['audit_allowed']=$this->auditPlan['allowed'];}$policy=hash('sha256','SoSecurity.Api.Credentials.AdmissionPolicy.1.'.json_encode($policyData,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $request=hash('sha256','SoSecurity.Api.Credentials.AdmissionRequest.1.'.json_encode(['entry'=>$method,'actor'=>$actor,'target'=>$target,'actor_identity'=>$actorIdentity,'target_identity'=>$targetIdentity,'credential'=>$credential,'parameters'=>$parameters,'allowed_scopes'=>$allowed,'observed'=>$observed,'policy'=>$policy],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $action=in_array($method,['authenticate','fromAuthorization'],true)?'authenticate':($method==='revokeAll'?'revoke_all':$method);
        return \SoSecurity\Account\StateOperation::credential('api.credentials.'.$action,$scope,$actor,$target,$request,$policy,$authorizedAt);
    }
    public function __debugInfo():array {return ['managed_credentials'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild API credential registries from trusted services.','configuration.api_credential_serialization');}
}
