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
    private $managementAuthorization;
    private $managementSubject;
    /** Identity/factor adapters MUST match the SessionRegistry's trusted authority. No I/O in construction. */
    public function __construct(AtomicStore $store,SessionRegistry $sessions,IdentityProvider $identities,HmacKeys $keys,string $site,callable $requestGuard,callable $scopeProvider,?CredentialPolicy $policy=null,?Clock $clock=null,?SecondFactor $factor=null,?Authorizer $managementAuthorization=null,?callable $managementSubject=null)
    {
        Guard::label($site);if(!preg_match('//u',$site)){throw new ConfigurationException('Credential site must be UTF-8.','configuration.api_credentials');}
        if(($managementAuthorization===null)!==($managementSubject===null)){throw new ConfigurationException('Delegated credential management needs both trusted operator resolution and object authorization.','configuration.api_credential_management');}
        $this->store=$store;$this->sessions=$sessions;$this->identities=new IdentityState($identities,$factor);$this->keys=$keys;$this->site=$site;$this->guard=$requestGuard;$this->scopeProvider=$scopeProvider;$this->policy=$policy ?? new CredentialPolicy();$this->clock=$clock ?? new SystemClock();$this->managementAuthorization=$managementAuthorization;$this->managementSubject=$managementSubject;
    }
    public function policy():CredentialPolicy {return $this->policy;}
    private function now():int
    {
        $now=$this->clock->now();if($now<0||$now>PHP_INT_MAX-31536000){throw new StorageException('Invalid API credential clock.','api_credentials.clock');}return $now;
    }
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('api_credentials.timeout');$now=$this->now();if($now<$seen){throw new StorageException('API credential clock moved backwards.','api_credentials.clock');}$seen=$now;return $now;
    }
    private function protect(string $operation,?Account $account,array $metadata):void
    {
        try{$allowed=($this->guard)($operation,$account,$metadata);}catch(\Throwable $error){throw new DependencyException('API credential request protection unavailable.','api_credentials.request_unavailable');}
        if($allowed!==true){throw new SecurityException('API credential request protection denied.','api_credentials.denied');}
    }
    private function identity(string $scope,string $subject):?array
    {
        try{$identity=$this->identities->load($scope,$subject);return $identity!==null&&$identity['mfa_required']&&$identity['factor']===null?null:$identity;}catch(\Throwable $error){throw new DependencyException('API credential identity authority unavailable.','api_credentials.identity_unavailable');}
    }
    private function capabilities(Account $account):array
    {
        try{$scopes=($this->scopeProvider)($account);if(!is_array($scopes)){throw new \RuntimeException('Invalid scope-provider result.');}$scopes=CredentialEncoding::scopes($scopes,true);}
        catch(\Throwable $error){throw new DependencyException('API credential scope authority unavailable.','api_credentials.scopes_unavailable');}
        return array_values(array_intersect($scopes,$this->policy->allowedScopes()));
    }
    private function actor(string $scope,string $subject,string $token,string $operation,Deadline $deadline,int &$seen):array
    {
        CredentialState::root($this->site,$scope,$subject);$this->tick($deadline,$seen);
        $manager=$subject;
        if($this->managementSubject!==null){
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
        return ['session'=>$current,'identity'=>$identity,'scopes'=>$scopes];
    }
    private function authorizeManagement(string $scope,string $owner,string $manager,Account $actor,string $operation,array $identity):void
    {
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
        $name=CredentialEncoding::name($name);$scopes=CredentialEncoding::scopes($scopes);$ttl=$this->lifetime($ttl);$root=CredentialState::root($this->site,$scope,$subject);$deadline=new Deadline($this->policy->ioMilliseconds());$seen=$this->now();
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
        return $this->replacement($scope,$subject,$sessionToken,$id,$expectedGeneration,null,null,null,'rotate');
    }
    /** Replaces capabilities/name and optionally shortens expiry; always rotates the secret and never extends expiry. */
    public function replace(string $scope,string $subject,string $sessionToken,string $id,int $expectedGeneration,string $name,array $scopes,?int $ttl=null):?IssuedCredential
    {
        $name=CredentialEncoding::name($name);$scopes=CredentialEncoding::scopes($scopes);if($ttl!==null){$this->lifetime($ttl);}return $this->replacement($scope,$subject,$sessionToken,$id,$expectedGeneration,$name,$scopes,$ttl,'replace');
    }
    private function replacement(string $scope,string $subject,string $sessionToken,string $id,int $generation,?string $name,?array $scopes,?int $ttl,string $operation):?IssuedCredential
    {
        CredentialEncoding::id($id);CredentialEncoding::version($generation);$root=CredentialState::root($this->site,$scope,$subject);$deadline=new Deadline($this->policy->ioMilliseconds());$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,$operation,$deadline,$seen);$before=$this->snapshot($scope,$root,$this->tick($deadline,$seen));$old=$before['entries'][$id] ?? null;
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
        $root=CredentialState::root($this->site,$scope,$subject);$deadline=new Deadline($this->policy->ioMilliseconds());$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,'all',$deadline,$seen);$this->protect('all',$actor['session']->account(),['owner'=>$subject]);$after=$this->actor($scope,$subject,$sessionToken,'all',$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);$epoch=bin2hex(random_bytes(16));
        $rows=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$subject,$root,$after,$now,$epoch){
            $state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now);if($state===null){return new Change(null,0,[]);}
            if(!hash_equals($state['identity'],$after['identity']['fingerprint'])){$state=CredentialState::empty($scope,$subject,$after['identity']['fingerprint'],$this->policy,$now,$epoch);}$state=CredentialState::prune($state,$now);return new Change($state,0,$state['entries']);
        });
        $final=$this->actor($scope,$subject,$sessionToken,'all',$deadline,$seen);$this->sameActor($actor,$final);$result=[];foreach($rows as $id=>$row){$result[]=CredentialState::info($id,$row);}return $result;
    }
    /** Revokes every generation of this management ID, scoped to the actual signed-in subject. */
    public function revoke(string $scope,string $subject,string $sessionToken,string $id):bool
    {
        CredentialEncoding::id($id);$root=CredentialState::root($this->site,$scope,$subject);$deadline=new Deadline($this->policy->ioMilliseconds());$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,'revoke',$deadline,$seen);$this->protect('revoke',$actor['session']->account(),['owner'=>$subject,'id'=>$id]);$after=$this->actor($scope,$subject,$sessionToken,'revoke',$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);
        $result=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$root,$id,$now){$state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now,false);if($state===null){return new Change(null,0,false);}$state=CredentialState::prune($state,$now);$exists=isset($state['entries'][$id]);unset($state['entries'][$id]);return new Change($state,0,$exists);});
        $final=$this->actor($scope,$subject,$sessionToken,'revoke',$deadline,$seen);$this->sameActor($actor,$final);return $result;
    }
    /** Explicit revoke-all also installs the current policy on a valid old-format-policy ledger, invalidating all tokens. */
    public function revokeAll(string $scope,string $subject,string $sessionToken):int
    {
        $root=CredentialState::root($this->site,$scope,$subject);$deadline=new Deadline($this->policy->ioMilliseconds());$seen=$this->now();$actor=$this->actor($scope,$subject,$sessionToken,'revoke_all',$deadline,$seen);$this->protect('revoke_all',$actor['session']->account(),['owner'=>$subject]);$after=$this->actor($scope,$subject,$sessionToken,'revoke_all',$deadline,$seen);$this->sameActor($actor,$after);$now=$this->tick($deadline,$seen);$epoch=bin2hex(random_bytes(16));
        $count=$this->store->transact(CredentialState::key($this->site,$root),function($state)use($scope,$subject,$root,$now,$after,$epoch){$state=CredentialState::read($state,$this->policy,$this->site,$scope,$root,$now,false);$count=$state===null?0:count(CredentialState::prune($state,$now)['entries']);return new Change(CredentialState::empty($scope,$subject,$after['identity']['fingerprint'],$this->policy,$now,$epoch),0,$count);});
        $final=$this->actor($scope,$subject,$sessionToken,'revoke_all',$deadline,$seen);$this->sameActor($actor,$final);return $count;
    }
    public function fromAuthorization(string $scope,$header,string $requiredScope):?VerifiedCredential
    {
        $token=is_string($header)&&strlen($header)<=520&&preg_match('/\ABearer ([A-Za-z0-9._-]+)\z/iD',$header,$match)?$match[1]:null;return $this->authenticate($scope,$token,$requiredScope);
    }
    public function authenticate(string $scope,$token,string $requiredScope):?VerifiedCredential
    {
        Guard::label($scope);if(!preg_match('//u',$scope)){throw new ConfigurationException('Credential scope must be UTF-8.','configuration.api_credentials');}CredentialEncoding::scopes([$requiredScope]);if(!in_array($requiredScope,$this->policy->allowedScopes(),true)){throw new ConfigurationException('Protected route requires a configured credential scope.','configuration.api_credential_scope');}
        $deadline=new Deadline($this->policy->ioMilliseconds());$seen=$this->now();$this->protect('authenticate',null,['required_scope'=>$requiredScope]);$parts=CredentialEncoding::parse($token);$this->tick($deadline,$seen);
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
    public function __debugInfo():array {return ['managed_credentials'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild API credential registries from trusted services.','configuration.api_credential_serialization');}
}
