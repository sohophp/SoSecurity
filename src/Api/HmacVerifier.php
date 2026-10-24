<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Operation\Intent;

final class HmacVerifier
{
    private $policy;
    private $keys;
    private $nonces;
    private $clock;
    private $boundary;private $state;private $sessions;private $nativePolicy;private $guard;private $busy=false;private $admitted;
    public function __construct(SignaturePolicy $policy,KeyProvider $keys,NonceStore $nonces,?Clock $clock=null,?\SoSecurity\Account\StateBoundary $boundary=null,?\SoSecurity\Account\StateAccountPolicy $state=null,?\SoSecurity\Auth\SessionRegistry $sessions=null,?\SoSecurity\Storage\AtomicStore $store=null,?\SoSecurity\Account\KeyRingStateSnapshot $keySource=null,string $keyName='',?callable $requestGuard=null,string $site='')
    {
        $clock=$clock??new SystemClock();if($state!==null&&($boundary===null||$sessions===null||$store===null||$keySource===null||!$keys instanceof KeyRing||!$keySource->uses($keys,$policy)||$requestGuard===null||$requestGuard instanceof \SoSecurity\Account\StateRequestGuard||!$nonces->stateContext($store,$clock)||!$state->signatureContext($store,$sessions,$clock,$boundary,$site,$keySource,$keyName))){throw new ConfigurationException('Use the exact native signature graph and covered immutable key source.','configuration.state_signature');}
        if($state===null&&($boundary!==null||$sessions!==null||$store!==null||$keySource!==null||$requestGuard!==null)){throw new ConfigurationException('Supply the native signature authority as one complete graph.','configuration.state_signature');}
        if($boundary!==null){$boundary->protect($store);}$this->policy=$policy;$this->keys=$keys;$this->nonces=$nonces;$this->clock=$clock;$this->boundary=$boundary;$this->state=$state;$this->sessions=$sessions;
        $this->nativePolicy=$state===null?null:hash('sha256','SoSecurity.Api.Hmac.Native.Policy.1.'.self::json([$state->binding(),$policy->options(),$keySource->fingerprint(),$keys->stateDigest(),$nonces->maximumTtl(),$site]));
        $this->guard=$requestGuard===null?null:static function(string $entry,Identity $identity,?Intent $intent,string $method,string $url)use($requestGuard):bool{return $requestGuard($entry,$identity,$intent,$method,$url)===true;};
    }
    public function verify(string $method,string $url,string $body,array $headers,?string $requiredScope=null): ?Identity
    {
        if($this->state!==null){throw new ConfigurationException('Use native signature For methods.','configuration.state_signature_entry');}$this->nonces->assertActive();$candidate=$this->candidate($method,$url,$body,$headers,$requiredScope);if($candidate===null){return null;}if(!$this->nonces->consume($candidate['signed']['keyid'],$candidate['signed']['nonce'],$candidate['expires'])){return null;}return $this->validTime($candidate['signed'],$this->clock->now())?$candidate['identity']:null;
    }
    private function candidate(string $method,string $url,string $body,array $headers,?string $requiredScope):?array
    {
        if ($requiredScope!==null) { Identity::validateScopes([$requiredScope]); }
        try { $target=$this->policy->target($method,$url,$body); $signed=SignatureProfile::parse($headers); }
        catch (ValidationException $e) { return null; }
        $now=$this->clock->now(); $skew=$this->policy->clockSkew();
        if ($now<0 || $now>PHP_INT_MAX-$skew || $signed['expires']>PHP_INT_MAX-$skew-1
            || $signed['created']>$now+$skew || $signed['expires']<$now-$skew || $signed['expires']<=$signed['created']
            || $signed['expires']-$signed['created']>$this->policy->maximumLifetime()
            || !hash_equals(SignatureProfile::digest($body),$signed['digest'])) { return null; }
        try { $key=$this->keys->find($signed['keyid']); }
        catch (\Throwable $e) { throw new SecurityException('Signing key lookup failed.','api.key_provider',$e); }
        if ($key===null) { return null; }
        if ($key->identity()->id()!==$signed['keyid']) { throw new SecurityException('Signing key provider returned another identity.','api.key_provider'); }
        if ($requiredScope!==null && !$key->identity()->allows($requiredScope)) { return null; }
        $base=SignatureProfile::base($method,$target,$signed['digest'],$signed['type'],$signed['parameters']);
        if (!hash_equals(Hmac::sign($base,$key->secret()),$signed['mac'])) { return null; }
        return ['identity'=>$key->identity(),'signed'=>$signed,'expires'=>$signed['expires']+$skew+1,'started'=>$now];
    }
    private function validTime(array $signed,int $now):bool
    {
        $skew=$this->policy->clockSkew();return $now>=0&&$now<=PHP_INT_MAX-$skew&&$now<=$signed['expires']+$skew&&$signed['created']<=$now+$skew;
    }
    private static function json(array $v):string{return json_encode($v,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    public function verifyFor(string $scope,string $method,string $url,string $body,array $headers,?string $requiredScope=null):?Identity{return $this->native('verify',$scope,$method,$url,$body,$headers,$requiredScope);}
    /** prepare(PDO, Identity): Intent is read-only; work(PDO, Identity, Intent) runs once in owned SQL. */
    public function withVerification(string $scope,\PDO $connection,array $tables,callable $prepare,string $method,string $url,string $body,array $headers,callable $work,?string $requiredScope=null)
    {
        if($this->state===null||!$this->state->credentialSqlContext($connection,$tables)){throw new ConfigurationException('Use the native signature PDO and complete declared business tables.','configuration.state_business');}return $this->native('execute',$scope,$method,$url,$body,$headers,$requiredScope,$connection,$tables,$prepare,$work);
    }
    private function live():void
    {
        try{$at=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Signature clock unavailable.','api.clock');}if($at<$this->admitted['seen']){throw new StorageException('Signature clock moved backwards during effects.','api.clock');}$this->admitted['seen']=$at;if(!$this->validTime($this->admitted['signed'],$at)){throw new SecurityException('Signature expired during effects.','api.expired');}
    }
    private function native(string $entry,string $scope,string $method,string $url,string $body,array $headers,?string $requiredScope,?\PDO $pdo=null,array $tables=[],?callable $prepare=null,?callable $work=null)
    {
        if($this->state===null){throw new ConfigurationException('Configure native signature authority explicitly.','configuration.state_signature');}if($this->busy||$this->boundary->active()){throw new ConfigurationException('Enter native signature requests once.','configuration.state_request_nested');}$this->boundary->assertScope($scope);if(!$this->state->recoveryRegistry($this->sessions,$scope)){throw new ConfigurationException('Use the exact native signature scope.','configuration.state_scope');}if($requiredScope!==null){Identity::validateScopes([$requiredScope]);}$names=array_keys($tables);sort($names);$deadline=new \SoSecurity\Support\Deadline(30000);$this->busy=true;
        try{$result=$this->boundary->run('hmac.'.$entry,function()use($entry,$pdo,$work,$deadline){$a=$this->admitted;$this->live();$s=$a['signed'];if(!$this->nonces->consume($s['keyid'],$s['nonce'],$a['expires'])){throw new StorageException('Admitted nonce changed during effects.','account.witness_changed');}$this->live();if($entry==='verify'){return $a['identity'];}$unit=new \SoSecurity\Support\SqlTransaction($pdo,$this->clock,30000);$live=function():void{$this->live();};return $unit->run(function()use($unit,$pdo,$a,$work){return $unit->invoke($work,[$pdo,$a['identity'],$a['intent']],'api.business_unavailable');},null,$live,$live,$deadline);
        },function(string $expected)use($entry,$scope,$method,$url,$body,$headers,$requiredScope,$pdo,$names,$prepare){
            $c=$this->candidate($method,$url,$body,$headers,$requiredScope);if($c===null){return false;}$key=NonceStore::stateKey($c['signed']['keyid'],$c['signed']['nonce']);$raw=$this->state->credentialBytes($key,$expected);if(!$this->nonces->stateAvailable($raw,$this->clock->now(),$c['expires'])){return false;}$intent=null;
            if($prepare!==null){$localPdo=$pdo;$localIdentity=$c['identity'];try{$intent=$prepare($localPdo,$localIdentity);}catch(SecurityException $error){throw $error;}catch(ConfigurationException $error){throw $error;}catch(\SoSecurity\Exception\ValidationException $error){throw $error;}catch(\Throwable $error){throw new DependencyException('Current signature business target unavailable.','api.business_unavailable');}if(!$intent instanceof Intent){throw new ConfigurationException('Load a validated server signature Intent.','configuration.state_business');}if($intent->resource()->scope()!==$scope){throw new SecurityException('Signature business scope denied.','authorization.denied');}}
            try{$allowed=($this->guard)($entry,$c['identity'],$intent,$method,$url);}catch(\Throwable $error){throw new DependencyException('Signature request guard unavailable.','api.request_unavailable');}if($allowed!==true){throw new SecurityException('Signature request denied.','api.request_denied');}
            if(!$this->state->credentialCapacity($key,$expected)){throw new SecurityException('Signature nonce physical capacity reached.','api.nonce_capacity');}$end=$this->clock->now();if($end<$c['started']){throw new StorageException('Signature admission clock moved backwards.','api.clock');}if(!$this->validTime($c['signed'],$end)){return false;}$this->admitted=$c+['intent'=>$intent,'seen'=>$end];$id=$c['identity'];$identity=hash('sha256',self::json([$id->id(),$id->subject(),$id->scopes()]));$target=$intent===null?$identity:$intent->fingerprint();$request=hash('sha256','SoSecurity.Api.Hmac.Native.Request.1.'.self::json(['entry'=>$entry,'method'=>$method,'url'=>hash('sha256',$url),'body'=>hash('sha256',$body),'signature'=>hash('sha256',SignatureProfile::base($method,$url,$c['signed']['digest'],$c['signed']['type'],$c['signed']['parameters']).$c['signed']['mac']),'required_scope'=>$requiredScope,'identity'=>$identity,'intent'=>$intent===null?null:$intent->fingerprint(),'tables'=>$names,'observed'=>$expected,'policy'=>$this->nativePolicy]));return \SoSecurity\Account\StateOperation::signature('hmac.'.$entry,$scope,$identity,$target,$request,$this->nativePolicy,$end);
        },null,$deadline);
            if($this->admitted!==null){
                $this->boundary->run('hmac.'.$entry.'_check',static function():void{throw new ConfigurationException('Signature completion is read only.','configuration.state_signature');},function()use($entry,$method,$url):bool{
                    $this->live();$admitted=$this->admitted;
                    try{$allowed=($this->guard)($entry,$admitted['identity'],$admitted['intent'],$method,$url);}catch(\Throwable $error){throw new DependencyException('Signature request guard unavailable.','api.request_unavailable');}
                    if($allowed!==true){throw new SecurityException('Signature request denied.','api.request_denied');}$this->live();return false;
                },null,$deadline);
                $deadline->check('account.operation_timeout');$this->live();
            }
            return $result;
        }finally{$this->admitted=null;$this->busy=false;}
    }
    public function __debugInfo():array{return ['hmac_verifier'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild signature verification from current private configuration.','configuration.signature_serialization');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize signature verification.','configuration.signature_serialization');}
}
