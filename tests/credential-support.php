<?php
declare(strict_types=1);
// Isolated synthetic identity provider. Actual password/HTTP/third-party claims require separate evidence.
final class CredentialTestStore implements SoSecurity\Storage\AtomicStore
{
    public $states=[];
    public $calls=0;
    public $inside=false;
    public $before;
    public $after;
    public $failure=false;
    public function transact(string $key,callable $callback)
    {
        if($this->failure){throw new SoSecurity\Storage\StorageException('PRIVATE-CREDENTIAL-STORE','test.offline');}
        ++$this->calls;if($this->before!==null){$hook=$this->before;$this->before=null;$hook($key,$this->calls);}
        $old=$this->states[$key] ?? null;$this->inside=true;try{$change=$callback($old);$again=$callback($old);}finally{$this->inside=false;}
        Check::same($change->value(),$again->value());Check::same($change->expiresAt(),$again->expiresAt());Check::same($change->result(),$again->result());Check::same(0,$change->expiresAt());SoSecurity\Storage\Codec::encode($change);
        if($change->value()===null){unset($this->states[$key]);}else{$this->states[$key]=$change->value();}
        if($this->after!==null){$hook=$this->after;$this->after=null;$hook($key,$this->calls);}return $change->result();
    }
}
final class CredentialEnvironment
{
    public $clock;
    public $store;
    public $accounts=[];
    public $provider;
    public $sessions;
    public $flow;
    public $login;
    public $otherLogin;
    public $keys;
    public $policy;
    public $registry;
    public $allowed=['documents:read','documents:write'];
    public $guard=true;
    public $guards=[];
    public $offline=false;
    public $scopesOffline=false;
    public $scopeCalls=0;
    public $findCalls=0;
    public $onScope;
    public $onFind;
    public $onGuard;
    public function __construct(?SoSecurity\Api\CredentialPolicy $policy=null)
    {
        $this->clock=new TestClock();$this->store=new CredentialTestStore();$this->accounts=['alice'=>new SoSecurity\Auth\Account('tenant','alice','1',true,['editor']),'bob'=>new SoSecurity\Auth\Account('tenant','bob','1',true,['editor'])];
        $this->provider=new SoSecurity\Auth\CallbackIdentityProvider(function(string $scope,string $id,string $password){$this->outside();return $scope==='tenant'&&$password==='test-password'?($this->accounts[$id] ?? null):null;},function(string $scope,string $subject){
            $this->outside();++$this->findCalls;if($this->onFind!==null){($this->onFind)($this->findCalls);}if($this->offline){throw new RuntimeException('PRIVATE-CREDENTIAL-PROVIDER');}return $scope==='tenant'?($this->accounts[$subject] ?? null):null;
        });
        $this->sessions=new SoSecurity\Auth\SessionRegistry(new SoSecurity\Storage\MemoryStore($this->clock),$this->provider,null,$this->clock,1000,3600);
        $this->flow=new SoSecurity\Auth\AuthenticationFlow(new SoSecurity\Storage\MemoryStore($this->clock),$this->provider,$this->sessions,static function(){return true;},null,$this->clock);
        $this->login=$this->flow->password('tenant','browser','alice','test-password');$this->otherLogin=$this->flow->password('tenant','browser-bob','bob','test-password');$this->keys=new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('k',32)]);
        $this->policy=$policy ?? new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['documents:read','documents:write']]);$this->registry=$this->service();
    }
    public function outside():void {Check::same(false,$this->store->inside);}
    public function service(?SoSecurity\Api\CredentialPolicy $policy=null,?SoSecurity\Support\HmacKeys $keys=null,string $site='credential-test'):SoSecurity\Api\CredentialRegistry
    {
        return new SoSecurity\Api\CredentialRegistry($this->store,$this->sessions,$this->provider,$keys ?? $this->keys,$site,function(string $operation,?SoSecurity\Auth\Account $actor,array $metadata){$this->outside();$this->guards[]=[$operation,$actor===null?null:$actor->subject(),$metadata];if($this->onGuard!==null){($this->onGuard)($operation);}return $this->guard;},function(SoSecurity\Auth\Account $actor){$this->outside();++$this->scopeCalls;if($this->onScope!==null){($this->onScope)($this->scopeCalls);}if($this->scopesOffline){throw new RuntimeException('PRIVATE-CREDENTIAL-SCOPES');}return $this->allowed;},$policy ?? $this->policy,$this->clock);
    }
    public function session():string {return $this->login->credential()->token();}
    public function issue(array $scopes=['documents:read'],?int $ttl=null,string $name='PRIVATE TOOL LABEL'):SoSecurity\Api\IssuedCredential {return $this->registry->issue('tenant','alice',$this->session(),$name,$scopes,$ttl);}
    public function auth($token,string $scope='documents:read'):?SoSecurity\Api\VerifiedCredential {return $this->registry->authenticate('tenant',$token,$scope);}
    public function rows():array {return $this->registry->all('tenant','alice',$this->session());}
    public function key():string {return SoSecurity\Api\CredentialState::key('credential-test',SoSecurity\Api\CredentialState::root('credential-test','tenant','alice'));}
}
function credentialCase(callable $test,?SoSecurity\Api\CredentialPolicy $policy=null):void {$test(new CredentialEnvironment($policy));}
