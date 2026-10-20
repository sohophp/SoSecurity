<?php
declare(strict_types=1);
// Isolated synthetic proof adapter. Real password/TOTP protocol acceptance is separate HTTP coverage.
final class OperationTestStore implements SoSecurity\Storage\AtomicStore
{
    public $states=[];
    public $expires=[];
    public $after;
    public $before;
    public $retry=true;
    public function transact(string $key,callable $callback)
    {
        if ($this->before!==null) { ($this->before)(); }
        $old=$this->states[$key] ?? null;$change=$callback($old);
        if ($this->retry) { $again=$callback($old);Check::same($change->value(),$again->value());Check::same($change->expiresAt(),$again->expiresAt());Check::same($change->result(),$again->result()); }
        $this->states[$key]=$change->value();$this->expires[$key]=$change->expiresAt();
        if ($this->after!==null) { $after=$this->after;$this->after=null;$after(); }
        return $change->result();
    }
}
final class OperationEnvironment
{
    public $clock;
    public $store;
    public $source;
    public $sessions;
    public $authorizer;
    public $current;
    public $credential;
    public $grants;
    public $guard=true;
    public $guards=0;
    public $offline=false;
    public function __construct(?SoSecurity\Operation\Policy $policy=null,?int $now=null)
    {
        $this->clock=new TestClock();if ($now!==null) {$this->clock->time=$now;}$this->store=new OperationTestStore();$this->current=new SoSecurity\Auth\Account('site','alice','1',true,['editor']);
        $this->source=new SoSecurity\Auth\CallbackIdentityProvider(function () { return null; },function (string $scope,string $subject) {
            if ($this->offline) { throw new RuntimeException('PRIVATE-OPERATION-AUTHORITY-FAILURE'); }
            return $scope==='site' && $subject==='alice' ? $this->current : null;
        });
        $this->sessions=new SoSecurity\Auth\SessionRegistry(new SoSecurity\Storage\MemoryStore($this->clock),$this->source,null,$this->clock,1000,3600,16);
        $this->authorizer=new SoSecurity\Authorization\Authorizer($this->source,new SoSecurity\Authorization\RolePolicy(['document.update'=>['type'=>'document','roles'=>['editor'],'fields'=>['title','body'],'owner_attribute'=>'owner']]));
        $this->credential=$this->newSession('password');
        $this->grants=new SoSecurity\Operation\Grants($this->store,$this->sessions,$this->authorizer,function (): bool { ++$this->guards;return $this->guard; },$policy,$this->clock);
    }
    public function newSession(string $method): SoSecurity\Auth\SessionCredential
    {
        $identity=(new SoSecurity\Auth\IdentityState($this->source,null))->load('site','alice');$epoch=$this->sessions->epoch('site','alice');
        $credential=$this->sessions->register('site','alice',$identity['fingerprint'],$epoch,$method);
        if ($credential===null) { throw new RuntimeException('Synthetic session registration failed.'); }return $credential;
    }
    public function reauthenticate(string $method='totp'): void
    {
        $identity=(new SoSecurity\Auth\IdentityState($this->source,null))->load('site','alice');$epoch=$this->sessions->epoch('site','alice');$reference=SoSecurity\Auth\SessionRegistry::reference($this->credential->token());
        $credential=$this->sessions->replace('site','alice',$identity['fingerprint'],$epoch,$method,$reference['id'],$reference['digest']);
        if ($credential===null) { throw new RuntimeException('Synthetic reauthentication failed.'); }$this->credential=$credential;
    }
    public function intent(array $parameters=['title'=>'PRIVATE-APPROVED-TITLE'],string $version='1'): SoSecurity\Operation\Intent
    {
        return new SoSecurity\Operation\Intent('document.update',new SoSecurity\Authorization\Resource('site','document','a',$version,['owner'=>'alice']),$parameters,['title']);
    }
    public function begin(?SoSecurity\Operation\Intent $intent=null): SoSecurity\Operation\Confirmation { return $this->grants->begin('site','alice',$this->credential->token(),$intent ?? $this->intent()); }
    public function confirm(SoSecurity\Operation\Confirmation $confirmation,?SoSecurity\Operation\Intent $intent=null): ?SoSecurity\Operation\Grant { return $this->grants->confirm('site','alice',$this->credential->token(),$intent ?? $this->intent(),$confirmation->token()); }
    public function consume(SoSecurity\Operation\Grant $grant,?SoSecurity\Operation\Intent $intent=null): ?SoSecurity\Operation\Permit { return $this->grants->consume('site','alice',$this->credential->token(),$intent ?? $this->intent(),$grant->token()); }
    public function approved(): SoSecurity\Operation\Grant { $pending=$this->begin();$this->reauthenticate();$grant=$this->confirm($pending);if ($grant===null) { throw new RuntimeException('Synthetic confirmation failed.'); }return $grant; }
}
