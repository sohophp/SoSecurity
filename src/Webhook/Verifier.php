<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SystemClock;

/** Opt-in fixed-endpoint verification. No state writes, acknowledgment or business side effects. */
final class Verifier
{
    private $endpoint;
    private $keys;
    private $guard;
    private $clock;
    public function __construct(Endpoint $endpoint,callable $keyProvider,callable $requestGuard,?Clock $clock=null)
    {$this->endpoint=$endpoint;$this->keys=$keyProvider;$this->guard=$requestGuard;$this->clock=$clock ?? new SystemClock();}
    public function endpoint():Endpoint {return $this->endpoint;}
    /** @internal Pure identity check, never invokes a provider. */
    public function stateContext(Endpoint $endpoint,\Closure $provider,Clock $clock):bool
    {
        return $this->endpoint->fingerprint()===$endpoint->fingerprint()&&$this->keys===$provider&&($clock===$this->clock||($clock instanceof SystemClock&&$this->clock instanceof SystemClock));
    }
    private function now(Deadline $deadline,?int $seen=null):int
    {
        $deadline->check('webhook.timeout');try{$now=$this->clock->now();}catch(\Throwable $error){throw new StorageException('Webhook clock unavailable.','webhook.clock');}if($now<0||$now>PHP_INT_MAX-1024||($seen!==null&&$now<$seen)){throw new StorageException('Invalid webhook clock.','webhook.clock');}return $now;
    }
    private function keys():?KeySet
    {
        $endpoint=$this->endpoint;
        try{$keys=($this->keys)($endpoint);if($keys!==null&&(!$keys instanceof KeySet||!$keys->matches($this->endpoint))){throw new \RuntimeException('Mismatched webhook key snapshot.');}return $keys;}
        catch(\Throwable $error){throw new DependencyException('Webhook key authority unavailable.','webhook.keys_unavailable');}
    }
    private function current(array $wire,int $now):bool
    {
        $time=$wire['timestamp'];return $time===null||($time<=PHP_INT_MAX-$this->endpoint->tolerance()-1&&($time<=$now?$now-$time<=$this->endpoint->tolerance():$time-$now<=$this->endpoint->futureSkew()));
    }
    private function authorize(Request $request):void
    {
        $endpoint=$this->endpoint;
        try{$allowed=($this->guard)($endpoint,$request);}catch(\Throwable $error){throw new DependencyException('Webhook request protection unavailable.','webhook.request_unavailable');}
        if($allowed!==true){throw new SecurityException('Webhook request protection denied.','webhook.denied');}
    }
    public function verify(Request $request):?VerifiedWebhook
    {
        $deadline=new Deadline($this->endpoint->ioMilliseconds());$now=$this->now($deadline);
        $this->authorize($request);$now=$this->now($deadline,$now);
        if($request->method()!=='POST'||!hash_equals($this->endpoint->url(),$request->url())||strlen($request->body())>$this->endpoint->maximumBody()){return null;}
        $wire=Wire::parse($this->endpoint,$request);if($wire===null||!$this->current($wire,$now)){return null;}
        $keys=$this->keys();$now=$this->now($deadline,$now);if($keys===null||!$this->current($wire,$now)||$keys->verify($wire['message'],$wire['signatures'])===null){return null;}
        // Current provider state can change while signature work or a remote key lookup is in progress.
        $keys=$this->keys();$now=$this->now($deadline,$now);if($keys===null||!$this->current($wire,$now)){return null;}$keyId=$keys->verify($wire['message'],$wire['signatures']);$now=$this->now($deadline,$now);
        if($keyId===null||!$this->current($wire,$now)){return null;}
        $this->authorize($request);$now=$this->now($deadline,$now);
        if(!$this->current($wire,$now)){return null;}
        return new VerifiedWebhook($this->endpoint,$request,$wire['id'],$wire['timestamp'],$keyId,$now);
    }
    public function __debugInfo():array {return ['endpoint'=>$this->endpoint->id(),'services'=>'[redacted]'];}
    public function __sleep():array {throw new \SoSecurity\Exception\ConfigurationException('Rebuild webhook verifiers from trusted services.','configuration.webhook_serialization');}
}
