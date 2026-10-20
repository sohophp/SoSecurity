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
    /** Guard(operation, Target, requestMethod): strict true; host owns issuer authorization and request policy. */
    public function __construct(AtomicStore $store,HmacKeys $keys,string $site,Policy $policy,callable $requestGuard,?Clock $clock=null)
    {
        Guard::label($site);if(strlen($site)>128||!preg_match('//u',$site)){throw new ConfigurationException('Invalid signed-link site.','configuration.link');}
        $this->store=$store;$this->keys=$keys;$this->site=$site;$this->policy=$policy;$this->guard=$requestGuard;$this->clock=$clock ?? new SystemClock();
    }
    public function policy():Policy {return $this->policy;}
    public function issue(Target $target,bool $oneTime=false,?int $ttl=null,string $binding=''):IssuedLink
    {
        $this->guard('issue',$target,'POST');$binding=Encoding::binding($binding);$ttl=$ttl ?? $this->policy->ttl();
        if($ttl<1||$ttl>$this->policy->maximumTtl()){throw new ConfigurationException('Invalid signed-link lifetime.','configuration.link');}
        $now=$this->now();$parts=['key_id'=>$this->keys->currentId(),'id'=>bin2hex(random_bytes(16)),'issued'=>$now,'expires'=>$now+$ttl,'mode'=>$oneTime?'o':'r'];
        $token='sl1.'.$parts['key_id'].'.'.$parts['id'].'.'.$now.'.'.$parts['expires'].'.'.$parts['mode'].'.'.Encoding::base64($this->keys->sign(Encoding::message($this->site,$this->policy,$target,$parts,$binding)));
        $url=Encoding::prefix($this->policy,$target).$token;
        if(strlen($url)>2048){throw new ConfigurationException('Signed URL exceeds 2 KiB.','configuration.link_target');}
        $entry=['digest'=>hash('sha256',$token),'target'=>$target->fingerprint(),'issued'=>$now,'expires'=>$parts['expires'],'one_time'=>$oneTime,'key_id'=>$parts['key_id']];$key=State::key($this->site,$target);
        $this->store->transact($key,function($state)use($now,$parts,$entry){
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);
            if(count($state['entries'])>=$this->policy->capacity()||isset($state['entries'][$parts['id']])){throw new SecurityException('Signed-link capacity reached.','link.capacity');}
            $state['entries'][$parts['id']]=$entry;return State::change($state,null);
        });
        $this->finish($key,$parts['id'],$entry['digest'],$now,$parts['expires']);
        return new IssuedLink($url,$parts['id'],$target,$now,$parts['expires'],$oneTime);
    }
    /** Supply current server-loaded target and actual method; HEAD never consumes a GET link. */
    public function verify(Target $target,string $url,string $method='GET',string $binding=''):?VerifiedLink
    {
        $this->guard('verify',$target,$method);$binding=Encoding::binding($binding);
        if($method!==$target->method()){return null;}$parts=Encoding::parse($url,$this->policy,$target);if($parts===null){return null;}
        if(!$this->keys->verify($parts['key_id'],Encoding::message($this->site,$this->policy,$target,$parts,$binding),$parts['mac'])){return null;}
        $now=$this->now();$key=State::key($this->site,$target);
        $entry=$this->store->transact($key,function($state)use($now,$parts,$target){
            $state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$entry=$state['entries'][$parts['id']] ?? null;
            if($entry===null||!hash_equals($entry['digest'],$parts['digest'])||!hash_equals($entry['target'],$target->fingerprint())||$entry['issued']>$now){return State::change($state,null);}
            if($entry['issued']!==$parts['issued']||$entry['expires']!==$parts['expires']||$entry['key_id']!==$parts['key_id']||$entry['one_time']!==($parts['mode']==='o')){throw new StorageException('Signed-link record differs from authenticated envelope.','storage.corrupt');}
            if($entry['one_time']){unset($state['entries'][$parts['id']]);}return State::change($state,$entry);
        });
        if($entry===null){$this->finished($now);return null;}
        $this->finish($key,$parts['id'],$parts['digest'],$now,$entry['expires']);
        return new VerifiedLink($parts['id'],$target,$entry['issued'],$entry['expires'],$entry['one_time']);
    }
    /** Per-purpose/resource management, including earlier versions/paths/bindings of that resource. */
    public function revoke(Target $target,string $id):bool
    {
        $this->guard('revoke',$target,'POST');if(!State::hex($id,32)){return false;}$now=$this->now();
        $result=$this->store->transact(State::key($this->site,$target),function($state)use($now,$id){$state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);$exists=isset($state['entries'][$id]);unset($state['entries'][$id]);return State::change($state,$exists);});$this->finished($now);return $result;
    }
    public function revokeAll(Target $target):void
    {
        $this->guard('revoke_all',$target,'POST');$now=$this->now();
        $this->store->transact(State::key($this->site,$target),function($state)use($now){State::read($state,$this->policy,$now);return new Change(null,0,null);});$this->finished($now);
    }
    /** Bounded metadata snapshot at read time; no URL/parameters/binding and no verification authority. */
    public function all(Target $target):array
    {
        $this->guard('all',$target,'GET');$now=$this->now();
        $entries=$this->store->transact(State::key($this->site,$target),function($state)use($now){$state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);return State::change($state,$state['entries']);});$this->finished($now);
        $result=[];foreach($entries as $id=>$entry){$result[]=['id'=>$id,'issued_at'=>$entry['issued'],'expires_at'=>$entry['expires'],'one_time'=>$entry['one_time'],'key_id'=>$entry['key_id'],'target_fingerprint'=>$entry['target']];}return $result;
    }
    private function guard(string $operation,Target $target,string $method):void
    {
        try{$allowed=($this->guard)($operation,$target,$method);}catch(\Throwable $error){throw new DependencyException('Signed-link request protection unavailable.','link.request_unavailable');}
        if($allowed!==true){throw new SecurityException('Signed-link request protection failed.','link.request_denied');}
    }
    private function finish(string $key,string $id,string $digest,int $started,int $expires):void
    {
        try{$this->finished($started,$expires);}catch(\Throwable $error){
            $now=$this->clock->now();if($now<0||$now>PHP_INT_MAX-86400){$now=$started;}$now=max($started,$now);
            $this->store->transact($key,function($state)use($id,$digest,$now){$state=State::prepare(State::read($state,$this->policy,$now),$this->policy,$now);if(isset($state['entries'][$id])&&hash_equals($state['entries'][$id]['digest'],$digest)){unset($state['entries'][$id]);}return State::change($state,null);});throw $error;
        }
    }
    private function finished(int $started,?int $expires=null):void
    {
        $now=$this->now();if($now<$started){throw new StorageException('Signed-link clock moved backwards during I/O.','link.clock');}
        if($expires!==null&&$expires<=$now){throw new SecurityException('Signed link expired during I/O.','link.expired');}
    }
    private function now():int {$now=$this->clock->now();if($now<0||$now>PHP_INT_MAX-86400){throw new StorageException('Invalid signed-link clock.','link.clock');}return $now;}
    public function __debugInfo():array {return ['signed_links'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild signed-link services from trusted configuration.','configuration.link_serialization');}
}
