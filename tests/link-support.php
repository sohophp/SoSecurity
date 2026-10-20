<?php
declare(strict_types=1);
final class LinkTestStore implements SoSecurity\Storage\AtomicStore
{
    public $states=[];
    public $expires=[];
    public $after;
    public $before;
    public $calls=0;
    public function transact(string $key,callable $callback)
    {
        ++$this->calls;if($this->before!==null){($this->before)();}
        $old=$this->states[$key] ?? null;$change=$callback($old);$again=$callback($old);
        Check::same($change->value(),$again->value());Check::same($change->expiresAt(),$again->expiresAt());Check::same($change->result(),$again->result());
        SoSecurity\Storage\Codec::encode($change);$this->states[$key]=$change->value();$this->expires[$key]=$change->expiresAt();
        if($this->after!==null){$after=$this->after;$this->after=null;$after();}return $change->result();
    }
}
final class LinkEnvironment
{
    public $clock;
    public $store;
    public $keys;
    public $policy;
    public $links;
    public $guard=true;
    public $guards=[];
    public function __construct(?SoSecurity\Link\Policy $policy=null,?SoSecurity\Support\HmacKeys $keys=null,string $site='link-test')
    {
        $this->clock=new TestClock();$this->store=new LinkTestStore();$this->keys=$keys ?? new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('k',32)]);
        $this->policy=$policy ?? new SoSecurity\Link\Policy('https://files.example');$this->links=$this->service($site);
    }
    public function service(string $site='link-test'):SoSecurity\Link\Links
    {
        return new SoSecurity\Link\Links($this->store,$this->keys,$site,$this->policy,function(string $operation,SoSecurity\Link\Target $target,string $method){$this->guards[]=[$operation,$target->fingerprint(),$method];return $this->guard;},$this->clock);
    }
    public function target(string $version='1',array $parameters=['id'=>'a','name'=>'PRIVATE PARAMETER'],string $method='GET'):SoSecurity\Link\Target
    {
        return new SoSecurity\Link\Target('document.read',new SoSecurity\Authorization\Resource('tenant','document','a',$version,['owner'=>'alice']),'/documents/view',$parameters,$method);
    }
    public function key(?SoSecurity\Link\Target $target=null,string $site='link-test'):string {return SoSecurity\Link\State::key($site,$target ?? $this->target());}
}
