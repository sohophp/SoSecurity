<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;

/** Candidate: fixed complete sources, under the same outer authority lock. */
final class CompositeStateSnapshot implements StateStoreSource
{
    private $dependencies;
    private $fingerprint;
    private $milliseconds;
    private $busy=false;
    public function __construct(PDO $pdo,array $sources,int $milliseconds=10000)
    {
        new Deadline($milliseconds);if(count($sources)<1||count($sources)>32){self::configuration();}$bindings=[];$copy=[];
        foreach($sources as $name=>$source){if(!is_string($name)||!$source instanceof StateSnapshot){self::configuration();}Guard::label($name);if(preg_match('//u',$name)!==1||$source->connection()!==$pdo){self::configuration();}$fingerprint=$source->fingerprint();if(!preg_match('/\A[a-f0-9]{64}\z/D',$fingerprint)){self::configuration();}$bindings[$name]=$fingerprint;$copy[$name]=$source;}
        ksort($copy,SORT_STRING);ksort($bindings,SORT_STRING);$this->milliseconds=$milliseconds;$this->fingerprint=hash('sha256','SoSecurity.State.CompositeSnapshot.Profile.1.'.json_encode($bindings,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $this->dependencies=static function()use($pdo,$copy,$bindings):array{return [$pdo,$copy,$bindings];};
    }
    /** @return never */
    private static function configuration():void{throw new ConfigurationException('Use fixed named state sources on the exact same PDO.','configuration.state_snapshot');}
    public function storageDomains():array{$d=($this->dependencies)();$domains=[];foreach($d[1] as $source){if(!$source instanceof SqlStateSnapshot&&!$source instanceof FileStateSnapshot&&!$source instanceof KeyRingStateSnapshot&&!$source instanceof WebhookStateSnapshot&&!$source instanceof FenceStateSnapshot&&!$source instanceof QuarantineStateSnapshot){self::configuration();}foreach($source->storageDomains() as $v){$domains[]=$v;}}return $domains;}
    public function connection():PDO{return (($this->dependencies)())[0];}
    public function fingerprint():string{return $this->fingerprint;}
    public function contains(string $name,StateSnapshot $source):bool{$d=($this->dependencies)();return isset($d[1][$name])&&$d[1][$name]===$source&&$source->connection()===$d[0]&&$source->fingerprint()===$d[2][$name];}
    public function coversFence(LocalEpochFence $fence):bool
    {
        foreach((($this->dependencies)())[1] as $source){if($source instanceof FenceStateSnapshot&&$source->coversFence($fence)){return true;}}return false;
    }
    public function coversStore(\SoSecurity\Storage\AtomicStore $store):bool
    {
        $d=($this->dependencies)();foreach($d[1] as $name=>$source){if($source->connection()!==$d[0]||$source->fingerprint()!==$d[2][$name]){self::configuration();}if($source instanceof StateStoreSource&&$source->coversStore($store)){return true;}}return false;
    }
    private function observe(Deadline $deadline,array $requests=[]):array
    {
        $d=($this->dependencies)();$result=[];$captures=[];
        foreach($d[1] as $name=>$source){
            $deadline->check('account.snapshot_timeout');if($source->connection()!==$d[0]||$source->fingerprint()!==$d[2][$name]){self::configuration();}if(isset($requests[$name])){if(!$source instanceof SqlStateSnapshot&&!$source instanceof FileStateSnapshot){self::configuration();}$part=$source->capture($requests[$name]);$value=$part->digest();$captures[$name]=$part;}else{$value=$source->digest();}
            if($source->connection()!==$d[0]||$source->fingerprint()!==$d[2][$name]||!preg_match('/\A[a-f0-9]{64}\z/D',$value)){self::configuration();}$deadline->check('account.snapshot_timeout');$result[$name]=$value;
        }return [$result,$captures];
    }
    public function digest():string
    {
        if($this->busy){throw new StorageException('State snapshot is already active.','account.snapshot_busy');}$this->busy=true;
        try{$deadline=new Deadline($this->milliseconds);$first=$this->observe($deadline)[0];$second=$this->observe($deadline)[0];if($first!==$second){throw new StorageException('Protected sources changed during composite capture.','account.snapshot_changed');}return hash('sha256','SoSecurity.State.CompositeSnapshot.1.'.$this->fingerprint.json_encode($first,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));}
        finally{$this->busy=false;}
    }
    /** Concrete sources only: no plugin digest callbacks during the future read-only permission phase. */
    public function capture(array $selectors):CompositeStateCapture
    {
        if($this->busy){throw new StorageException('State snapshot is already active.','account.snapshot_busy');}
        if(count($selectors)<1||count($selectors)>4){self::configuration();}$d=($this->dependencies)();$copy=[];
        foreach($d[1] as $name=>$source){if(!$source instanceof SqlStateSnapshot&&!$source instanceof FileStateSnapshot&&!$source instanceof KeyRingStateSnapshot&&!$source instanceof WebhookStateSnapshot&&!$source instanceof FenceStateSnapshot&&!$source instanceof QuarantineStateSnapshot){self::configuration();}}
        // Normalize every child before opening any SQL snapshot or scratch directory.
        foreach($selectors as $name=>$request){if(!is_string($name)||!isset($d[1][$name])||!is_array($request)){self::configuration();}$source=$d[1][$name];if(!$source instanceof SqlStateSnapshot&&!$source instanceof FileStateSnapshot){self::configuration();}$copy[$name]=$source->selections($request);}
        $this->busy=true;
        try{
            $deadline=new Deadline($this->milliseconds);$first=$this->observe($deadline,$copy);$second=$this->observe($deadline,$copy);
            if($first[0]!==$second[0]||array_keys($first[1])!==array_keys($second[1])){self::changed();}
            foreach($first[1] as $name=>$capture){if(!$capture->same($second[1][$name])){self::changed();}}
            $digest=hash('sha256','SoSecurity.State.CompositeSnapshot.1.'.$this->fingerprint.json_encode($first[0],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
            return new CompositeStateCapture($this,$digest,$first[1]);
        }finally{$this->busy=false;}
    }
    /** @return never */
    private static function changed():void{throw new StorageException('Protected sources or selected values changed during composite capture.','account.snapshot_changed');}
    public function __debugInfo():array{return ['composite_state_snapshot'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload explicit state snapshot declarations.','configuration.state_snapshot');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize composite state sources.','configuration.state_snapshot');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State sources are immutable.','configuration.immutable');}
}
