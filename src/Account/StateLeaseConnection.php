<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Concurrency\Lease;
use SoSecurity\Concurrency\LeasePolicy;
use SoSecurity\Concurrency\LeaseState;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;

/** Exact lease ledger and current host authority; business writes still enforce the returned fence. */
final class StateLeaseConnection
{
    private $dependencies;
    private $busy=false;
    /** Guard(action, authority scope, resource scope, resource, owner): current actor or null/false.
     * Holder actions require actor === owner. Provisioning, inspection and removal require explicit independent authority. */
    public function __construct(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,FileStore $store,string $site,string $scope,string $epoch,Clock $clock,callable $guard,int $milliseconds=1000)
    {
        new Deadline($milliseconds);
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($fileName,$files)||!$files->coversStore($store)||!$store->usesClock($clock)){self::invalid();}
        $binding=hash('sha256','SoSecurity.StateLeaseConnection.1.'.json_encode([$boundary->binding(),$source->fingerprint(),$files->fingerprint(),$fileName,$store->snapshotReference('lease-state-context'),$site,$scope,$epoch,$milliseconds]));
        $boundary->bindFileStore($store);
        $this->dependencies=static function()use($boundary,$source,$files,$fileName,$store,$site,$scope,$clock,$guard,$milliseconds,$binding):array{return compact('boundary','source','files','fileName','store','site','scope','clock','guard','milliseconds','binding');};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Declare the exact lease file graph and current resource authority.','configuration.state_lease');}
    public function validate(AtomicStore $store,Clock $clock):void{$d=($this->dependencies)();if($store!==$d['store']||$clock!==$d['clock']){self::invalid();}}
    public function validateFactory(string $site,Clock $clock,?StateBoundary $boundary):void
    {
        $d=($this->dependencies)();if($site!==$d['site']||$clock!==$d['clock']||($boundary!==null&&$boundary!==$d['boundary'])||$d['store']->snapshotFile('lease-state-context')!==hash('sha256',$site.':shared'."\0".'lease-state-context').'.json'){self::invalid();}
    }
    public function store():FileStore{return ($this->dependencies)()['store'];}
    private function authority(string $action,string $scope,string $resource,?string $owner):?string
    {
        $d=($this->dependencies)();$authorityScope=$d['scope'];$requestedOwner=$owner;
        try{$actor=($d['guard'])($action,$authorityScope,$scope,$resource,$owner);if($actor===null||$actor===false){return null;}if(!is_string($actor)){throw new \RuntimeException('Invalid actor.');}Guard::label($actor);if(preg_match('//u',$actor)!==1){throw new \RuntimeException('Invalid actor encoding.');}if($requestedOwner!==null&&$actor!==$requestedOwner){return null;}return $actor;}
        catch(\Throwable $error){throw new DependencyException('Lease authority unavailable.','lease.authority_unavailable');}
    }
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('lease.timeout');
        try{$now=($this->dependencies)()['clock']->now();}catch(\Throwable $error){throw new StorageException('Lease clock unavailable.','lease.clock');}
        if($now<=0||$now>PHP_INT_MAX-31536001||$now<$seen){throw new StorageException('Invalid lease clock.','lease.clock');}$seen=$now;return $now;
    }
    private function approved(?array $admitted):array
    {
        if($admitted===null){self::invalid();}return $admitted;
    }
    /** Internal native manager callbacks: pure ledger decision, then exact original completion checks. */
    public function transact(string $action,string $scope,string $resource,?string $owner,LeasePolicy $policy,callable $prepare,callable $finish)
    {
        if(!in_array($action,['initialize','acquire','renew','verify','release','inspect','remove'],true)||((in_array($action,['acquire','renew','verify','release'],true))!==($owner!==null))){self::invalid();}
        $key=LeaseState::context($scope,$resource,0,$owner);$d=($this->dependencies)();
        if($this->busy||$d['boundary']->active()){throw new ConfigurationException('Enter native leases once before other protected effects.','configuration.state_lease_nested');}
        $deadline=new Deadline($d['milliseconds']);$seen=0;$admitted=null;$result=null;$caller=null;$denied=false;$entry='leases.'.$action;$this->busy=true;
        try{
            $d['boundary']->run($entry,function()use($d,$entry,$scope,$resource,$owner,$key,$deadline,&$seen,&$admitted,&$result,$finish):void{
                $a=$this->approved($admitted);
                if($this->authority($entry,$scope,$resource,$owner)!==$a['actor']){throw new SecurityException('Lease authority changed.','lease.denied');}
                $now=$this->tick($deadline,$seen);if($a['until']!==0&&$a['until']<=$now){throw new SecurityException('Lease admission expired.','lease.expired');}
                $result=$d['store']->transact($key,static function($old)use($a):Change{if($old!==$a['old']){throw new StorageException('Lease ledger changed.','lease.changed');}return $a['change'];});
                $finish($result);
                if($this->authority($entry,$scope,$resource,$owner)!==$a['actor']){throw new SecurityException('Lease authority changed.','lease.denied');}
                $now=$this->tick($deadline,$seen);if($a['until']!==0&&$a['until']<=$now){throw new SecurityException('Lease expired before completion.','lease.expired');}
            },function(string $expected)use($d,$entry,$action,$scope,$resource,$owner,$key,$policy,$prepare,$deadline,&$seen,&$admitted,&$result,&$denied,&$caller){
                $this->tick($deadline,$seen);$actor=$this->authority($entry,$scope,$resource,$owner);$now=$this->tick($deadline,$seen);if($actor===null){$denied=true;return false;}
                $view=$d['source']->capture([$d['fileName']=>['entry'=>$d['store']->snapshotFile($key)]]);$part=$view->part($d['fileName']);
                if(!$view->matches($d['source'])||!hash_equals($expected,$view->digest())||!$part instanceof FileStateCapture||!$part->matches($d['files'])){throw new StorageException('Lease source changed.','account.witness_stale');}
                $raw=$part->file('entry');$old=$raw===null?null:Codec::decode($raw,$now);if($raw!==null){$envelope=json_decode($raw,true,32);if($envelope['expires']!==0){throw new StorageException('Lease ledgers must not expire.','storage.corrupt');}}
                $now=$this->tick($deadline,$seen);$change=$prepare($old,$now);if(!$change instanceof Change||$change->expiresAt()!==0){self::invalid();}$encoded=Codec::encode($change);$result=$change->result();$until=$result instanceof Lease?$result->expiresAt():0;
                if($this->authority($entry,$scope,$resource,$owner)!==$actor){$denied=true;return false;}$caller=$actor;$now=$this->tick($deadline,$seen);if($until!==0&&$until<=$now){throw new SecurityException('Lease admission expired.','lease.expired');}
                // Invalid credentials and normal contention do not consume a witness generation.
                if((in_array($action,['acquire','renew','verify','release'],true)&&($result===null||$result===false))||$old===$change->value()){return false;}
                if($change->value()!==null&&!$d['files']->canStoreFile($d['store']->snapshotFile($key))){throw new SecurityException('Lease physical capacity reached.','lease.capacity');}
                $now=$this->tick($deadline,$seen);if($until!==0&&$until<=$now){throw new SecurityException('Lease admission expired.','lease.expired');}
                $admitted=['actor'=>$actor,'old'=>$old,'change'=>$change,'until'=>$until];$configuration=hash('sha256',$d['binding'].'.'.$policy->fingerprint());
                $request=hash('sha256','SoSecurity.LeaseAdmission.1.'.json_encode([$entry,$scope,hash('sha256',$resource),$owner===null?null:hash('sha256',$owner),$expected,hash('sha256',$encoded),$until]));
                return StateOperation::lease($entry,$d['scope'],$actor,hash('sha256',$key),$request,$configuration,$now);
            },null,$deadline);
            if($denied){throw new SecurityException('Lease admission denied.','lease.denied');}
            // Completing the witness also performs I/O and host budget checks. Never return a credential based only on the earlier effect check.
            if($caller===null||$this->authority($entry,$scope,$resource,$owner)!==$caller){throw new SecurityException('Lease completion authority changed.','lease.denied');}
            $now=$this->tick($deadline,$seen);if($result instanceof Lease&&$result->expiresAt()<=$now){throw new StorageException('Lease expired before return.','lease.expired');}return $result;
        }finally{$this->busy=false;}
    }
    public function __debugInfo():array{return ['state_leases'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
