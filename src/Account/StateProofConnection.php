<?php
declare(strict_types=1);
namespace SoSecurity\Account;

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

/** Exact request-proof storage and explicit current browser/request authority. */
final class StateProofConnection
{
    private $dependencies;
    private $busy=false;

    /** Guard(action, authority scope, proof scope, browser binding): opaque caller string or null/false. */
    public function __construct(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,FileStore $store,string $site,string $scope,string $epoch,Clock $clock,callable $guard,int $milliseconds=1000)
    {
        new Deadline($milliseconds);
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($fileName,$files)||!$files->coversStore($store)||!$store->usesClock($clock)){self::invalid();}
        $binding=hash('sha256','SoSecurity.StateProofConnection.1.'.json_encode([$boundary->binding(),$source->fingerprint(),$files->fingerprint(),$fileName,$store->snapshotReference('proof-state-context'),$site,$scope,$epoch,$milliseconds]));
        $boundary->bindFileStore($store);
        $this->dependencies=static function()use($boundary,$source,$files,$fileName,$store,$site,$scope,$clock,$guard,$milliseconds,$binding):array{return compact('boundary','source','files','fileName','store','site','scope','clock','guard','milliseconds','binding');};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Declare the exact request-proof file graph and current authority.','configuration.state_proof');}
    public function validate(AtomicStore $store,Clock $clock):void{$d=($this->dependencies)();if($store!==$d['store']||$clock!==$d['clock']){self::invalid();}}
    public function validateFactory(string $site,Clock $clock,?StateBoundary $boundary):void
    {
        $d=($this->dependencies)();if($site!==$d['site']||$clock!==$d['clock']||($boundary!==null&&$boundary!==$d['boundary'])||$d['store']->snapshotFile('proof-state-context')!==hash('sha256',$site.':tokens'."\0".'proof-state-context').'.json'){self::invalid();}
    }
    public function store():FileStore{return ($this->dependencies)()['store'];}
    public function now():int
    {
        try{$now=($this->dependencies)()['clock']->now();}catch(\Throwable $error){throw new StorageException('Request-proof clock unavailable.','proof.clock');}
        if($now<=0||$now>PHP_INT_MAX-31536001){throw new StorageException('Invalid request-proof clock.','proof.clock');}return $now;
    }
    private function authority(string $action,string $scope,string $binding):?string
    {
        $d=($this->dependencies)();$authorityScope=$d['scope'];
        try{$actor=($d['guard'])($action,$authorityScope,$scope,$binding);if($actor===null||$actor===false){return null;}if(!is_string($actor)){throw new \RuntimeException('Invalid actor.');}Guard::label($actor);if(preg_match('//u',$actor)!==1){throw new \RuntimeException('Invalid actor encoding.');}return $actor;}
        catch(\Throwable $error){throw new DependencyException('Request-proof authority unavailable.','proof.authority_unavailable');}
    }
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('proof.timeout');$now=$this->now();if($now<$seen){throw new StorageException('Request-proof clock moved backwards.','proof.clock');}$seen=$now;return $now;
    }
    /** Callback is pure, just like AtomicStore::transact. Zero validUntil means no expiring successful proof. */
    public function transact(string $kind,string $action,string $scope,string $binding,callable $callback,int &$validUntil)
    {
        if(!in_array($kind,['csrf','captcha'],true)||!in_array($action,['issue','verify','revoke'],true)||($kind==='csrf'&&$scope==='password-reset')){self::invalid();}
        $key=Guard::key($kind,$scope,$binding);$d=($this->dependencies)();
        if($this->busy||$d['boundary']->active()){throw new ConfigurationException('Enter request-proof operations once before other protected effects.','configuration.state_request_nested');}
        $deadline=new Deadline($d['milliseconds']);$this->busy=true;$seen=0;$admitted=null;$result=null;$caller=null;$denied=false;$entry='proof.'.$kind.'.'.$action;
        try{
            $d['boundary']->run($entry,function()use($d,$entry,$scope,$binding,$key,$deadline,&$seen,&$admitted,&$result,&$validUntil):void{
                /** @var array|null $admitted Populated by the admission callback before effects. */
                if($admitted===null){self::invalid();}$a=$admitted;
                if($this->authority($entry,$scope,$binding)!==$a['actor']){throw new SecurityException('Request-proof authority changed.','proof.denied');}
                $now=$this->tick($deadline,$seen);if($validUntil!==0&&$validUntil<=$now){throw new SecurityException('Request proof expired.','proof.expired');}
                $result=$d['store']->transact($key,static function($old)use($a){if($old!==$a['old']){throw new StorageException('Request-proof state changed.','proof.changed');}return $a['change'];});
                if($this->authority($entry,$scope,$binding)!==$a['actor']){throw new SecurityException('Request-proof authority changed.','proof.denied');}
                $now=$this->tick($deadline,$seen);if($validUntil!==0&&$validUntil<=$now){throw new SecurityException('Request proof expired.','proof.expired');}
            },function(string $expected)use($d,$entry,$scope,$binding,$kind,$action,$key,$callback,$deadline,&$seen,&$admitted,&$result,&$denied,&$validUntil,&$caller){
                $this->tick($deadline,$seen);$actor=$this->authority($entry,$scope,$binding);$now=$this->tick($deadline,$seen);
                if($actor===null){$denied=true;return false;}
                $view=$d['source']->capture([$d['fileName']=>['entry'=>$d['store']->snapshotFile($key)]]);$part=$view->part($d['fileName']);
                if(!$view->matches($d['source'])||!hash_equals($expected,$view->digest())||!$part instanceof FileStateCapture||!$part->matches($d['files'])){throw new StorageException('Request-proof source changed.','account.witness_stale');}
                $raw=$part->file('entry');$old=$raw===null?null:Codec::decode($raw,$now);$change=$callback($old);
                if(!$change instanceof Change){self::invalid();} $encoded=Codec::encode($change);
                if($this->authority($entry,$scope,$binding)!==$actor){$denied=true;return false;}$caller=$actor;$now=$this->tick($deadline,$seen);
                if($validUntil!==0&&$validUntil<=$now){$denied=true;return false;}
                $result=$change->result();
                // Invalid CSRF is a read-only denial. CAPTCHA wrong answers may spend attempts.
                if(($kind==='csrf'&&$action==='verify'&&$result!==true)||($old===$change->value()&&($old!==null||$raw===null))){return false;}
                if($change->value()!==null&&!$d['files']->canStoreFile($d['store']->snapshotFile($key))){throw new SecurityException('Request-proof physical capacity reached.','proof.capacity');}
                $now=$this->tick($deadline,$seen);if($validUntil!==0&&$validUntil<=$now){$denied=true;return false;}
                $admitted=['actor'=>$actor,'old'=>$old,'change'=>$change];
                $request=hash('sha256','SoSecurity.RequestProof.1.'.json_encode([$entry,$scope,hash('sha256',$binding),$expected,hash('sha256',$encoded),$validUntil]));
                return StateOperation::proof($entry,$d['scope'],$actor,hash('sha256',$key),$request,$d['binding'],$now);
            },null,$deadline);
            if($denied){if($action==='verify'){return false;}throw new SecurityException('Request-proof admission denied.','proof.denied');}
            // Final witness I/O and host budget checks happen after the effect callback.
            if($caller===null||$this->authority($entry,$scope,$binding)!==$caller){if($action==='verify'){return false;}throw new SecurityException('Request-proof completion authority changed.','proof.denied');}
            $now=$this->tick($deadline,$seen);if($validUntil!==0&&$validUntil<=$now){if($action==='verify'){return false;}throw new SecurityException('Request proof expired before return.','proof.expired');}return $result;
        }finally{$this->busy=false;}
    }
    public function __debugInfo():array{return ['state_proofs'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
