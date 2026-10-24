<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;

/** Explicit legacy service-key scope and complete physical state; no inferred account identity. */
final class StateApiKeyConnection
{
    private $dependencies;
    private $busy=false;
    public function __construct(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,FileStore $store,string $site,string $scope,string $epoch,Clock $clock,callable $requestGuard,int $milliseconds=1000)
    {
        new Deadline($milliseconds);
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($fileName,$files)||!$files->coversStore($store)||!$store->usesClock($clock)){self::invalid();}
        $binding=hash('sha256','SoSecurity.StateApiKeyConnection.1.'.json_encode([$boundary->binding(),$source->fingerprint(),$files->fingerprint(),$fileName,$store->snapshotReference('api-key-state-context'),$site,$scope,$epoch,$milliseconds]));
        $boundary->bindFileStore($store);
        $this->dependencies=static function()use($boundary,$source,$files,$fileName,$store,$site,$scope,$clock,$requestGuard,$milliseconds,$binding):array{return [$boundary,$source,$files,$fileName,$store,$site,$scope,$clock,$requestGuard,$milliseconds,$binding];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Declare the exact complete legacy API key file graph and explicit scope.','configuration.state_api_keys');}
    public function validate(AtomicStore $store,Clock $clock):void{$d=($this->dependencies)();if($d[4]!==$store||$d[7]!==$clock){self::invalid();}}
    public function validateFactory(string $site,Clock $clock):void{$d=($this->dependencies)();if($site!==$d[5]||$clock!==$d[7]||$d[4]->snapshotFile('api-key-state-context')!==hash('sha256',$site.':shared'."\0".'api-key-state-context').'.json'){self::invalid();}}
    public function boundTo(StateBoundary $boundary):bool{return ($this->dependencies)()[0]===$boundary;}
    public function store():FileStore{return ($this->dependencies)()[4];}
    public function scope():string{return ($this->dependencies)()[6];}
    public function milliseconds():int{return ($this->dependencies)()[9];}
    public function binding():string{return ($this->dependencies)()[10];}
    /** Copied bytes are checked against the whole declared source, not just the selected file. */
    public function bytes(string $key,string $expected):?string
    {
        $d=($this->dependencies)();$view=$d[1]->capture([$d[3]=>['entry'=>$d[4]->snapshotFile($key)]]);
        if(!$view->matches($d[1])||!hash_equals($expected,$view->digest())){throw new StorageException('Legacy API key source changed during admission.','account.witness_stale');}$part=$view->part($d[3]);if(!$part instanceof FileStateCapture||!$part->matches($d[2])){self::invalid();}return $part->file('entry');
    }
    public function capacity(string $key,string $expected):bool
    {
        $d=($this->dependencies)();$available=$d[2]->canStoreFile($d[4]->snapshotFile($key));if(!hash_equals($expected,$d[1]->digest())){throw new StorageException('Legacy API key capacity source changed.','account.witness_stale');}return $available;
    }
    /** Return a current opaque caller identifier, or null/false to deny. No account is invented. */
    public function authority(string $action,string $subject,array $metadata):?string
    {
        $d=($this->dependencies)();$scope=$d[6];
        try{$actor=($d[8])($action,$scope,$subject,$metadata);if($actor===null||$actor===false){return null;}if(!is_string($actor)){throw new \RuntimeException('Invalid caller identifier.');}Guard::label($actor);if(preg_match('//u',$actor)!==1){throw new \RuntimeException('Invalid caller encoding.');}return $actor;}
        catch(\Throwable $error){throw new DependencyException('Legacy API key authority unavailable.','api.authority_unavailable');}
    }
    public function assertEntry():void
    {
        if($this->busy||($this->dependencies)()[0]->active()){throw new ConfigurationException('Enter native API key operations directly once.','configuration.state_request_nested');}
    }
    public function run(string $action,callable $admission,callable $effect)
    {
        if(!in_array($action,['issue','authenticate','rotate','revoke'],true)){self::invalid();}$d=($this->dependencies)();$this->assertEntry();$this->busy=true;
        try{return $d[0]->run('api.keys.'.$action,$effect,$admission);}finally{$this->busy=false;}
    }
    public function __debugInfo():array{return ['state_api_keys'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
