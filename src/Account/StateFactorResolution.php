<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Mfa\ManagedFactorFrame;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\HmacKeys;

/** Fresh approved convergence to exact previously persisted null envelopes. Never resolves arbitrary bytes. */
final class StateFactorResolution
{
    private $dependencies;
    private $execution;
    private $fingerprint;
    public function __construct(LocalStateWitness $witness,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys,array $manifest,callable $persist)
    {
        if(!StateFactorManifest::valid($manifest)){self::invalid();}$encoded=json_encode($manifest,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);$copy=is_string($encoded)?json_decode($encoded,true,12):null;if(!is_array($copy)||!StateFactorManifest::valid($copy)){self::invalid();}$manifest=$copy;
        $policy=$factors->statePolicy($site,$scope,$epoch,$keys);
        if(!StateFactorManifest::valid($manifest)||$policy===null||$witness->format()!==3||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($fileName,$files)||$manifest['source']!==$source->fingerprint()||$manifest['files']!==$files->fingerprint()||$manifest['name']!==$fileName||$manifest['factor']!==$policy['reference']||$manifest['context']!==$policy['context']||!$files->coversReference($manifest['factor'])){self::invalid();}
        foreach($manifest['entries'] as $entry){$outer=json_decode($entry['after'],true,12);$frame=ManagedFactorFrame::read($policy['context'],$keys,$entry['key'],$outer['value']);if($frame['payload']!==null){self::invalid();}}
        $this->fingerprint=hash('sha256','SoSecurity.Account.StateFactorResolution.1.'.$witness->binding().$witness->generation().StateFactorManifest::fingerprint($manifest));
        $this->dependencies=static function()use($witness,$source,$files,$fileName,$factors,$keys,$manifest,$persist):array{return [$witness,$source,$files,$fileName,$factors,$keys,$manifest,$persist];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use the exact sealed non-secret physical effect manifest and covered factor source.','configuration.factor_resolution');}
    private function d():array{return ($this->dependencies)();}
    public function binding():string{return $this->fingerprint;}
    public function manifest():array{return $this->d()[6];}
    public function count():int{return count($this->d()[6]['entries']);}
    public function boundTo(LocalStateWitness $witness):bool{return $this->d()[0]===$witness&&$witness->coversSnapshot($this->d()[1]);}
    public function usesFactors(TotpFactors $factors):bool{return $this->d()[4]===$factors;}
    public function usesContext(string $context,HmacKeys $keys):bool{return $this->d()[6]['context']===$context&&$this->d()[5]===$keys;}
    private function view():array
    {
        $d=$this->d();$selectors=[];foreach($d[6]['entries'] as $i=>$entry){$selectors['factor_'.$i]=$entry['file'];}
        $view=$d[1]->capture([$d[3]=>$selectors]);$part=$view->part($d[3]);if(!$view->matches($d[1])||!$part instanceof FileStateCapture||!$part->matches($d[2])){self::invalid();}
        $raws=[];foreach($d[6]['entries'] as $i=>$entry){$raw=$part->file('factor_'.$i);$old=$raw===null?null:hash('sha256',$raw);if($raw!==$entry['after']&&$old!==$entry['before']){throw new StorageException('A sealed factor target changed to unreviewed bytes.','account.factor_resolution_changed');}$raws[$entry['key']]=$raw;}
        return [$view->digest(),$raws];
    }
    public function observed():string{if($this->execution!==null){self::invalid();}return $this->view()[0];}
    public function guard(LocalStateWitness $witness,string $operation):void
    {
        if(!$this->boundTo($witness)||!$witness->factorResolutionActive($this,$operation)){self::invalid();}$this->deadline($operation);$witness->factorResolutionCurrent($this,$operation);$this->deadline($operation);
    }
    private function deadline(string $operation):void{if($this->execution!==null){$v=($this->execution)();if($v[0]!==$operation){self::invalid();}$v[2]->check('account.witness_timeout');}}
    private function entry(LocalStateWitness $witness,string $operation,FileStore $store,string $key):array
    {
        $this->guard($witness,$operation);if($this->execution===null){self::invalid();}$d=$this->d();foreach($d[6]['entries'] as $entry){if($entry['key']===$key){if($store->snapshotReference($key)!==['directory'=>$d[6]['factor']['directory'],'file'=>$entry['file']]){self::invalid();}return $entry;}}self::invalid();
    }
    public function replacement(LocalStateWitness $witness,string $operation,FileStore $store,string $key,?string $raw):string
    {
        $entry=$this->entry($witness,$operation,$store,$key);$v=($this->execution)();if(!array_key_exists($key,$v[1])||$raw!==$v[1][$key]){throw new StorageException('Resolution bytes changed before the fixed write.','account.factor_cas');}return $entry['after'];
    }
    public function persist(LocalStateWitness $witness,string $operation,FileStore $store,string $key,$handle):void
    {
        $this->entry($witness,$operation,$store,$key);if(!is_resource($handle)||($this->d()[7])($handle)!==true){throw new StorageException('Resolution persistence was not acknowledged.','account.factor_persistence');}$this->guard($witness,$operation);
    }
    public function apply(LocalStateWitness $witness,string $operation,Deadline $deadline):void
    {
        if($this->execution!==null){self::invalid();}$this->guard($witness,$operation);$view=$this->view();if(!$witness->factorResolutionActive($this,$operation,$view[0])){throw new StorageException('Resolution source changed before effects.','account.factor_resolution_changed');}$raws=$view[1];$this->execution=static function()use($operation,$raws,$deadline):array{return [$operation,$raws,$deadline];};
        foreach($this->d()[6]['entries'] as $entry){$deadline->check('account.witness_timeout');$this->d()[4]->resolveState($entry['key'],$this,$witness,$operation);}
    }
    public function contained(string $operation):string
    {
        $d=$this->d();$this->guard($d[0],$operation);if($this->execution===null){self::invalid();}$view=$this->view();foreach($d[6]['entries'] as $entry){if($view[1][$entry['key']]!==$entry['after']){throw new StorageException('The exact physical resolution is incomplete.','account.factor_resolution_changed');}}return $view[0];
    }
    public function __debugInfo():array{return ['factor_resolution'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
