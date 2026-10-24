<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Storage\ProofEpochStore;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;

/** Retire all old proofs of the explicitly selected native scopes/namespaces, not a guessed key inventory. */
final class StateProofRetirement
{
    private $dependencies;private $image;private $initial=false;private $execution;
    private function __construct(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,FileStore $store,Clock $clock,callable $persist,array $components)
    {
        if($w->format()!==3||!$w->coversSnapshot($source)||!$source->contains($fileName,$files)||!$files->coversStore($store)||count($components)<1||count($components)>4||array_keys($components)!==range(0,count($components)-1)){self::invalid();}
        $copy=[];foreach($components as $c){if(!is_array($c)||array_keys($c)!==['service','scope']||!is_string($c['scope'])){self::invalid();}$service=$c['service'];if($service instanceof \SoSecurity\Password\ResetTokens){if($c['scope']!==''){self::invalid();}}
            elseif(!$service instanceof \SoSecurity\Operation\Grants&&!$service instanceof \SoSecurity\Link\Links){self::invalid();}elseif(!$w->allowsScope($c['scope'])){self::invalid();}$copy[]=['service'=>$service,'scope'=>$c['scope']];}
        $this->dependencies=static function()use($w,$source,$files,$fileName,$store,$clock,$persist,$copy):array{return [$w,$source,$files,$fileName,$store,$clock,$persist,$copy];};$this->frames(str_repeat('0',64));
    }
    private function d():array{return ($this->dependencies)();}private function m():array{return ($this->image)();}
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use exact covered native proof services, scopes and fixed epoch effects.','configuration.proof_retirement');}
    /** @return never */
    private static function changed():void{throw new StorageException('Proof epoch differs from the sealed before/after image.','account.proof_changed');}
    private function frames(string $nonce):array
    {
        $d=$this->d();$rows=[];$seen=[];foreach($d[7] as $i=>$c){$s=$c['service'];$kind=$s instanceof \SoSecurity\Operation\Grants?'operations':($s instanceof \SoSecurity\Link\Links?'links':'password-reset');$probe=$s instanceof \SoSecurity\Password\ResetTokens?$s->stateRetirementEpoch($d[4],$d[5],str_repeat('0',64)):$s->stateRetirementEpoch($d[4],$d[5],$c['scope'],str_repeat('0',64));if($probe===null){self::invalid();}$epoch=hash('sha256','SoSecurity.Account.ProofEpoch.1.'.$d[0]->binding().$d[0]->generation().$nonce.$kind.json_encode($c['scope']).$probe['context']);
            $f=$s instanceof \SoSecurity\Password\ResetTokens?$s->stateRetirementEpoch($d[4],$d[5],$epoch):$s->stateRetirementEpoch($d[4],$d[5],$c['scope'],$epoch);if($f===null||!$d[2]->coversReference($f['reference'])||isset($seen[$f['reference']['file']])){self::invalid();}$seen[$f['reference']['file']]=true;$rows[]=['kind'=>$kind,'scope'=>$c['scope'],'component'=>$f['context'],'key'=>$f['key'],'reference'=>$f['reference'],'after'=>$f['after']];
        }return $rows;
    }
    private function capture(array $frames):array
    {
        $d=$this->d();$selectors=[];foreach($frames as $i=>$f){$selectors['proof_'.$i]=$f['reference']['file'];}$v=$d[1]->capture([$d[3]=>$selectors]);$part=$v->part($d[3]);if(!$part instanceof FileStateCapture||!$part->matches($d[2])){self::invalid();}$raw=[];foreach($frames as $i=>$f){$raw[]=$part->file('proof_'.$i);}return [$v->digest(),$raw];
    }
    private static function authority(array $state):string{unset($state['key'],$state['seal']);return hash('sha256',json_encode($state,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    public static function prepare(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,FileStore $store,Clock $clock,callable $persist,array $components,callable $budget):self
    {
        $self=new self($w,$source,$files,$fileName,$store,$clock,$persist,$components);$state=$w->inspect($budget);if($state['status']!=='quarantined'||(isset($state['remediation'])&&$state['remediation']['phase']!=='complete')){self::invalid();}$nonce=bin2hex(random_bytes(32));$frames=$self->frames($nonce);$v=$self->capture($frames);$entries=[];
        foreach($frames as $i=>$f){ProofEpochStore::markerBytes($v[1][$i],substr($f['key'],12));$entries[]=['kind'=>$f['kind'],'scope'=>$f['scope'],'component'=>$f['component'],'key'=>$f['key'],'reference'=>$f['reference'],'before'=>$v[1][$i]===null?null:hash('sha256',$v[1][$i]),'after'=>$f['after']];}
        $self->load(['format'=>1,'context'=>$w->binding(),'generation'=>$w->generation(),'source'=>$source->fingerprint(),'files'=>$files->fingerprint(),'file_name'=>$fileName,'nonce'=>$nonce,'authority'=>self::authority($state),'observed'=>$v[0],'entries'=>$entries]);$self->initial=true;return $self;
    }
    public static function resume(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,FileStore $store,Clock $clock,callable $persist,array $components,array $manifest):self{$self=new self($w,$source,$files,$fileName,$store,$clock,$persist,$components);$self->load($manifest);return $self;}
    private function load(array $m):void
    {
        if(!StateProofManifest::valid($m)){self::invalid();}$m=json_decode(json_encode($m,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),true,6);$d=$this->d();foreach(['context'=>$d[0]->binding(),'generation'=>$d[0]->generation(),'source'=>$d[1]->fingerprint(),'files'=>$d[2]->fingerprint(),'file_name'=>$d[3]] as $k=>$v){if($m[$k]!==$v){self::invalid();}}$frames=$this->frames($m['nonce']);if(count($frames)!==count($m['entries'])){self::invalid();}
        foreach($frames as $i=>$f){$entry=$m['entries'][$i];unset($entry['before']);if($entry!==$f){self::invalid();}}$this->image=static function()use($m):array{return $m;};
    }
    public function manifest():array{return $this->m();}public function binding():string{return hash('sha256','SoSecurity.Account.StateProofRetirement.1.'.StateProofManifest::fingerprint($this->m()));}public function count():int{return count($this->m()['entries']);}
    public function boundTo(LocalStateWitness $w):bool{return $this->d()[0]===$w&&$w->coversSnapshot($this->d()[1]);}
    private function view():array
    {
        $m=$this->m();$v=$this->capture($m['entries']);$names=[];foreach($m['entries'] as $i=>$e){$names[]=$e['reference']['file'];if($v[1][$i]!==$e['after']&&($v[1][$i]===null?null:hash('sha256',$v[1][$i]))!==$e['before']){self::changed();}}if(!$this->d()[2]->canStoreFiles($names)){throw new StorageException('Permanent proof epochs need physical capacity.','account.snapshot_capacity');}return $v;
    }
    public function initialFor(array $state):bool{return $this->initial&&self::authority($state)===$this->m()['authority']&&$this->observed()===$this->m()['observed'];}
    public function observed():string{return $this->view()[0];}
    public function guard(LocalStateWitness $w,string $operation):void{if(!$this->boundTo($w)||!$w->proofRetirementActive($this,$operation)){self::invalid();}if($this->execution!==null){($this->execution)()->check('account.witness_timeout');}$w->proofRetirementCurrent($this,$operation);}
    private function entry(FileStore $store,string $key):array{if($store!==$this->d()[4]){self::invalid();}foreach($this->m()['entries'] as $e){if($e['key']===$key&&$store->snapshotReference($key)===$e['reference']){return $e;}}self::invalid();}
    public function replacement(LocalStateWitness $w,string $operation,FileStore $store,string $key,?string $raw):string{$this->guard($w,$operation);$e=$this->entry($store,$key);if($raw!==$e['after']&&($raw===null?null:hash('sha256',$raw))!==$e['before']){self::changed();}return $e['after'];}
    public function persist(LocalStateWitness $w,string $operation,FileStore $store,string $key,$handle):void{$this->guard($w,$operation);$this->entry($store,$key);if(!is_resource($handle)||($this->d()[6])($handle)!==true){throw new StorageException('Proof epoch persistence is unknown.','account.proof_persistence');}$this->guard($w,$operation);}
    public function apply(LocalStateWitness $w,string $operation,Deadline $deadline):void{if(!$this->boundTo($w)||!$w->proofRetirementActive($this,$operation)){self::invalid();}$this->execution=static function()use($deadline):Deadline{return $deadline;};$this->guard($w,$operation);$v=$this->view();if(!$w->proofRetirementActive($this,$operation,$v[0])){self::changed();}foreach($this->m()['entries'] as $e){$this->d()[4]->retireProofState($e['key'],$this,$w,$operation);}$this->installed($w,$operation);}
    public function installed(LocalStateWitness $w,string $operation):string{$this->guard($w,$operation);$v=$this->view();foreach($this->m()['entries'] as $i=>$e){if($v[1][$i]!==$e['after']){self::changed();}}return $v[0];}
    public function __debugInfo():array{return ['state_proof_retirement'=>'[redacted]'];}public function __clone(){self::invalid();}public function __sleep():array{self::invalid();}public function __wakeup():void{self::invalid();}
}
