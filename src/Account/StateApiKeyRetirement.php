<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Api\ApiKeys;
use SoSecurity\Api\CredentialRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
/** Fixed namespace/subject-wide legacy key retirement. Never account activation or arbitrary work. */
final class StateApiKeyRetirement
{
    private $dependencies;private $image;private $initial=false;private $execution;
    private function __construct(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,$api,FileStore $store,Clock $clock,callable $persist,?string $scope=null,?int $stamp=null)
    {
        if(!$api instanceof ApiKeys&&!$api instanceof CredentialRegistry){self::invalid();}if($api instanceof CredentialRegistry&&($scope===null||$stamp===null||!$w->allowsScope($scope))){self::invalid();}
        $probe=$api instanceof ApiKeys?$api->stateEpoch($store,$clock,'state-api-context',str_repeat('0',64)):$api->stateRetirementEpoch($store,$clock,$scope,'state-api-context',str_repeat('0',32),$stamp);
        if($w->format()!==3||!$w->coversSnapshot($source)||!$source->contains($fileName,$files)||!$files->coversStore($store)||$probe===null){self::invalid();}
        $this->dependencies=static function()use($w,$source,$files,$fileName,$api,$store,$clock,$persist,$scope,$stamp):array{return [$w,$source,$files,$fileName,$api,$store,$clock,$persist,$scope,$stamp];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use exact covered legacy API services and fixed epoch effects.','configuration.api_key_retirement');}
    /** @return never */
    private static function changed():void{throw new StorageException('API key epoch bytes differ from the sealed before/after image.','account.api_key_changed');}
    private function d():array{return ($this->dependencies)();}private function m():array{return ($this->image)();}
    private function frame(string $subject,string $nonce):array{$d=$this->d();$epoch=hash('sha256','SoSecurity.Account.ApiKeyEpoch.1.'.$d[0]->binding().$d[0]->generation().$nonce.$subject);$v=$d[4] instanceof ApiKeys?$d[4]->stateEpoch($d[5],$d[6],$subject,$epoch):$d[4]->stateRetirementEpoch($d[5],$d[6],$d[8],$subject,substr($epoch,0,32),$d[9]);if($v===null||!$d[2]->coversReference($v['reference'])){self::invalid();}return $v;}
    private function capture(string $file):array{$d=$this->d();$view=$d[1]->capture([$d[3]=>['epoch'=>$file]]);$part=$view->part($d[3]);if(!$part instanceof FileStateCapture||!$part->matches($d[2])){self::invalid();}return [$view->digest(),$part->file('epoch')];}
    private static function authority(array $state):string{unset($state['key'],$state['seal']);return hash('sha256',json_encode($state,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    public static function prepare(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,ApiKeys $api,FileStore $store,Clock $clock,callable $persist,string $subject,callable $budget):self
    {
        return self::begin($w,$source,$files,$fileName,$api,$store,$clock,$persist,$subject,$budget,null,null);
    }
    public static function prepareCredentials(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,CredentialRegistry $api,FileStore $store,Clock $clock,callable $persist,string $scope,string $subject,callable $budget):self
    {
        return self::begin($w,$source,$files,$fileName,$api,$store,$clock,$persist,$subject,$budget,$scope,$clock->now());
    }
    private static function begin(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,$api,FileStore $store,Clock $clock,callable $persist,string $subject,callable $budget,?string $scope,?int $stamp):self
    {
        Guard::label($subject);$self=new self($w,$source,$files,$fileName,$api,$store,$clock,$persist,$scope,$stamp);$state=$w->inspect($budget);if($state['status']!=='quarantined'||(isset($state['remediation'])&&$state['remediation']['phase']!=='complete')){self::invalid();}$nonce=bin2hex(random_bytes(32));$f=$self->frame($subject,$nonce);$v=$self->capture($f['reference']['file']);$m=['format'=>$api instanceof ApiKeys?1:2,'context'=>$w->binding(),'generation'=>$w->generation(),'source'=>$source->fingerprint(),'files'=>$files->fingerprint(),'file_name'=>$fileName,'api'=>$f['context'],'subject'=>$subject,'nonce'=>$nonce,'authority'=>self::authority($state),'observed'=>$v[0],'key'=>$f['key'],'reference'=>$f['reference'],'before'=>$v[1]===null?null:hash('sha256',$v[1]),'after'=>$f['after']];if($api instanceof CredentialRegistry){$m['kind']='account_credentials';$m['scope']=$scope;$m['stamp']=$stamp;}$self->load($m);$self->initial=true;return $self;
    }
    public static function resume(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,ApiKeys $api,FileStore $store,Clock $clock,callable $persist,array $manifest):self{$self=new self($w,$source,$files,$fileName,$api,$store,$clock,$persist);$self->load($manifest);return $self;}
    public static function resumeCredentials(LocalStateWitness $w,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,CredentialRegistry $api,FileStore $store,Clock $clock,callable $persist,array $manifest):self
    {
        if(!StateApiKeyManifest::valid($manifest)||$manifest['format']!==2){self::invalid();}$self=new self($w,$source,$files,$fileName,$api,$store,$clock,$persist,$manifest['scope'],$manifest['stamp']);$self->load($manifest);return $self;
    }
    private function load(array $m):void
    {
        if(!StateApiKeyManifest::valid($m)){self::invalid();}$m=json_decode(json_encode($m,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),true,5);$d=$this->d();if(($m['format']===2)!==($d[4] instanceof CredentialRegistry)||($m['format']===2&&($m['scope']!==$d[8]||$m['stamp']!==$d[9]))){self::invalid();}$f=$this->frame($m['subject'],$m['nonce']);foreach(['context'=>$d[0]->binding(),'generation'=>$d[0]->generation(),'source'=>$d[1]->fingerprint(),'files'=>$d[2]->fingerprint(),'file_name'=>$d[3],'api'=>$f['context'],'key'=>$f['key'],'reference'=>$f['reference'],'after'=>$f['after']] as $k=>$v){if($m[$k]!==$v){self::invalid();}}$this->image=static function()use($m):array{return $m;};
    }
    public function manifest():array{return $this->m();}public function binding():string{return hash('sha256','SoSecurity.Account.StateApiKeyRetirement.1.'.StateApiKeyManifest::fingerprint($this->m()));}public function count():int{return 1;}
    public function boundTo(LocalStateWitness $w):bool{return $this->d()[0]===$w&&$w->coversSnapshot($this->d()[1]);}
    public function initialFor(array $state):bool{return $this->initial&&self::authority($state)===$this->m()['authority']&&$this->observed()===$this->m()['observed'];}
    private function view():array{$m=$this->m();$v=$this->capture($m['reference']['file']);if($v[1]===null&&!$this->d()[2]->canStoreFile($m['reference']['file'])){throw new StorageException('Permanent API epoch needs an available physical slot.','account.snapshot_capacity');}if($v[1]!==$m['after']&&($v[1]===null?null:hash('sha256',$v[1]))!==$m['before']){self::changed();}return $v;}
    public function observed():string{return $this->view()[0];}
    public function guard(LocalStateWitness $w,string $operation):void{if(!$this->boundTo($w)||!$w->apiKeyRetirementActive($this,$operation)){self::invalid();}if($this->execution!==null){($this->execution)()->check('account.witness_timeout');}$w->apiKeyRetirementCurrent($this,$operation);}
    public function replacement(LocalStateWitness $w,string $operation,FileStore $store,string $key,?string $raw):string{$this->guard($w,$operation);$m=$this->m();if($store!==$this->d()[5]||$key!==$m['key']||$store->snapshotReference($key)!==$m['reference']||($raw!==$m['after']&&($raw===null?null:hash('sha256',$raw))!==$m['before'])){self::changed();}return $m['after'];}
    public function persist(LocalStateWitness $w,string $operation,FileStore $store,string $key,$handle):void{$this->guard($w,$operation);if($store!==$this->d()[5]||$key!==$this->m()['key']||!is_resource($handle)||($this->d()[7])($handle)!==true){throw new StorageException('API key epoch persistence is unknown.','account.api_key_persistence');}$this->guard($w,$operation);}
    public function apply(LocalStateWitness $w,string $operation,Deadline $deadline):void{if(!$this->boundTo($w)||!$w->apiKeyRetirementActive($this,$operation)){self::invalid();}$this->execution=static function()use($deadline):Deadline{return $deadline;};$this->guard($w,$operation);$v=$this->view();if(!$w->apiKeyRetirementActive($this,$operation,$v[0])){self::changed();}$this->d()[5]->retireApiKeyState($this->m()['key'],$this,$w,$operation);$this->installed($w,$operation);}
    public function installed(LocalStateWitness $w,string $operation):string{$this->guard($w,$operation);$v=$this->view();if($v[1]!==$this->m()['after']){self::changed();}return $v[0];}
    public function __debugInfo():array{return ['state_api_key_retirement'=>'[redacted]'];}public function __clone(){self::invalid();}public function __sleep():array{self::invalid();}public function __wakeup():void{self::invalid();}
}
