<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Deadline;
use SoSecurity\Storage\StorageException;

/** Exact fixed disabling effects only, matched to a manifest durably recorded before the first SQL write. */
final class StateAccountResolution
{
    private $dependencies;
    private $fingerprint;
    public function __construct(LocalStateWitness $witness,StateAccountContainment $accounts,array $manifest)
    {
        if(!$accounts->boundTo($witness)||!$accounts->acceptsManifest($manifest)){self::invalid();}$manifest=json_decode(json_encode($manifest,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE),true,6);
        $this->fingerprint=hash('sha256','SoSecurity.Account.StateAccountResolution.1.'.$witness->binding().$witness->generation().json_encode($manifest,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $this->dependencies=static function()use($witness,$accounts,$manifest):array{return [$witness,$accounts,$manifest];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use the exact fixed account plan and persisted row-hash manifest.','configuration.account_resolution');}
    private function d():array{return ($this->dependencies)();}
    public function boundTo(LocalStateWitness $witness):bool{return $this->d()[0]===$witness&&$this->d()[1]->boundTo($witness);}
    public function usesPlan(StateAccountContainment $plan):bool{return $this->d()[1]===$plan;}
    public function binding():string{return $this->fingerprint;}
    public function manifest():array{return $this->d()[2];}
    public function count():int{return count($this->d()[2]['rows']);}
    public function observed():string{return $this->d()[1]->resolutionObserved($this);}
    public function apply(LocalStateWitness $witness,string $operation,Deadline $deadline):void
    {
        if(!$this->boundTo($witness)||!$witness->accountResolutionActive($this,$operation)){self::invalid();}$this->d()[1]->resolve($this,$witness,$operation,$deadline);
    }
    public function contained(LocalStateWitness $witness,string $operation):string
    {
        if(!$this->boundTo($witness)||!$witness->accountResolutionActive($this,$operation)){self::invalid();}$witness->accountResolutionCurrent($this,$operation);$digest=$this->d()[1]->contained($this->d()[2]['operation']);
        if($digest!==$this->observed()){throw new StorageException('Account resolution source changed after fixed effects.','account.account_resolution_changed');}return $digest;
    }
    public function __debugInfo():array{return ['state_account_resolution'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
