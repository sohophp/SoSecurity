<?php
declare(strict_types=1);
namespace SoSecurity\Mfa;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Support\HmacKeys;

/** Internal authenticated envelope. A permanent authenticated tombstone never becomes legacy-empty state. */
final class ManagedFactorStore implements AtomicStore
{
    private $store;
    private $context;
    private $keys;
    private $authority;
    public function __construct(AtomicStore $store,string $context,HmacKeys $keys,FactorAuthority $authority)
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$context)){throw new ConfigurationException('Use an exact managed factor context.','configuration.mfa');}
        $shared=$store;$depth=0;while($shared instanceof \SoSecurity\Storage\NamespacedStore){if(++$depth>8){throw new ConfigurationException('Managed factor storage nesting exceeds its bound.','configuration.mfa_store');}$shared=$shared->underlying();}
        if($shared instanceof \SoSecurity\Storage\MemoryStore||$shared instanceof \SoSecurity\Storage\SessionStore||$shared instanceof self){throw new ConfigurationException('Use shared persistent factor storage without nested managed envelopes.','configuration.mfa_store');}
        $this->store=$store;$this->context=$context;$this->keys=$keys;$this->authority=$authority;
    }
    public function usesKeys(HmacKeys $keys):bool{return $this->keys===$keys;}
    public function coveredBy(\SoSecurity\Account\LocalStateWitness $witness):bool{return $witness->coversStore($this->store);}
    public function snapshotReference(string $key,string $context):?array{return $context===$this->context&&$this->store instanceof \SoSecurity\Storage\FileStore?$this->store->snapshotReference($key):null;}
    /** @internal The fixed plan alone computes and authorizes the permanent null envelope. */
    public function containState(string $key,\SoSecurity\Account\StateFactorContainment $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    {
        if(!$plan->usesContext($this->context,$this->keys)||!$this->store instanceof \SoSecurity\Storage\FileStore){throw new ConfigurationException('Use the covered raw FileStore for containment.','configuration.factor_containment');}
        $this->store->containState($key,$plan,$witness,$operation);
    }
    public function resolveState(string $key,\SoSecurity\Account\StateFactorResolution $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    {
        if(!$plan->usesContext($this->context,$this->keys)||!$this->store instanceof \SoSecurity\Storage\FileStore){throw new ConfigurationException('Use the covered raw FileStore for resolution.','configuration.factor_resolution');}
        $this->store->resolveState($key,$plan,$witness,$operation);
    }
    public function installCredentialState(string $key,\SoSecurity\Account\StateCredentialInstallation $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    {
        if(!$plan->usesContext($this->context,$this->keys)||!$this->store instanceof \SoSecurity\Storage\FileStore){throw new ConfigurationException('Use exact managed credential installation storage.','configuration.credential_installation');}$this->store->installCredentialState($key,$plan,$witness,$operation);
    }
    private static function json(array $value):string{return ManagedFactorFrame::encode($value);}
    private function frame(string $key,$value):array{return ManagedFactorFrame::read($this->context,$this->keys,$key,$value);}
    private function envelope(string $key,?array $payload,?array $migration):array
    {
        $value=['v'=>$migration===null?2:3,'context'=>$this->context,'key'=>$this->keys->currentId(),'payload'=>$payload];if($migration!==null){$value['migration']=$migration;}
        $value['seal']=bin2hex($this->keys->sign('SoSecurity.Mfa.ManagedFactor.1.'.$key.':'.self::json($value)));return $value;
    }
    private static function info($info,$payload,string $key):array
    {
        if(!is_array($info)||array_keys($info)!==['factor_id','digest']||($info['factor_id']!==null&&(!is_string($info['factor_id'])||!preg_match('/\A[a-f0-9]{32}\z/D',$info['factor_id'])))||!is_string($info['digest'])||!preg_match('/\A[a-f0-9]{64}\z/D',$info['digest'])){throw new StorageException('Migration inspection must return bounded metadata only.','mfa.migration_corrupt');}
        if($payload!==null&&!is_array($payload)){throw new StorageException('Invalid raw migration payload.','mfa.migration_corrupt');}$actualId=$payload===null?null:($payload['enabled']['id']??null);$encoded=$payload===null?'null':self::json($payload);$digest=hash('sha256','SoSecurity.Mfa.LegacyMigration.1.'.$key.':'.$encoded);
        if($info['factor_id']!==$actualId||!hash_equals($digest,$info['digest'])){throw new StorageException('Migration callback cannot substitute source metadata.','mfa.migration_corrupt');}return $info;
    }
    public function migrationInspect(string $key,callable $inspect):array
    {
        if(!$this->authority->permits($key,'migrationInspect')&&!$this->authority->permits($key,'migrationInspectClosed')){throw new ConfigurationException('Use an active migration inspection.','configuration.mfa_authority');}
        return $this->store->transact($key,function($stored)use($key,$inspect):Change{
            $managed=is_array($stored)&&in_array($stored['v']??null,[2,3],true);$f=$managed?$this->frame($key,$stored):['payload'=>$stored,'migration'=>null];
            $argument=$f['payload'];$result=$inspect($argument);$info=self::info($result,$f['payload'],$key);return new Change($stored,0,$info+['managed'=>$managed,'migration'=>$f['migration']]);
        });
    }
    public function migrate(string $key,callable $inspect,bool $commit):array
    {
        $action=$commit?'completeManagedMigration':'adoptManagedExact';$meta=$this->authority->migration($key,$action);
        if($meta===null){throw new ConfigurationException('Use an active exact migration capability.','configuration.mfa_authority');}
        return $this->store->transact($key,function($stored)use($key,$inspect,$commit,$meta):Change{
            if($stored===null||(is_array($stored)&&($stored['v']??null)===1)){
                if($commit){throw new SecurityException('A prepared migration receipt is required.','mfa.migration_changed');}$f=['payload'=>$stored,'migration'=>null];
            }else{$f=$this->frame($key,$stored);if($f['migration']===null){throw new SecurityException('Do not implicitly adopt previously managed state.','mfa.migration_changed');}}
            $argument=$f['payload'];$result=$inspect($argument);$info=self::info($result,$f['payload'],$key);$receipt=$f['migration'];
            if($info['factor_id']!==$meta['factor_id']||($receipt===null||$receipt['state']==='prepared'||!$commit)&&!hash_equals($meta['state_digest'],$info['digest'])){throw new SecurityException('Exact legacy factor state changed.','mfa.migration_changed');}
            if($receipt!==null&&($receipt['operation']!==$meta['migration_id']||$receipt['digest']!==$meta['state_digest'])){throw new SecurityException('Migration receipt belongs to a different operation.','mfa.migration_changed');}
            if($receipt===null){$receipt=['operation'=>$meta['migration_id'],'digest'=>$meta['state_digest'],'state'=>'prepared'];}
            if($commit){$receipt['state']='committed';}
            return new Change($this->envelope($key,$f['payload'],$receipt),0,$info+['managed'=>true,'migration'=>$receipt]);
        });
    }
    private function run(string $key,callable $callback,bool $adopt)
    {
        if($this->authority->permits($key,'migrationInspectClosed')){throw new ConfigurationException('Closed migration inspection cannot mutate factors.','mfa.closed_read_only');}
        if(!$this->authority->permits($key,$adopt?'adoptManaged':null)){throw new ConfigurationException('Managed storage requires a matching active factor call.','configuration.mfa_authority');}
        return $this->store->transact($key,function($stored)use($key,$callback,$adopt):Change{
            $migration=null;
            if($adopt&&($stored===null||(is_array($stored)&&($stored['v']??null)===1))){$payload=$stored;if($payload!==null){self::json($payload);}}
            elseif($stored===null&&($this->authority->permits($key,'prepare')||$this->authority->permits($key,'revokeGeneration')||$this->authority->permits($key,'revoke')||$this->authority->permits($key,'revokeGenerationClosed'))){$payload=null;}
            else{$frame=$this->frame($key,$stored);$payload=$frame['payload'];$migration=$frame['migration'];if($migration!==null&&$migration['state']!=='committed'){throw new SecurityException('Migration preparation cannot authenticate or mutate factors.','mfa.migration_pending');}}
            $change=$callback($payload);if(!$change instanceof Change){throw new StorageException('Managed factor callback must return a change.','mfa.managed_corrupt');}
            $generation=$this->authority->retirement($key);
            if($generation!==null){
                $canDelete=true;if($payload!==null){foreach(['enabled','pending'] as $field){if(!array_key_exists($field,$payload)||($payload[$field]!==null&&(!is_array($payload[$field])||($payload[$field]['id']??null)!==$generation))){$canDelete=false;}}}
                if($canDelete?($change->value()!==null||$change->result()!==true):($change->value()!==$payload||$change->result()!==false)){throw new StorageException('Closed factor capability only permits exact deletion or an unchanged conflict.','mfa.closed_effect');}
            }
            return new Change($this->envelope($key,$change->value(),$migration),0,$change->result());
        });
    }
    public function transact(string $key,callable $callback) {return $this->run($key,$callback,false);}
    public function adopt(string $key,callable $callback) {return $this->run($key,$callback,true);}
    public function __debugInfo():array {return ['managed_factor_store'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload managed factor storage.','configuration.mfa_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload managed factor storage.','configuration.mfa_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Managed factor storage is immutable.','configuration.immutable');}
}
