<?php
declare(strict_types=1);
namespace SoSecurity\Storage;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** @internal Legacy-compatible payload view; permanent retirement epochs are owned by the recovery boundary. */
final class ProofEpochStore implements AtomicStore
{
    private $store;private $context;
    public function __construct(AtomicStore $store,string $kind,string $scope)
    {
        $this->context=self::context($kind,$scope);$this->store=$store;
    }
    public static function context(string $kind,string $scope):string
    {
        if(!in_array($kind,['operations','links','password-reset'],true)||preg_match('//u',$scope)!==1){throw new ConfigurationException('Use an exact proof epoch purpose and scope.','configuration.proof_epoch');}Guard::label($scope);
        return hash('sha256','SoSecurity.Storage.ProofEpoch.Context.1.'.json_encode([$kind,$scope],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
    }
    public static function key(string $context):string
    {
        if(preg_match('/\A[a-f0-9]{64}\z/D',$context)!==1){throw new ConfigurationException('Use an exact proof epoch context.','configuration.proof_epoch');}return 'proof-epoch:'.$context;
    }
    public static function marker($value,string $context):?array
    {
        if($value===null){return null;}if(!is_array($value)||array_keys($value)!==['v','context','epoch']||$value['v']!==1||$value['context']!==$context||!is_string($value['epoch'])||preg_match('/\A[a-f0-9]{64}\z/D',$value['epoch'])!==1){throw new StorageException('Proof epoch marker is invalid.','proof_epoch.corrupt');}return $value;
    }
    public static function markerBytes(?string $raw,string $context):?array
    {
        if($raw===null){return null;}if(strlen($raw)>512){throw new StorageException('Proof epoch marker exceeds its bound.','proof_epoch.corrupt');}$outer=json_decode($raw,true,4);if(!is_array($outer)||array_keys($outer)!==['expires','value']||$outer['expires']!==0||!is_array($outer['value'])){throw new StorageException('Proof epoch must be permanent.','proof_epoch.corrupt');}return self::marker($outer['value'],$context);
    }
    public static function payload(?array $stored,?array $marker,string $context):?array
    {
        if($stored===null){return null;}
        if(array_key_exists('proof_epoch',$stored)){
            if(array_keys($stored)!==['proof_epoch','context','epoch','value']||$stored['proof_epoch']!==1||$stored['context']!==$context||!is_string($stored['epoch'])||preg_match('/\A[a-f0-9]{64}\z/D',$stored['epoch'])!==1||!is_array($stored['value'])){throw new StorageException('Proof epoch envelope is invalid.','proof_epoch.corrupt');}
            if($marker===null){throw new StorageException('A versioned proof requires its permanent marker.','proof_epoch.missing');}return hash_equals($marker['epoch'],$stored['epoch'])?$stored['value']:null;
        }
        return $marker===null?$stored:null;
    }
    private function current():?array
    {
        $context=$this->context;$view=$this->store->transact(self::key($context),static function($value)use($context):Change{$marker=self::marker($value,$context);return new Change($marker,0,['marker'=>$marker]);});return $view['marker'];
    }
    public function transact(string $key,callable $callback)
    {
        $context=$this->context;if($key===self::key($context)){throw new ConfigurationException('Proof payloads cannot overwrite their permanent marker.','configuration.proof_epoch');}$before=$this->current();
        $result=$this->store->transact($key,static function(?array $stored)use($before,$context,$callback):Change{
            $change=$callback(self::payload($stored,$before,$context));if(!$change instanceof Change){throw new StorageException('Proof storage requires a Change.','storage.callback');}$value=$change->value();
            if($before!==null&&$value!==null){$value=['proof_epoch'=>1,'context'=>$context,'epoch'=>$before['epoch'],'value'=>$value];}return new Change($value,$change->expiresAt(),$change->result());
        });
        try{$after=$this->current();}catch(\Throwable $error){throw new StorageException('Proof marker recheck failed after possible effects; do not replay automatically.','proof_epoch.completion_unknown',$error);}if($after!==$before){throw new StorageException('Proof epoch changed after possible effects; do not replay automatically.','proof_epoch.completion_unknown');}return $result;
    }
    public static function retirement(FileStore $store,string $kind,string $scope,string $epoch,string $policy):array
    {
        $context=self::context($kind,$scope);if(preg_match('/\A[a-f0-9]{64}\z/D',$epoch)!==1||preg_match('/\A[a-f0-9]{64}\z/D',$policy)!==1){throw new ConfigurationException('Use an exact proof retirement epoch and policy.','configuration.proof_epoch');}$key=self::key($context);$reference=$store->snapshotReference($key);
        return ['context'=>hash('sha256','SoSecurity.Storage.ProofEpoch.Retirement.1.'.json_encode([$context,$policy,$reference],JSON_UNESCAPED_SLASHES)),'key'=>$key,'reference'=>$reference,'after'=>Codec::encode(new Change(['v'=>1,'context'=>$context,'epoch'=>$epoch],0,true))];
    }
    public function __debugInfo():array{return ['proof_epoch_store'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild proof storage.','configuration.proof_epoch');}
    public function __wakeup():void{throw new ConfigurationException('Rebuild proof storage.','configuration.proof_epoch');}
}
