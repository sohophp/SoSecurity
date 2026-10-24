<?php
declare(strict_types=1);
namespace SoSecurity\Mfa;
use SoSecurity\Account\LocalEpochFence;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;

/** Internal managed-call authority. Callbacks run outside retryable storage callbacks. */
final class FactorAuthority
{
    private $fence;
    private $guard;
    private $registered;
    private $clock;
    private $milliseconds;
    private $active;
    private $busy=false;
    public function __construct(LocalEpochFence $fence,callable $guard,Clock $clock,int $milliseconds)
    {
        if($guard instanceof \SoSecurity\Account\FactorWorkerAuthority&&!$guard->boundTo($fence)){throw new ConfigurationException('Use the same registered worker authority.','configuration.mfa_workers');}
        $this->registered=$guard instanceof \SoSecurity\Account\FactorWorkerAuthority?$guard:null;
        new Deadline($milliseconds);$this->fence=$fence;$this->guard=static function(...$args)use($guard){return $guard(...$args);};$this->clock=$clock;$this->milliseconds=$milliseconds;
    }
    public function registeredWith(\PDO $connection):bool {return $this->registered!==null&&$this->registered->matchesConnection($connection);}
    public function enlistWorkers(\PDO $connection,?\SoSecurity\Support\SqlTransaction $owner=null):void {if($this->registered!==null){$this->registered->assertCurrent($connection,$owner);}}
    public function boundTo(LocalEpochFence $fence):bool {return $this->fence->binding()===$fence->binding();}
    public function permits(string $key,?string $action=null):bool {return $this->active!==null&&$this->active[0]===$key&&($action===null||$this->active[1]===$action);}
    private function check(string $action,string $phase,string $scope,string $subject,array $metadata):void
    {
        $local=[$action,$phase,$scope,$subject,$metadata];$references=[];foreach($local as &$arg){$references[]=&$arg;}unset($arg);
        try{$ok=call_user_func_array($this->guard,$references);}catch(\Throwable $error){throw new DependencyException('Current managed factor authority unavailable.','mfa.authority');}
        if($ok!==true){throw new SecurityException('Current managed factor authority required.','mfa.authority_denied');}
    }
    private function now():int
    {
        try{$now=$this->clock->now();}catch(\Throwable $error){throw new DependencyException('Managed factor clock unavailable.','mfa.clock');}if($now<0||$now>PHP_INT_MAX-86400){throw new SecurityException('Managed factor clock is invalid.','mfa.clock');}return $now;
    }
    private static function metadata(string $action,array $metadata):void
    {
        if(!in_array($action,['begin','confirm','verify','verifyRecovery','verifyBound','regenerateRecoveryCodes','regenerateRecoveryCodesBound','disableBound','disable','prepare','revokeGeneration','revoke','status','reencrypt','reencryptBound','adoptManaged','revokeGenerationClosed','migrationInspect','migrationInspectClosed','adoptManagedExact','completeManagedMigration'],true)){throw new ValidationException('Use an explicit managed factor purpose.','mfa.input');}
        $fields=[];if(in_array($action,['confirm','verifyBound','regenerateRecoveryCodesBound','disableBound','prepare','revokeGeneration','reencryptBound','adoptManaged','revokeGenerationClosed'],true)){$fields[]='factor_id';}
        if(in_array($action,['verifyBound','disable','disableBound'],true)){$fields[]='recovery';}
        if(in_array($action,['adoptManagedExact','completeManagedMigration'],true)){$fields=['factor_id','state_digest','migration_id'];foreach(['state_digest','migration_id'] as $field){if(!isset($metadata[$field])||!is_string($metadata[$field])||!preg_match('/\A[a-f0-9]{64}\z/D',$metadata[$field])){throw new ValidationException('Use exact bounded migration identifiers.','mfa.input');}}}
        $keys=array_keys($metadata);sort($keys);sort($fields);if($keys!==$fields){throw new ValidationException('Use exact bounded managed factor metadata.','mfa.input');}
        if(array_key_exists('factor_id',$metadata)&&(($metadata['factor_id']===null&&!in_array($action,['adoptManaged','adoptManagedExact','completeManagedMigration'],true))||($metadata['factor_id']!==null&&(!is_string($metadata['factor_id'])||!preg_match('/\A[a-f0-9]{32}\z/D',$metadata['factor_id']))))){throw new ValidationException('Bind a canonical managed factor generation.','mfa.input');}
        if(array_key_exists('recovery',$metadata)&&!is_bool($metadata['recovery'])){throw new ValidationException('Use a bounded managed proof kind.','mfa.input');}
    }
    public function work(string $action,string $scope,string $subject,array $metadata,callable $operation)
    {
        if(in_array($action,['revokeGenerationClosed','migrationInspectClosed'],true)){throw new ConfigurationException('Use the explicit closed retirement entry.','configuration.mfa_closed');}return $this->run($action,$scope,$subject,$metadata,$operation,null);
    }
    public function migration(string $key,string $action):?array {return in_array($action,['adoptManagedExact','completeManagedMigration'],true)&&$this->permits($key,$action)?$this->active[2]:null;}
    public function inspectClosed(LocalEpochFence $fence,string $scope,string $subject,callable $operation)
    {
        if(!$this->boundTo($fence)){throw new ConfigurationException('Use the configured closed worker authority.','configuration.mfa_closed');}return $this->run('migrationInspectClosed',$scope,$subject,[],$operation,$fence);
    }
    public function retirement(string $key):?string {return $this->permits($key,'revokeGenerationClosed')?$this->active[2]['factor_id']:null;}
    public function retireClosed(LocalEpochFence $fence,string $scope,string $subject,string $generation,callable $operation)
    {
        if(!$this->boundTo($fence)){throw new ConfigurationException('Use the configured closed worker authority.','configuration.mfa_closed');}
        return $this->run('revokeGenerationClosed',$scope,$subject,['factor_id'=>$generation],$operation,$fence);
    }
    private function run(string $action,string $scope,string $subject,array $metadata,callable $operation,?LocalEpochFence $closed)
    {
        if($this->busy){throw new ConfigurationException('Nested managed factor access is forbidden.','configuration.mfa_nested');}
        self::metadata($action,$metadata);$key=Guard::key('mfa-totp',$scope,$subject);$deadline=new Deadline($this->milliseconds);$this->busy=true;
        $method=$closed===null?'work':'closedWork';$authority=$closed??$this->fence;
        try{return $authority->$method(function()use($action,$scope,$subject,$metadata,$operation,$key,$deadline){
            $observed=$this->now();$this->check($action,'before',$scope,$subject,$metadata);$deadline->check('mfa.timeout');
            if($this->now()<$observed){throw new SecurityException('Managed factor clock moved backwards.','mfa.clock');}
            $observed=$this->now();$this->active=[$key,$action,$metadata];try{$result=$operation();}finally{$this->active=null;}
            try{$this->check($action,'return',$scope,$subject,$metadata);$deadline->check('mfa.timeout');if($this->now()<$observed){throw new SecurityException('Managed factor clock moved backwards.','mfa.clock');}}
            catch(\Throwable $error){throw new StorageException('Managed factor result withheld after possible storage effects.','mfa.completion_unknown');}
            return $result;
        });}finally{$this->active=null;$this->busy=false;}
    }
    public function __debugInfo():array {return ['factor_authority'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload managed factor authority.','configuration.mfa_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload managed factor authority.','configuration.mfa_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Managed factor authority is immutable.','configuration.immutable');}
}
