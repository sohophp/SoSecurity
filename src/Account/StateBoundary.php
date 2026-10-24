<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** one shared operation context. All protected SDK services must use this exact instance. */
final class StateBoundary
{
    private $dependencies;
    private $storageState;
    private $storageGuard;
    private $activeAction;private $activeDeadline;private $addressConsuming=false;
    public function __construct(LocalStateWitness $witness,callable $budgets)
    {
        $this->dependencies=static function()use($witness,$budgets):array{return [$witness,$budgets];};
        $state=new StateExecutionContext();$this->storageState=$state;
        $this->storageGuard=static function(bool $refusal=false,bool $fresh=false,?\SoSecurity\Support\Deadline $deadline=null,bool $optional=false)use($state):?\Closure{if($fresh){return $state->refusalCheck();}if($optional&&!$state->active()){return null;}if($deadline!==null){$state->restrictDeadline($deadline);}else{$state->assertActive();}return $refusal?$state->refusalScope():null;};
    }
    private function enter(?\SoSecurity\Support\Deadline $deadline=null):void{$this->storageState->enter($deadline);}
    private function leave():void{$this->storageState->leave();}
    public function bindFileStore(\SoSecurity\Storage\FileStore $store):void
    {
        if(!$this->coversStore($store)){throw new ConfigurationException('Bind only the exact covered physical storage.','configuration.state_coverage');}
        \SoSecurity\Storage\FileStateBoundary::bind($store->snapshotBinding(),$this->storageGuard);
    }
    public function run(string $action,callable $operation,?callable $admission=null,?StateAccountConnection $lifecycle=null,?\SoSecurity\Support\Deadline $operationDeadline=null,?\SoSecurity\Support\Deadline $executionDeadline=null)
    {
        // Admission may have a shorter sink sub-budget; it never extends the complete caller budget.
        if($executionDeadline!==null){if($operationDeadline!==null){$operationDeadline->restrictTo($executionDeadline);}else{$operationDeadline=$executionDeadline;}}
        $executionDeadline=$executionDeadline??$operationDeadline;
        Guard::label($action);if($operationDeadline!==null){$operationDeadline->check('account.operation_timeout');}if($lifecycle!==null&&(!$lifecycle->boundTo($this)||$this->storageState->entered())){throw new ConfigurationException('Use one outer lifecycle connection context.','configuration.state_refusal');}if($this->storageState->entered()){
            if(!$this->active()){throw new StorageException('State authority belongs to another execution context.','account.state_context');}
            if($executionDeadline===null){if($admission!==null){$admission();}return $operation();}
            return $this->storageState->withinBudget($executionDeadline,static function()use($admission,$operation,$operationDeadline){if($admission!==null){$admission();}$operationDeadline->check('account.operation_timeout');return $operation();});
        }$d=($this->dependencies)();
        return $d[0]->work(function()use($operation,$action,$executionDeadline){$this->enter($executionDeadline);$this->activeAction=$action;$this->activeDeadline=$executionDeadline;try{return $operation();}finally{$this->activeAction=null;$this->activeDeadline=null;$this->leave();}},static function(string $phase)use($d,$action):bool{return ($d[1])($phase,$action)===true;},$d[0]->format()>=2?$d[0]->internalOperation($action):null,$admission,$lifecycle,$operationDeadline);
    }
    /** One address consumption across all adapters in this exact execution, under its original root deadline. */
    public function withAddressConsumption(\SoSecurity\Support\Deadline $deadline,callable $operation)
    {
        $this->assertActive();
        if($this->addressConsuming||$this->activeDeadline===null||!in_array($this->activeAction,['account.address_change.request','account.address_change.complete'],true)){throw new ConfigurationException('Use one exact native address effect and its original budget.','configuration.state_request_nested');}
        $deadline->restrictTo($this->activeDeadline);$deadline->check('account.timeout');$this->addressConsuming=true;
        try{$result=$operation();$deadline->check('account.timeout');return $result;}
        finally{$this->addressConsuming=false;}
    }
    public function authorized(string $action,string $scope,string $target,StateAccountPolicy $policy,StatePermission $permission,callable $operation)
    {
        Guard::label($action);$this->assertScope($scope);if(!$permission->matches($action,$scope,$target)){throw new ConfigurationException('Bind permissions to the exact action and target.','configuration.state_permission');}
        if($this->storageState->entered()){throw new ConfigurationException('Do not nest a new permission decision inside active effects.','configuration.state_permission_nested');}$d=($this->dependencies)();
        return $d[0]->authorized($policy,$permission,function()use($operation){$this->enter();try{return $operation();}finally{$this->leave();}},static function(string $phase)use($d,$action):bool{return ($d[1])($phase,$action)===true;});
    }
    public function boundTo(LocalStateWitness $witness):bool{return (($this->dependencies)())[0]===$witness;}
    /** Only the small execution guard is retained by the SQL connection registry. */
    public function sqlGuard(\PDO $connection):\Closure
    {
        $witness=(($this->dependencies)())[0];
        if(!$witness->usesConnection($connection)||!$this->semanticAuthority()){throw new ConfigurationException('Use the exact semantic SQL authority.','configuration.state_connection');}
        return $this->storageGuard;
    }
    public function assertScope(string $scope):void {if(!(($this->dependencies)())[0]->allowsScope($scope)){throw new ConfigurationException('Use the exact declared state authority scope.','configuration.state_scope');}}
    public function assertActive():void
    {
        if(!$this->active()){throw new StorageException('Protected state requires its active independent operation authority.','account.state_required');}
    }
    public function active():bool{return $this->storageState->active();}
    public function semanticAuthority():bool{return (($this->dependencies)())[0]->format()>=2;}
    public function acceptsPolicy(StateAccountPolicy $policy):bool{return $policy->boundTo((($this->dependencies)())[0]);}
    public function independentOf(LocalStateWitness $witness):bool{return (($this->dependencies)())[0]->independentOf($witness);}
    public function recoveryAuthority(LocalStateWitness $witness):bool{$old=(($this->dependencies)())[0];return $old->binding()===$witness->binding()&&$old->sameSnapshot($witness);}
    public function binding():string{$w=(($this->dependencies)())[0];return hash('sha256','SoSecurity.Account.StateBoundary.1.'.$w->binding().($w->format()===3?'.'.$w->generation():''));}
    public function matches(string $site,string $scope,string $epoch):bool{return (($this->dependencies)())[0]->matches($site,$scope,$epoch);}
    public function protect(AtomicStore $store):WitnessedStore
    {
        if($store instanceof WitnessedStore){if(!$store->boundTo($this)){throw new ConfigurationException('Use one exact state authority for protected storage.','configuration.state_boundary');}return $store;}
        if(!$this->coversStore($store)){throw new ConfigurationException('Protected storage is outside the exact declared snapshot coverage.','configuration.state_coverage');}return new WitnessedStore($store,$this);
    }
    public function coversFence(LocalEpochFence $fence):bool{return (($this->dependencies)())[0]->coversFence($fence);}
    public function coversStore(AtomicStore $store):bool{return (($this->dependencies)())[0]->coversStore($store);}
    public function __debugInfo():array{return ['state_boundary'=>'[redacted]'];}
    public function __clone(){throw new ConfigurationException('Do not clone state operation contexts.','configuration.state_boundary');}
    public function __sleep():array{throw new ConfigurationException('Reload state authority dependencies.','configuration.state_boundary');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize state authority.','configuration.state_boundary');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State authority is immutable.','configuration.immutable');}
}
