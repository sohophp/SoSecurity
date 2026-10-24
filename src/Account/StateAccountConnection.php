<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Operation\Grants;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SystemClock;

/** Complete lifecycle source declaration; never adopts state, initializes SQL or grants caller permission. */
final class StateAccountConnection
{
    private $dependencies;
    private $maintenanceBusy=false;
    public function __construct(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,SqlStateSnapshot $sql,string $sqlName,Repository $accounts,string $table,array $columns,string $site,string $scope,string $epoch,Clock $clock,Policy $policy,SessionRegistry $sessions)
    {
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($sqlName,$sql)||$source->connection()!==$sql->connection()||!$sessions->boundTo($boundary)){self::invalid();}
        $pdo=$sql->connection();if($accounts->connection()!==$pdo){self::invalid();}
        $required=['scope'=>'bytes:256','subject'=>'bytes:256','credential_version'=>'bytes:256','address_version'=>'bytes:256','address'=>'bytes:320','password'=>'nullable_bytes:4096','status'=>'bytes:16','verified'=>'int','mfa_required'=>'int','roles'=>'bytes:4096'];
        $actual=array_keys($columns);$expected=array_keys($required);sort($actual);sort($expected);if($actual!==$expected){self::invalid();}$types=[];$copy=[];
        foreach($required as $name=>$type){$column=$columns[$name];if(!is_string($column)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$column)||isset($types[$column])){self::invalid();}$copy[$name]=$column;$types[$column]=$type;}
        if(!$sql->coversColumns($table,$types,[$copy['scope'],$copy['subject']],[$copy['scope']=>$scope])){self::invalid();}
        $records=Ledger::recordTypes();$records['payload']='blob:16384';$outbox=\SoSecurity\Outbox\Schema::recordTypes();$outbox['payload_body']='blob:1048576';
        foreach(['sosecurity_account_roots'=>[Ledger::rootTypes(),['namespace']],'sosecurity_account_records'=>[$records,['namespace','record_id']],'sosecurity_outbox_roots'=>[\SoSecurity\Outbox\Schema::rootTypes(),['namespace']],'sosecurity_outbox_records'=>[$outbox,['namespace','key_hash']]] as $name=>$definition){if(!$sql->coversColumns($name,$definition[0],$definition[1],[])){self::invalid();}}
        $binding=hash('sha256',json_encode(['SoSecurity.Account.StateAccountConnection.1',$witness->binding(),$source->fingerprint(),$sqlName,$sql->fingerprint(),$table,$copy,$site,$scope,$epoch,$policy->fingerprint()],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        SqlStateAccess::bind($pdo,SqlStateAccess::context($site,$scope,$epoch),$binding,$boundary->sqlGuard($pdo),$boundary);
        $this->dependencies=static function()use($boundary,$pdo,$accounts,$site,$scope,$epoch,$clock,$policy,$sessions,$sql,$table,$copy):array{return [$boundary,$pdo,$accounts,$site,$scope,$epoch,$clock,$policy,$sessions,$sql,$table,$copy];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Declare the complete same-PDO account, lifecycle ledger and outbox sources.','configuration.state_connection');}
    public function validate(PDO $pdo,Repository $accounts,string $site,string $scope,string $epoch,Clock $clock,Policy $policy):void
    {
        $d=($this->dependencies)();if($d[1]!==$pdo||$d[2]!==$accounts||$d[3]!==$site||$d[4]!==$scope||$d[5]!==$epoch||!($d[6]===$clock||($d[6] instanceof SystemClock&&$clock instanceof SystemClock))||$d[7]->fingerprint()!==$policy->fingerprint()){self::invalid();}
    }
    public function assertAddressPolicy(StateAccountPolicy $policy):void
    {
        $d=($this->dependencies)();if(!$d[0]->acceptsPolicy($policy)||!$policy->maintenanceContext($d[9],$d[10],$d[11])||!$policy->recoveryRegistry($d[8],$d[4])||!$policy->recoveryClock($d[6])||$d[0]->active()||$this->maintenanceBusy){self::invalid();}
    }
    /** Trusted native address callbacks only; this does not initialize or grant caller authority. */
    public function addressOperation(StateAccountPolicy $policy,string $action,callable $admission,callable $operation,\SoSecurity\Support\Deadline $deadline)
    {
        $d=($this->dependencies)();
        $this->assertAddressPolicy($policy);if(!in_array($action,['proposal','completion_proposal','request','complete'],true)){self::invalid();}
        $this->maintenanceBusy=true;try{return $d[0]->run('account.address_change.'.$action,$operation,$admission,null,$deadline);}finally{$this->maintenanceBusy=false;}
    }
    /** Read-only current request guard after the effect boundary's final budget callback. */
    public function addressReturn(StateAccountPolicy $policy,AccountRecord $expected,callable $guard,\SoSecurity\Support\Deadline $deadline):void
    {
        $this->assertAddressPolicy($policy);$d=($this->dependencies)();$subject=$expected->account()->subject();
        if($expected->account()->scope()!==$d[4]){self::invalid();}$deadline->check('account.timeout');$this->maintenanceBusy=true;
        try{
            $d[0]->run('account.address_change.return_check',static function():void{throw new ConfigurationException('Address return checks cannot replay effects.','configuration.state_connection');},function(string $digest)use($policy,$expected,$guard,$deadline,$d,$subject):bool{
                $deadline->check('account.timeout');$identity=$policy->credentialView($d[4],$subject,null,$digest);$c=$d[11];
                $rows=$policy->policyFacts($d[9],['address_return'=>['table'=>$d[10],'key'=>[$c['scope']=>$d[4],$c['subject']=>$subject],'columns'=>[$c['credential_version'],$c['address'],$c['address_version']]]],$digest);$row=$rows['address_return'];
                if($identity===null||$row===null){throw new \SoSecurity\Exception\SecurityException('Current address account required.','account.changed');}$actor=$identity['account'];
                $record=new AccountRecord(new \SoSecurity\Auth\Account($d[4],$subject,$row[$c['credential_version']],true,$actor->roles(),$actor->mfaRequired()),new Address($row[$c['address']],$d[7]->allowsSmtpUtf8()),$row[$c['address_version']],true,'active');
                if(!hash_equals($expected->fingerprint(),$record->fingerprint())){throw new \SoSecurity\Exception\SecurityException('Address return account changed.','account.changed');}
                $deadline->check('account.timeout');$failed=false;$allowed=false;$local=$record;
                try{$allowed=$guard($local);}catch(\Throwable $error){$failed=true;}
                $deadline->check('account.timeout');$policy->policyCurrent($digest);$deadline->check('account.timeout');
                if($failed){throw new \SoSecurity\Exception\DependencyException('Address request authority unavailable.','account.authority');}if($allowed!==true){throw new \SoSecurity\Exception\SecurityException('Address request authority refused.','account.denied');}return false;
            },null,$deadline);
            $deadline->check('account.timeout');
        }finally{$this->maintenanceBusy=false;}
    }
    public function addressView(StateAccountPolicy $policy,string $subject,string $token,string $expected):?array
    {
        $d=($this->dependencies)();if(!$d[0]->acceptsPolicy($policy)||!$policy->maintenanceContext($d[9],$d[10],$d[11])||!$policy->recoveryRegistry($d[8],$d[4])||!$policy->recoveryClock($d[6])){self::invalid();}
        return $policy->addressView($d[4],$subject,$token,$expected,$d[11]['address'],$d[11]['address_version'],$d[7]->allowsSmtpUtf8());
    }
    public function validateSendBudgets(SendBudgets $budgets):void
    {
        $d=($this->dependencies)();$budgets->validateState($d[0],$d[3],$d[6]);
    }
    public function boundTo(StateBoundary $boundary):bool{return (($this->dependencies)())[0]===$boundary;}
    public function boundToWitness(LocalStateWitness $witness):bool{return (($this->dependencies)())[0]->boundTo($witness);}
    /** Observe a subsequent exact execution; no state admission or permission is granted. */
    public function refusalCheck():\Closure
    {
        $d=($this->dependencies)();$guard=$d[0]->sqlGuard($d[1]);$check=$guard(false,true);
        if(!$check instanceof \Closure){self::invalid();}return $check;
    }
    /** Public request admission only; business and recovery approval remain independent. */
    public function requestHandler(string $purpose,StateRequestGuard $requests):\Closure
    {
        $d=($this->dependencies)();$handler=new StateLifecycleRequests($d[0],$d[4],$purpose,$requests,$this);
        return static function(string $action,callable $preflight,callable $operation)use($handler){return $handler->run($action,$preflight,$operation);};
    }
    /** Exact native maintenance page; neither a caller identity nor a role is inferred. */
    public function maintenance(string $purpose,string $action,StateAccountPolicy $policy,StatePermission $permission,int $limit,string $after,callable $admission,callable $operation):?array
    {
        $target=$this->maintenanceTarget($purpose,$action,$limit,$after);
        return $this->runMaintenance('account.'.$purpose.'.'.$action,$target,$policy,$permission,$admission,$operation);
    }
    private function runMaintenance(string $name,string $target,StateAccountPolicy $policy,StatePermission $permission,callable $admission,callable $operation,?\SoSecurity\Support\Deadline $operationDeadline=null):?array
    {
        $d=($this->dependencies)();
        if(!$d[0]->acceptsPolicy($policy)||!$policy->maintenanceContext($d[9],$d[10],$d[11])||!$policy->recoveryRegistry($d[8],$d[4])||!$policy->recoveryClock($d[6])||!$permission->matches($name,$d[4],$target)||$d[0]->active()||$this->maintenanceBusy){self::invalid();}
        $r=$permission->definition();if($r['self']||!$r['roles']){self::invalid();}$deadline=new \SoSecurity\Support\Deadline($d[7]->ioMilliseconds());
        $this->maintenanceBusy=true;try{return $d[0]->run($name,function()use($policy,$permission,$operation,$deadline):array{
            $deadline->check('account.maintenance_timeout');if(!$policy->maintenancePermission($permission)){throw new \SoSecurity\Exception\SecurityException('Current maintenance permission required.','account.state_denied');}
            $result=$operation();$deadline->check('account.maintenance_timeout');
            if(!$policy->maintenancePermission($permission)){throw new \SoSecurity\Exception\SecurityException('Maintenance completion permission changed.','account.state_denied');}$deadline->check('account.maintenance_timeout');return $result;
        },function(string $expected)use($policy,$permission,$admission,$deadline){
            $deadline->check('account.maintenance_timeout');if(!$policy->maintenancePermission($permission,$expected)){return false;}
            if($admission()!==true){return false;}$deadline->check('account.maintenance_timeout');
            if(!$policy->maintenancePermission($permission,$expected)){return false;}
            return StateOperation::authorized($permission,$policy->binding(),$policy->now());
        },null,$operationDeadline);}finally{$this->maintenanceBusy=false;}
    }
    public function validateIdempotency(PDO $pdo,string $site,string $epoch,Clock $clock):void
    {
        $this->validateOutbox($pdo,$site,$epoch,$clock);$d=($this->dependencies)();$records=\SoSecurity\Idempotency\Schema::recordTypes();$records['response_body']='blob:1048576';
        foreach(['sosecurity_idempotency_roots'=>[\SoSecurity\Idempotency\Schema::rootTypes(),['namespace']],'sosecurity_idempotency_records'=>[$records,['namespace','key_hash']]] as $table=>$spec){if(!$d[9]->coversColumns($table,$spec[0],$spec[1],[])){self::invalid();}}
    }
    public function idempotencyMaintenanceTarget(string $action,string $scope,string $subject,string $operation,string $configuration,int $limit=20,string $after=''):string
    {
        $d=($this->dependencies)();\SoSecurity\Idempotency\State::group($scope,$subject,$operation);
        if(!in_array($action,['initialize','maintain'],true)||$scope!==$d[4]||preg_match('/\A[a-f0-9]{64}\z/D',$configuration)!==1||$limit<1||$limit>50||($after!==''&&preg_match('/\A[a-f0-9]{64}\z/D',$after)!==1)||($action==='initialize'&&($limit!==20||$after!==''))){self::invalid();}
        return hash('sha256',json_encode(['SoSecurity.Account.IdempotencyMaintenance.1',$d[0]->binding(),$d[3],$scope,$d[5],$subject,$operation,$configuration,$action,$limit,$after]));
    }
    public function idempotencyMaintenance(string $action,StateAccountPolicy $policy,StatePermission $permission,string $scope,string $subject,string $operation,string $configuration,int $limit,string $after,callable $admission,callable $effect,callable $completion,\SoSecurity\Support\Deadline $deadline):?array
    {
        $target=$this->idempotencyMaintenanceTarget($action,$scope,$subject,$operation,$configuration,$limit,$after);$d=($this->dependencies)();$maximum=$d[9]->maximumRows('sosecurity_idempotency_roots');
        $result=$this->runMaintenance('idempotency.'.$action,$target,$policy,$permission,static function()use($admission,$maximum):bool{return $admission($maximum);},$effect,$deadline);
        if($result!==null){$this->maintenanceBusy=true;try{$deadline->check('idempotency.timeout');$completion();$deadline->check('idempotency.timeout');if(!$policy->maintenancePermission($permission)){throw new \SoSecurity\Exception\SecurityException('Idempotency maintenance permission changed before return.','idempotency.denied');}$deadline->check('idempotency.timeout');}finally{$this->maintenanceBusy=false;}}return $result;
    }
    /** Trusted handler declaration: every named business table must be fully covered by this exact source. */
    public function idempotencyBusiness(array $tables):string
    {
        $d=($this->dependencies)();if(!$tables||count($tables)>4){self::invalid();}$checked=[];
        foreach($tables as $table=>$spec){
            if(!is_string($table)||preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$table)!==1||!is_array($spec)||count($spec)>3||array_diff(array_keys($spec),['columns','primary','where'])||!isset($spec['columns'],$spec['primary'])||!is_array($spec['columns'])||!$spec['columns']||count($spec['columns'])>64||!is_array($spec['primary'])||!$spec['primary']||count($spec['primary'])>4||array_values($spec['primary'])!==$spec['primary']){self::invalid();}
            $filter=$spec['where']??[];if(!is_array($filter)||count($filter)>4){self::invalid();}foreach($filter as $name=>$value){if(!is_string($name)||preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$name)!==1||(!is_int($value)&&(!is_string($value)||strlen($value)>1024||preg_match('//u',$value)!==1))){self::invalid();}}
            if(!$d[9]->containsDefinition($table,$spec['columns'],$spec['primary'],$filter)){self::invalid();}$columns=$spec['columns'];ksort($columns,SORT_STRING);ksort($filter,SORT_STRING);$checked[$table]=['columns'=>$columns,'primary'=>$spec['primary'],'where'=>$filter];
        }
        ksort($checked,SORT_STRING);return hash('sha256','SoSecurity.Account.IdempotencyBusiness.1.'.json_encode($checked));
    }
    public function idempotencyRequestTarget(string $action,\SoSecurity\Idempotency\Request $request,string $configuration):string
    {
        $d=($this->dependencies)();if(!in_array($action,['execute','lookup'],true)||$request->scope()!==$d[4]||preg_match('/\A[a-f0-9]{64}\z/D',$configuration)!==1){self::invalid();}
        return hash('sha256',json_encode(['SoSecurity.Account.IdempotencyRequest.1',$d[0]->binding(),$d[3],$d[4],$d[5],$action,$request->subject(),$request->operation(),hash('sha256',$request->key()),$request->fingerprint(),$configuration]));
    }
    public function idempotencyRequest(string $action,StateAccountPolicy $policy,StatePermission $permission,\SoSecurity\Idempotency\Request $request,string $configuration,callable $admission,callable $effect,callable $completion,\SoSecurity\Support\Deadline $deadline):?array
    {
        $target=$this->idempotencyRequestTarget($action,$request,$configuration);$d=($this->dependencies)();$maximum=$d[9]->maximumRows('sosecurity_idempotency_records');
        $result=$this->runMaintenance('idempotency.'.$action,$target,$policy,$permission,static function()use($admission,$maximum):bool{return $admission($maximum);},$effect,$deadline);
        if($result!==null){$this->maintenanceBusy=true;try{$deadline->check('idempotency.timeout');$completion($result);$deadline->check('idempotency.timeout');if(!$policy->maintenancePermission($permission)){throw new \SoSecurity\Exception\SecurityException('Idempotency request permission changed before return.','idempotency.denied');}$deadline->check('idempotency.timeout');}finally{$this->maintenanceBusy=false;}}return $result;
    }
    public function validateOutbox(PDO $pdo,string $site,string $epoch,Clock $clock):void
    {
        $d=($this->dependencies)();if($d[1]!==$pdo||$d[3]!==$site||$d[5]!==$epoch||$d[6]!==$clock){self::invalid();}
    }
    public function outboxRotationTarget(string $scope,string $producer,string $actor,string $configuration,int $limit=20,string $after=''):string
    {
        $d=($this->dependencies)();foreach([$scope,$producer,$actor] as $label){\SoSecurity\Support\Guard::label($label);if(preg_match('//u',$label)!==1){self::invalid();}}
        if($scope!==$d[4]||preg_match('/\A[a-f0-9]{64}\z/D',$configuration)!==1||$limit<1||$limit>50||($after!==''&&preg_match('/\A[a-f0-9]{64}\z/D',$after)!==1)){self::invalid();}
        return hash('sha256',json_encode(['SoSecurity.Account.OutboxRotation.1',$d[0]->binding(),$d[3],$scope,$d[5],$d[7]->fingerprint(),$producer,$actor,$configuration,$limit,$after]));
    }
    public function outboxRotation(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $actor,string $configuration,int $limit,string $after,callable $admission,callable $operation):?array
    {
        return $this->runMaintenance('outbox.rotate',$this->outboxRotationTarget($scope,$producer,$actor,$configuration,$limit,$after),$policy,$permission,$admission,$operation);
    }
    public function outboxInitialTarget(string $scope,string $producer,string $worker,string $id,string $configuration):string
    {
        if(strlen($id)>128){self::invalid();}\SoSecurity\Outbox\State::idTime($id);
        return hash('sha256','SoSecurity.Account.OutboxInitial.1.'.$this->outboxRotationTarget($scope,$producer,$worker,$configuration,1,'').$id);
    }
    public function outboxInitial(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $worker,string $id,string $configuration,callable $admission,callable $operation,?\SoSecurity\Support\Deadline $operationDeadline=null):?array
    {
        return $this->runMaintenance('outbox.claim_initial',$this->outboxInitialTarget($scope,$producer,$worker,$id,$configuration),$policy,$permission,$admission,$operation,$operationDeadline);
    }
    public function outboxCurrentTarget(string $scope,string $producer,string $worker,string $token,string $configuration):string
    {
        if(strlen($token)!==132||preg_match('/\Ac1\.[a-f0-9]{64}\.[a-f0-9]{64}\z/D',$token)!==1){self::invalid();}
        return hash('sha256','SoSecurity.Account.OutboxCurrent.1.'.$this->outboxRotationTarget($scope,$producer,$worker,$configuration,1,'').hash('sha256',$token));
    }
    public function outboxCurrent(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $worker,string $token,string $configuration,callable $admission,callable $operation,?\SoSecurity\Support\Deadline $operationDeadline=null):?array
    {
        return $this->runMaintenance('outbox.current_claim',$this->outboxCurrentTarget($scope,$producer,$worker,$token,$configuration),$policy,$permission,$admission,$operation,$operationDeadline);
    }
    public function outboxAcknowledgeTarget(string $scope,string $producer,string $worker,string $token,string $configuration):string
    {
        return hash('sha256','SoSecurity.Account.OutboxAcknowledge.1.'.$this->outboxCurrentTarget($scope,$producer,$worker,$token,$configuration));
    }
    public function outboxAcknowledge(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $worker,string $token,string $configuration,callable $admission,callable $operation,?\SoSecurity\Support\Deadline $operationDeadline=null):?array
    {
        return $this->runMaintenance('outbox.acknowledge',$this->outboxAcknowledgeTarget($scope,$producer,$worker,$token,$configuration),$policy,$permission,$admission,$operation,$operationDeadline);
    }
    public function outboxRejectTarget(string $scope,string $producer,string $worker,string $token,string $error,string $configuration):string
    {
        if(strlen($error)>64||preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$error)!==1){self::invalid();}
        return hash('sha256','SoSecurity.Account.OutboxReject.1.'.$this->outboxCurrentTarget($scope,$producer,$worker,$token,$configuration).'.'.$error);
    }
    public function outboxReject(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $worker,string $token,string $error,string $configuration,callable $admission,callable $operation,?\SoSecurity\Support\Deadline $operationDeadline=null):?array
    {
        return $this->runMaintenance('outbox.reject',$this->outboxRejectTarget($scope,$producer,$worker,$token,$error,$configuration),$policy,$permission,$admission,$operation,$operationDeadline);
    }
    public function outboxRejectedDispatchTarget(string $scope,string $producer,string $worker,string $id,string $configuration,int $previousAttempt,string $error):string
    {
        if($previousAttempt<1||$previousAttempt>=100||strlen($error)>64||preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$error)!==1||in_array($error,['lease_expired','expired','attempts_exhausted'],true)){self::invalid();}
        return hash('sha256','SoSecurity.Account.OutboxRejectedDispatch.1.'.$this->outboxInitialTarget($scope,$producer,$worker,$id,$configuration).json_encode([$previousAttempt,$error]));
    }
    public function outboxRejectedDispatch(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $worker,string $id,string $configuration,int $previousAttempt,string $error,callable $admission,callable $operation,\SoSecurity\Support\Deadline $deadline):?array
    {
        return $this->runMaintenance('outbox.dispatch_rejected',$this->outboxRejectedDispatchTarget($scope,$producer,$worker,$id,$configuration,$previousAttempt,$error),$policy,$permission,$admission,$operation,$deadline);
    }
    public function outboxDispatchTarget(string $scope,string $producer,string $worker,string $id,string $configuration):string
    {
        return hash('sha256','SoSecurity.Account.OutboxDispatch.1.'.$this->outboxInitialTarget($scope,$producer,$worker,$id,$configuration));
    }
    public function outboxDispatch(StateAccountPolicy $policy,StatePermission $permission,string $scope,string $producer,string $worker,string $id,string $configuration,callable $admission,callable $operation,\SoSecurity\Support\Deadline $deadline):?array
    {
        return $this->runMaintenance('outbox.dispatch',$this->outboxDispatchTarget($scope,$producer,$worker,$id,$configuration),$policy,$permission,$admission,$operation,$deadline);
    }
    public function maintenanceTarget(string $purpose,string $action,int $limit=20,string $after=''):string
    {
        if(!in_array($purpose,['registration','address_change','recovery','mailbox_recovery','factor_notices'],true)||!in_array($action,['maintain','rotate'],true)||$limit<1||$limit>50||($after!==''&&!preg_match('/\A[a-f0-9]{64}\z/D',$after))){self::invalid();}
        $d=($this->dependencies)();return hash('sha256',json_encode(['SoSecurity.Account.Maintenance.1',$d[0]->binding(),$d[3],$d[4],$d[5],$d[7]->fingerprint(),$purpose,$action,$limit,$after]));
    }
    public function assertActive():void{(($this->dependencies)())[0]->assertActive();}
    public function assertAuthentication(SessionRegistry $sessions,Grants $grants):void
    {
        $d=($this->dependencies)();if($sessions!==$d[8]||!$grants->stateContext($sessions,$d[0],$d[6])){self::invalid();}
    }
    public function __debugInfo():array{return ['account_connection'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
