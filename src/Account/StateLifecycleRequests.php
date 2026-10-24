<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;

/** @internal Native public lifecycle admission; never grants account or management authority. */
final class StateLifecycleRequests
{
    private $boundary;private $scope;private $purpose;private $guard;private $busy=false;private $connection;
    public function __construct(StateBoundary $boundary,string $scope,string $purpose,StateRequestGuard $guard,StateAccountConnection $connection)
    {
        if(!in_array($purpose,['registration','recovery','mailbox_recovery','address_change'],true)){throw new ConfigurationException('Use a fixed public lifecycle purpose.','configuration.state_request');}
        $boundary->assertScope($scope);$this->boundary=$boundary;$this->scope=$scope;$this->purpose=$purpose;$this->guard=$guard;$this->connection=$connection;
    }
    private function request(string $purpose,bool $current):void
    {
        try{$allowed=$current?$this->guard->current($purpose,$this->scope):($this->guard)($purpose,$this->scope);}
        catch(\Throwable $error){throw new \SoSecurity\Exception\DependencyException('Lifecycle request protection unavailable.','account.request_unavailable');}
        if($allowed!==true){throw new SecurityException($current?'Current host request admission required.':'Current host request protection required.','account.request_denied');}
    }
    public function run(string $action,callable $preflight,callable $operation)
    {
        if(!in_array($action,$this->purpose==='address_change'?['confirm','cancel']:['request','confirm','cancel'],true)||$this->busy||$this->boundary->active()){throw new ConfigurationException('Enter native lifecycle requests directly, without a surrounding operation.','configuration.state_request_nested');}
        $this->busy=true;
        try{
            $purpose=$this->purpose.'.'.$action;
            $this->request($purpose,false);
            $admission=$preflight();
            return $this->boundary->run('account.'.$purpose,static function()use($operation,$admission){return $operation($admission);},function()use($purpose):void{
                $this->request($purpose,true);
            },$this->connection);
        }finally{$this->busy=false;}
    }
}
