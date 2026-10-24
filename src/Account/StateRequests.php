<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
final class StateRequests implements StateRequestGuard
{
    private $dependencies;
    public function __construct(callable $public,callable $current){$this->dependencies=static function()use($public,$current):array{return [$public,$current];};}
    public function __invoke(string $action,string $scope):bool{return (($this->dependencies)())[0]($action,$scope)===true;}
    public function current(string $action,string $scope):bool{return (($this->dependencies)())[1]($action,$scope)===true;}
    public function __debugInfo():array{return ['state_requests'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload request authority dependencies.','configuration.state_boundary');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize request authority.','configuration.state_boundary');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Request authority is immutable.','configuration.immutable');}
}
