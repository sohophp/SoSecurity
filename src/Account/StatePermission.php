<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Server-built operation requirements and a registry reference, never an approval by itself. */
final class StatePermission
{
    private $contents;
    public function __construct(string $action,string $scope,string $actor,string $target,string $token,array $roles=[],int $strength=2,int $maximumAge=300,bool $freshOnly=true,bool $selfOnly=true,array $methods=[])
    {
        foreach([$action,$scope,$actor,$target] as $value){Guard::label($value);if(preg_match('//u',$value)!==1){self::invalid();}}
        $reference=SessionRegistry::reference($token);if((!$selfOnly&&count($roles)===0)||$reference===null||$strength<1||$strength>2||$maximumAge<1||$maximumAge>86400||count($roles)>8){self::invalid();}
        // Account's shared validator normalizes and copies role strings; no callbacks.
        $roles=(new Account($scope,$actor,'state-permission',true,$roles))->roles();
        if(count($methods)>4||array_values($methods)!==$methods){self::invalid();}$allowed=[];foreach($methods as $method){if(!is_string($method)||!in_array($method,['password','totp','recovery','webauthn'],true)||in_array($method,$allowed,true)){self::invalid();}$allowed[]=$method;}sort($allowed,SORT_STRING);
        $definition=['action'=>$action,'scope'=>$scope,'actor'=>$actor,'target'=>$target,'reference'=>$reference,'roles'=>$roles,'strength'=>$strength,'age'=>$maximumAge,'fresh'=>$freshOnly,'self'=>$selfOnly,'methods'=>$allowed];
        $this->contents=static function()use($definition):array{return $definition;};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use exact bounded server-owned state permission requirements.','configuration.state_permission');}
    /** @internal The raw credential is never retained. */
    public function definition():array{return ($this->contents)();}
    public function matches(string $action,string $scope,string $target):bool{$v=$this->definition();return $v['action']===$action&&$v['scope']===$scope&&$v['target']===$target;}
    public function binding():string{return hash('sha256','SoSecurity.Account.StatePermission.2.'.json_encode($this->definition()));}
    public function __debugInfo():array{return ['state_permission'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
