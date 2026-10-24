<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Account\StateAccountPolicy;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

/** Explicit captured-facts policy; evaluator callbacks must be pure and bounded. */
final class SnapshotPolicy implements PolicyProvider
{
    private $dependencies;
    private $fingerprint;
    public function __construct(SnapshotEvaluator $policy,SqlStateSnapshot $source,string $profile)
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$profile)){throw new ConfigurationException('Declare one policy and its exact configuration digest.','configuration.authorization_state');}
        // The reviewed profile binds implementation and configuration; anonymous class names contain deployment paths.
        $this->fingerprint=hash('sha256','SoSecurity.Authorization.SnapshotPolicy.2.'.json_encode([$source->fingerprint(),$profile]));
        $this->dependencies=static function()use($policy,$source):array{return [$policy,$source];};
    }
    public function fingerprint():string{return $this->fingerprint;}
    public function matches(StateAccountPolicy $state):bool{return $state->policySource((($this->dependencies)())[1]);}
    public function decide(Account $actor,string $action,Resource $resource,array $requestedFields=[]):?Decision
    {
        throw new ConfigurationException('Evaluate declared policies only through captured native authority.','configuration.authorization_state');
    }
    public function evaluate(StateAccountPolicy $state,string $expected,Account $actor,string $action,Resource $resource,array $requestedFields=[]):?Decision
    {
        if(!$this->matches($state)){throw new ConfigurationException('Use the exact captured policy source.','configuration.authorization_state');}
        Shape::name($action);$fields=Shape::fields($requestedFields);$d=($this->dependencies)();
        try{$selectors=$d[0]->selectors($actor,$action,$resource,$fields);}
        catch(\Throwable $error){throw new DependencyException('Declared policy unavailable.','authorization.unavailable');}
        $facts=$state->policyFacts($d[1],$selectors,$expected);
        try{$decision=$d[0]->decide($actor,$action,$resource,$fields,$facts);}
        catch(\Throwable $error){throw new DependencyException('Declared policy unavailable.','authorization.unavailable');}
        $state->policyCurrent($expected);return $decision;
    }
    public function __debugInfo():array{return ['policy'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild declared policies.','configuration.authorization_serialization');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize declared policies.','configuration.authorization_serialization');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Declared policies are immutable.','configuration.immutable');}
}
