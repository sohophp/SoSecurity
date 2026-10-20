<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Support\Clock;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Exception\ConfigurationException;

/** Compatibility facade for the purpose-bound shared intent maintenance engine. */
final class FactorMigrationMaintenance
{
    private $engine;
    public function __construct(PDO $pdo,string $site,string $scope,string $epoch,HmacKeys $keys,TotpFactors $managed,LocalEpochFence $fence,callable $decode,callable $stopped,callable $authority,callable $budgets,callable $approval,callable $audit,callable $events,Policy $policy,Clock $clock)
    {
        $this->engine=new FactorIntentMaintenance($pdo,$site,$scope,$epoch,$keys,$managed,$fence,$decode,$stopped,$authority,$budgets,$approval,$audit,$events,$policy,$clock);
    }
    public function review(string $mode,string $source,int $limit=20,string $after=''):array{return $this->engine->review($mode,$source,$limit,$after);}
    public function reviewClosed(string $mode,string $source,int $limit=20,string $after=''):array{return $this->engine->reviewClosed($mode,$source,$limit,$after);}
    public function maintain(array $context,string $source,array $proof):array{return $this->engine->maintain($context,$source,$proof);}
    public function drainAndMaintain(array $context,string $source,array $proof):array{return $this->engine->drainAndMaintain($context,$source,$proof);}
    public function maintainClosed(array $context,string $source,array $proof):array{return $this->engine->maintainClosed($context,$source,$proof);}
    public function __debugInfo():array{return ['factor_migration_maintenance'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload history maintenance dependencies.','configuration.factor_migration');}
    public function __wakeup():void{throw new ConfigurationException('Reload history maintenance dependencies.','configuration.factor_migration');}
    public function __set(string $name,$value):void{throw new ConfigurationException('History maintenance is immutable.','configuration.immutable');}
}
