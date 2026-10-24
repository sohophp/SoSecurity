<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\AtomicStore;

/** reads can prune or rewrite state; every transact requires an active outer witness. */
final class WitnessedStore implements AtomicStore
{
    private $dependencies;
    public function __construct(AtomicStore $store,StateBoundary $boundary)
    {
        if($store instanceof self){throw new ConfigurationException('Use the existing protected store.','configuration.state_boundary');}
        if(!$boundary->coversStore($store)){throw new ConfigurationException('Protected storage is outside the exact declared snapshot coverage.','configuration.state_coverage');}
        $physical=$store;$depth=0;
        while($physical instanceof \SoSecurity\Storage\NamespacedStore){if(++$depth>16){throw new ConfigurationException('Protected storage nesting exceeds its bound.','configuration.state_coverage');}$physical=$physical->underlying();}
        if(!$physical instanceof \SoSecurity\Storage\FileStore){throw new ConfigurationException('This witness requires an explicitly supported physical storage adapter.','configuration.state_coverage');}
        $physical->bindStateBoundary($boundary);
        $this->dependencies=static function()use($store,$boundary):array{return [$store,$boundary];};
    }
    public function boundTo(StateBoundary $boundary):bool{return (($this->dependencies)())[1]===$boundary;}
    public function protects(AtomicStore $store):bool{return (($this->dependencies)())[0]===$store;}
    public function assertActive():void{(($this->dependencies)())[1]->assertActive();}
    public function transact(string $key,callable $callback)
    {
        $d=($this->dependencies)();$d[1]->assertActive();return $d[0]->transact($key,$callback);
    }
    public function __debugInfo():array{return ['witnessed_store'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload protected storage dependencies.','configuration.state_boundary');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize protected storage.','configuration.state_boundary');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Protected storage is immutable.','configuration.immutable');}
}
