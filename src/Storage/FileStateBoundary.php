<?php
declare(strict_types=1);
namespace SoSecurity\Storage;
use SoSecurity\Exception\ConfigurationException;

/** Internal process-local admission for complete physical domains, including new raw instances. */
final class FileStateBoundary
{
    /** Guards capture only a small execution cell, never the service graph, keys or PDO. */
    private static $domains=[];
    public static function bind(string $domain,\Closure $guard):void
    {
        if(isset(self::$domains[$domain])){
            if(self::$domains[$domain]!==$guard){throw new ConfigurationException('One physical state directory requires one exact operation authority.','configuration.state_boundary');}
            return;
        }
        if(count(self::$domains)>=128){throw new ConfigurationException('Explicit state directory bindings exceed the process bound.','configuration.state_boundary_capacity');}
        self::$domains[$domain]=$guard;
    }
    public static function bound(string $domain):bool{return isset(self::$domains[$domain]);}
    public static function assertActive(string $domain):void{if(isset(self::$domains[$domain])){(self::$domains[$domain])();}}
    public static function assertStoreActive(AtomicStore $store):void
    {
        $depth=0;while($store instanceof NamespacedStore){if(++$depth>16){throw new ConfigurationException('Storage nesting exceeds its bound.','configuration.state_boundary');}$store=$store->underlying();}
        if($store instanceof \SoSecurity\Account\WitnessedStore){$store->assertActive();}elseif($store instanceof FileStore){self::assertActive($store->snapshotBinding());}
    }
    public static function protects(AtomicStore $store):bool
    {
        $depth=0;
        while($store instanceof NamespacedStore){if(++$depth>16){throw new ConfigurationException('Storage nesting exceeds its bound.','configuration.state_boundary');}$store=$store->underlying();}
        return $store instanceof \SoSecurity\Account\WitnessedStore||($store instanceof FileStore&&self::bound($store->snapshotBinding()));
    }
}
