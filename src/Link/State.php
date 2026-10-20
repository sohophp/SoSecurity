<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** Internal v1 per-site/purpose/resource ledger. No plaintext URL, binding or business parameters. */
final class State
{
    public static function hex($value,int $length):bool {return is_string($value)&&strlen($value)===$length&&preg_match('/\A[a-f0-9]+\z/D',$value)===1;}
    public static function key(string $site,Target $target):string
    {
        $resource=$target->resource();return Guard::key('signed-links',$site,hash('sha256',json_encode([$target->purpose(),$resource->scope(),$resource->type(),$resource->id()])));
    }
    private static function fields(array $value,array $fields):bool {$keys=array_keys($value);sort($keys);sort($fields);return $keys===$fields;}
    public static function read($state,Policy $policy,int $now):?array
    {
        if ($state===null) {return null;}
        if (!is_array($state) || !self::fields($state,['v','policy','seen','entries']) || $state['v']!==1 || !self::hex($state['policy'],64)
            || !is_int($state['seen']) || $state['seen']<0 || $state['seen']>PHP_INT_MAX-86400 || !is_array($state['entries']) || count($state['entries'])>64) {throw new StorageException('Corrupt signed-link ledger.','storage.corrupt');}
        if (!hash_equals($policy->fingerprint(),$state['policy'])) {throw new StorageException('Migrate active signed-link policy explicitly.','link.policy_changed');}
        if ($state['seen']>$now) {throw new StorageException('Signed-link clock moved backwards.','link.clock');}
        if (count($state['entries'])>$policy->capacity()) {throw new StorageException('Corrupt signed-link capacity.','storage.corrupt');}
        foreach ($state['entries'] as $id=>$entry) {
            if (!self::hex($id,32) || !is_array($entry) || !self::fields($entry,['digest','target','issued','expires','one_time','key_id']) || !self::hex($entry['digest'],64) || !self::hex($entry['target'],64)
                || !is_int($entry['issued']) || $entry['issued']<0 || $entry['issued']>$state['seen'] || !is_int($entry['expires']) || $entry['expires']<=$entry['issued'] || $entry['expires']>$entry['issued']+$policy->maximumTtl()
                || !is_bool($entry['one_time']) || !is_string($entry['key_id']) || !preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$entry['key_id'])) {throw new StorageException('Corrupt signed-link entry.','storage.corrupt');}
        }
        return $state;
    }
    public static function prepare(?array $state,Policy $policy,int $now):array
    {
        $state=$state ?? ['v'=>1,'policy'=>$policy->fingerprint(),'seen'=>$now,'entries'=>[]];
        foreach ($state['entries'] as $id=>$entry) {if($entry['expires']<=$now){unset($state['entries'][$id]);}}
        $state['seen']=$now;return $state;
    }
    public static function change(array $state,$result):Change
    {
        $expires=0;foreach($state['entries'] as $entry){$expires=max($expires,$entry['expires']);}
        return new Change($state['entries']?$state:null,$expires,$result);
    }
}
