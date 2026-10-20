<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** Internal bounded v1 ledger; all callbacks use captured time and immutable facts. */
final class State
{
    public static function hex($value,int $length): bool { return is_string($value) && strlen($value) === $length && preg_match('/\A[a-f0-9]+\z/D',$value) === 1; }
    public static function context(string $scope,string $subject,int $now): string
    {
        $key = Guard::key('operations',$scope,$subject);
        if (!preg_match('//u',$scope) || !preg_match('//u',$subject) || $now < 0 || $now > PHP_INT_MAX-86400) { throw new ConfigurationException('Invalid operation context/clock.','configuration.operation'); }
        return $key;
    }
    public static function reference(string $token,string $prefix): ?array
    {
        if (!in_array($prefix,['oc1','og1'],true) || strlen($token) !== 101 || !preg_match('/\A' . $prefix . '\.([a-f0-9]{32})\.([a-f0-9]{64})\z/D',$token,$parts)) { return null; }
        return ['id'=>$parts[1],'digest'=>hash('sha256',$token)];
    }
    private static function fields(array $value,array $expected): bool { $keys=array_keys($value);sort($keys);sort($expected);return $keys===$expected; }
    public static function read($state,Policy $policy,int $now): ?array
    {
        if ($state === null) { return null; }
        if (!is_array($state) || !self::fields($state,['v','policy','seen','entries']) || $state['v'] !== 1 || !self::hex($state['policy'],64)
            || !is_int($state['seen']) || $state['seen'] < 0 || $state['seen'] > PHP_INT_MAX-86400 || !is_array($state['entries']) || count($state['entries']) > 16) { throw new StorageException('Corrupt operation ledger.','storage.corrupt'); }
        if (!hash_equals($policy->fingerprint(),$state['policy'])) { throw new StorageException('Active operation policy changed; migrate the scope explicitly.','operation.policy_changed'); }
        if ($state['seen'] > $now) { throw new StorageException('Operation clock moved backwards.','operation.clock'); }
        if (count($state['entries']) > $policy->capacity()) { throw new StorageException('Corrupt operation capacity.','storage.corrupt'); }
        foreach ($state['entries'] as $id=>$entry) {
            if (!self::hex($id,32) || !is_array($entry) || !self::fields($entry,['phase','digest','intent','account','session','created','session_digest','issued','expires','authenticated','method'])
                || !in_array($entry['phase'],['pending','granted'],true) || !self::hex($entry['digest'],64) || !self::hex($entry['intent'],64) || !self::hex($entry['account'],64)
                || !self::hex($entry['session'],32) || !self::hex($entry['session_digest'],64) || !is_int($entry['created']) || $entry['created'] < 0
                || !is_int($entry['issued']) || $entry['issued'] < $entry['created'] || $entry['issued'] > $state['seen'] || !is_int($entry['expires']) || $entry['expires'] <= $entry['issued']
                || $entry['expires'] > $entry['issued']+$policy->ttl() || !is_int($entry['authenticated']) || $entry['authenticated'] < 0 || $entry['authenticated'] > $state['seen']
                || !in_array($entry['method'],['remembered','password','totp','recovery','webauthn'],true)
                || ($entry['method'] === 'remembered' ? $entry['authenticated'] !== 0 : $entry['authenticated'] < $entry['created'])) { throw new StorageException('Corrupt operation entry.','storage.corrupt'); }
            if ($entry['phase'] === 'pending' && $entry['authenticated'] > $entry['issued']) { throw new StorageException('Corrupt pending operation proof.','storage.corrupt'); }
            if ($entry['phase'] === 'granted' && (!in_array($entry['method'],$policy->methods(),true) || $entry['authenticated'] < $entry['issued']
                || $entry['expires'] > $entry['authenticated']+$policy->maximumAge())) { throw new StorageException('Corrupt approved operation proof.','storage.corrupt'); }
        }
        return $state;
    }
    public static function prepare(?array $state,Policy $policy,int $now): array
    {
        $state = $state ?? ['v'=>1,'policy'=>$policy->fingerprint(),'seen'=>$now,'entries'=>[]];
        foreach ($state['entries'] as $id=>$entry) { if ($entry['expires'] <= $now) { unset($state['entries'][$id]); } }
        $state['seen']=$now;return $state;
    }
    public static function change(array $state,$result): Change
    {
        $expires=0; foreach ($state['entries'] as $entry) { $expires=max($expires,$entry['expires']); }
        return new Change($state['entries'] ? $state : null,$expires,$result);
    }
    public static function matches(array $entry,array $facts): bool
    {
        return hash_equals($entry['account'],$facts['account']) && hash_equals($entry['session'],$facts['session']) && $entry['created']===$facts['created'];
    }
}
