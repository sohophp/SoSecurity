<?php
declare(strict_types=1);
namespace SoSecurity\Concurrency;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** Internal bounded ledger validation; no clock reads, randomness, I/O or business side effects. */
final class LeaseState
{
    public static function context(string $scope, string $resource, int $now, ?string $owner = null): string
    {
        $key = Guard::key('leases', $scope, $resource);
        if (!preg_match('//u', $scope) || !preg_match('//u', $resource) || $now < 0 || $now > PHP_INT_MAX - 86400) { throw new ConfigurationException('Invalid lease context/clock.', 'configuration.lease'); }
        if ($owner !== null) { Guard::key('leases', $scope, $owner); if (!preg_match('//u', $owner)) { throw new ConfigurationException('Invalid lease owner.', 'configuration.lease'); } }
        return $key;
    }
    public static function fields(array $value, array $expected): bool { $keys = array_keys($value); sort($keys); sort($expected); return $keys === $expected; }
    public static function hex($value, int $length): bool { return is_string($value) && strlen($value) === $length && preg_match('/\A[a-f0-9]+\z/D', $value) === 1; }
    public static function token(string $token): ?array
    {
        if (strlen($token) !== 133 || !preg_match('/\Al1\.([a-f0-9]{32})\.([a-f0-9]{32})\.([a-f0-9]{64})\z/D', $token, $parts)) { return null; }
        return ['epoch' => $parts[1], 'id' => $parts[2], 'digest' => hash('sha256', $token)];
    }
    public static function read($state, LeasePolicy $policy, int $now): ?array
    {
        if ($state === null) { return null; }
        if (!is_array($state) || !self::fields($state, ['v','epoch','policy','sequence','seen','holders']) || $state['v'] !== 1 || !self::hex($state['epoch'], 32)
            || !self::hex($state['policy'], 64) || !is_int($state['sequence']) || $state['sequence'] < 0 || !is_int($state['seen']) || $state['seen'] < 0
            || $state['seen'] > PHP_INT_MAX - 86400 || !is_array($state['holders']) || count($state['holders']) > 64) { throw new StorageException('Corrupt lease ledger.', 'storage.corrupt'); }
        if (!hash_equals($policy->fingerprint(), $state['policy'])) { throw new StorageException('Lease policy changed; drain and migrate the ledger explicitly.', 'lease.policy_changed'); }
        if ($state['seen'] > $now) { throw new StorageException('Lease clock moved backwards.', 'lease.clock'); }
        if (count($state['holders']) > $policy->maximum()) { throw new StorageException('Corrupt lease capacity.', 'storage.corrupt'); }
        $fences = []; $owners = [];
        foreach ($state['holders'] as $id => $holder) {
            if (!self::hex($id, 32) || !is_array($holder) || !self::fields($holder, ['digest','owner','fence','issued','expires','absolute'])
                || !self::hex($holder['digest'], 64) || !self::hex($holder['owner'], 64) || !is_int($holder['fence']) || $holder['fence'] < 1 || $holder['fence'] > $state['sequence']
                || !is_int($holder['issued']) || $holder['issued'] < 0 || $holder['issued'] > $state['seen'] || !is_int($holder['expires']) || !is_int($holder['absolute'])
                || $holder['expires'] <= $holder['issued'] || $holder['absolute'] !== $holder['issued'] + $policy->maximumLifetime()
                || $holder['expires'] > $holder['absolute'] || $holder['expires'] > $state['seen'] + $policy->ttl()
                || isset($fences[$holder['fence']]) || isset($owners[$holder['owner']])) { throw new StorageException('Corrupt lease holder.', 'storage.corrupt'); }
            $fences[$holder['fence']] = true; $owners[$holder['owner']] = true;
        }
        return $state;
    }
    public static function prune(array $state, int $now): array
    {
        foreach ($state['holders'] as $id => $holder) { if ($holder['expires'] <= $now) { unset($state['holders'][$id]); } }
        $state['seen'] = $now; return $state;
    }
    public static function owner(string $scope, string $resource, string $owner): string { return hash('sha256', json_encode([$scope, $resource, $owner])); }
    public static function holder(array $state, array $reference, string $owner): ?array
    {
        if (!hash_equals($state['epoch'], $reference['epoch'])) { return null; }
        $holder = $state['holders'][$reference['id']] ?? null;
        return $holder !== null && hash_equals($holder['owner'], $owner) && hash_equals($holder['digest'], $reference['digest']) ? $holder : null;
    }
    public static function finish(int $started, int $now, ?Lease $lease = null): void
    {
        if ($now < $started) { throw new StorageException('Lease clock moved backwards during storage I/O.', 'lease.clock'); }
        if ($lease !== null && $lease->expiresAt() <= $now) { throw new StorageException('Lease expired during storage I/O; do not start or continue work.', 'lease.expired'); }
    }
}
