<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;

/** Internal shared ledger format. Migrate validated v1 records in the same atomic write that uses them. */
final class RegistryState
{
    public static function empty(string $epoch, int $now): array { return ['v' => 2, 'epoch' => $epoch, 'sessions' => [], 'remember' => [], 'updated' => $now]; }

    public static function read($state, int $now, int $idle, int $absolute): ?array
    {
        if ($state === null) { return null; }
        if (!is_array($state) || !isset($state['v']) || !in_array($state['v'], [1, 2], true)
            || !self::fields($state, $state['v'] === 1 ? ['v', 'epoch', 'sessions', 'updated'] : ['v', 'epoch', 'sessions', 'remember', 'updated'])
            || !self::hex($state['epoch'], 64) || !is_array($state['sessions']) || count($state['sessions']) > 32
            || !is_int($state['updated']) || $state['updated'] < 0) { throw new StorageException('Corrupt session registry.', 'storage.corrupt'); }
        if ($state['updated'] > $now) { throw new SecurityException('Session registry clock moved backwards.', 'auth.clock'); }
        $legacy = $state['v'] === 1;
        if ($legacy) { $state['remember'] = []; }
        if (!is_array($state['remember']) || count($state['remember']) > 16) { throw new StorageException('Corrupt persistent grants.', 'storage.corrupt'); }
        foreach ($state['remember'] as $id => $grant) {
            self::grant($id, $grant, $state['epoch'], $now);
            if ($grant['expires'] <= $now) { unset($state['remember'][$id]); }
        }
        foreach ($state['sessions'] as $id => $record) {
            $fields = ['digest', 'fingerprint', 'method', 'created', 'seen', 'expires', 'authenticated', 'idle', 'label'];
            if (!$legacy) { $fields = array_merge($fields, ['resumed', 'grant']); }
            if (!self::hex($id, 32) || !is_array($record) || !self::fields($record, $fields)
                || !self::hex($record['digest'], 64) || !self::hex($record['fingerprint'], 64)
                || !is_string($record['method']) || !in_array($record['method'], ['remembered', 'password', 'totp', 'recovery', 'webauthn'], true)
                || !self::label($record['label'])) { throw new StorageException('Corrupt registered session.', 'storage.corrupt'); }
            foreach (['created', 'seen', 'expires', 'authenticated', 'idle'] as $field) {
                if (!is_int($record[$field]) || $record[$field] < 0) { throw new StorageException('Corrupt session deadline.', 'storage.corrupt'); }
            }
            if ($record['created'] > $record['seen'] || $record['authenticated'] > $record['seen'] || $record['seen'] >= $record['expires']
                || $record['expires'] - $record['created'] > 31536000 || $record['idle'] < 1 || $record['idle'] > 31536000) {
                throw new StorageException('Corrupt session lifetime.', 'storage.corrupt');
            }
            if ($record['seen'] > $now) { throw new SecurityException('Session clock moved backwards.', 'auth.clock'); }
            if ($legacy) { $record['resumed'] = false; $record['grant'] = null; }
            if (!is_bool($record['resumed']) || ($record['grant'] !== null && !self::hex($record['grant'], 32))
                || ($record['resumed'] && ($record['authenticated'] === 0 || $record['method'] === 'remembered' || $record['grant'] === null))) {
                throw new StorageException('Corrupt resumed-session provenance.', 'storage.corrupt');
            }
            if ($record['grant'] !== null) {
                $grant = $state['remember'][$record['grant']] ?? null;
                if ($grant === null) {
                    if ($record['resumed']) { unset($state['sessions'][$id]); continue; }
                    $record['grant'] = null; // Expiring persistence does not invalidate a separately proven fresh session.
                } elseif ($grant['session_id'] !== $id || $grant['fingerprint'] !== $record['fingerprint']
                    || ($record['resumed'] && ($record['authenticated'] !== $grant['authenticated'] || $record['method'] !== $grant['method'] || $record['expires'] > $grant['expires']))) {
                    throw new StorageException('Persistent grant/session linkage is corrupt.', 'storage.corrupt');
                }
            }
            if ($record['expires'] <= $now || $now - $record['seen'] >= min($record['idle'], $idle) || $now - $record['created'] >= $absolute) {
                unset($state['sessions'][$id]);
            } else { $state['sessions'][$id] = $record; }
        }
        $state['v'] = 2;
        return $state;
    }

    private static function grant($id, $grant, string $epoch, int $now): void
    {
        $fields = ['fingerprint', 'epoch', 'digest', 'generation', 'created', 'authenticated', 'expires', 'method', 'session_id', 'label', 'rotated', 'recent'];
        if (!self::hex($id, 32) || !is_array($grant) || !self::fields($grant, $fields)
            || !self::hex($grant['fingerprint'], 64) || !self::hex($grant['epoch'], 64) || $grant['epoch'] !== $epoch
            || !self::hex($grant['digest'], 64) || !self::hex($grant['session_id'], 32) || !self::label($grant['label'])
            || !is_string($grant['method']) || !in_array($grant['method'], ['password', 'totp', 'recovery', 'webauthn'], true)
            || !is_array($grant['recent']) || count($grant['recent']) > 8) { throw new StorageException('Corrupt persistent grant.', 'storage.corrupt'); }
        foreach (['generation', 'created', 'authenticated', 'expires', 'rotated'] as $field) {
            if (!is_int($grant[$field]) || $grant[$field] < 0) { throw new StorageException('Corrupt persistent-grant budget.', 'storage.corrupt'); }
        }
        if ($grant['generation'] > 2147483647 || $grant['authenticated'] < 1 || $grant['authenticated'] > $grant['created']
            || $grant['expires'] <= $grant['created'] || $grant['expires'] - $grant['authenticated'] > 31536000
            || $grant['rotated'] < $grant['created'] || $grant['rotated'] >= $grant['expires'] || $grant['rotated'] > $now || array_values($grant['recent']) !== $grant['recent']) {
            throw new StorageException('Corrupt persistent-grant lifetime.', 'storage.corrupt');
        }
        $last = -1;
        foreach ($grant['recent'] as $entry) {
            if (!is_array($entry) || !self::fields($entry, ['generation', 'until']) || !is_int($entry['generation']) || !is_int($entry['until'])
                || $entry['generation'] <= $last || $entry['generation'] >= $grant['generation'] || $entry['until'] < $grant['created']
                || $entry['until'] > $grant['expires'] || $entry['until'] > $grant['rotated'] + 10) {
                throw new StorageException('Corrupt concurrent-rotation window.', 'storage.corrupt');
            }
            $last = $entry['generation'];
        }
    }

    public static function removeGrant(array $state, string $id): array
    {
        unset($state['remember'][$id]);
        foreach ($state['sessions'] as $sessionId => $record) { if ($record['grant'] === $id) { unset($state['sessions'][$sessionId]); } }
        return $state;
    }
    public static function forIdentity(array $state, string $fingerprint): array
    {
        foreach ($state['remember'] as $id => $grant) { if (!hash_equals($grant['fingerprint'], $fingerprint)) { $state = self::removeGrant($state, $id); } }
        foreach ($state['sessions'] as $id => $record) { if (!hash_equals($record['fingerprint'], $fingerprint)) { unset($state['sessions'][$id]); } }
        return $state;
    }
    public static function change(?array $state, int $now, $result): Change
    {
        if ($state !== null) { $state['updated'] = $now; }
        return new Change($state, 0, $result);
    }
    private static function fields(array $value, array $fields): bool { $keys = array_keys($value); sort($keys); sort($fields); return $keys === $fields; }
    private static function hex($value, int $length): bool { return is_string($value) && strlen($value) === $length && preg_match('/\A[a-f0-9]+\z/D', $value) === 1; }
    private static function label($value): bool { return is_string($value) && strlen($value) <= 128 && preg_match('//u', $value) === 1 && !preg_match('/[\x00-\x1f\x7f]/', $value); }
}
