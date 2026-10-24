<?php
declare(strict_types=1);
namespace SoSecurity\Mfa;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
/** Internal pure decoder. Expiry normalization changes only the returned value. */
final class TotpFactorState
{
    public static function read($state, int $now): ?array
    {
        if ($state === null) { return null; }
        if (!is_array($state) || !self::fields($state, ['v', 'enabled', 'pending', 'recovery', 'failures', 'blocked_until', 'updated'])
            || $state['v'] !== 1 || !is_array($state['recovery']) || count($state['recovery']) > 10
            || !is_int($state['failures']) || $state['failures'] < 0 || $state['failures'] > 10
            || !is_int($state['blocked_until']) || $state['blocked_until'] < 0 || !is_int($state['updated']) || $state['updated'] < 0) {
            throw new StorageException('Corrupt MFA state.', 'storage.corrupt');
        }
        if ($state['updated'] > $now) { throw new SecurityException('MFA clock moved backwards.', 'mfa.clock'); }
        foreach ($state['recovery'] as $digest) {
            if (!is_string($digest) || !preg_match('/\A[a-f0-9]{64}\z/D', $digest)) { throw new StorageException('Corrupt recovery codes.', 'storage.corrupt'); }
        }
        if (array_values($state['recovery']) !== $state['recovery'] || count(array_unique($state['recovery'])) !== count($state['recovery'])
            || ($state['enabled'] === null && $state['recovery'] !== [])) { throw new StorageException('Corrupt recovery state.', 'storage.corrupt'); }
        foreach (['enabled', 'pending'] as $field) {
            $factor = $state[$field];
            if ($factor === null) { continue; }
            $fields = ['id', 'secret', 'profile', 'last_step']; if ($field === 'pending') { $fields[] = 'expires'; }
            if (!is_array($factor) || !self::fields($factor, $fields) || !is_string($factor['id']) || !preg_match('/\A[a-f0-9]{32}\z/D', $factor['id'])
                || !is_string($factor['secret']) || strlen($factor['secret']) < 60 || strlen($factor['secret']) > 2048
                || !is_int($factor['last_step']) || $factor['last_step'] < -1 || !is_array($factor['profile'])
                || ($field === 'pending' && (!is_int($factor['expires']) || $factor['expires'] < 0))) {
                throw new StorageException('Corrupt MFA factor.', 'storage.corrupt');
            }
            self::profile($factor['profile']);
        }
        if ($state['pending'] !== null && $state['pending']['expires'] <= $now) { $state['pending'] = null; }
        if ($state['blocked_until'] !== 0 && $state['blocked_until'] <= $now) { $state['failures'] = 0; $state['blocked_until'] = 0; }
        return $state;
    }

    public static function profile(array $profile): Totp
    {
        if (!self::fields($profile, ['algorithm', 'digits', 'period']) || !is_string($profile['algorithm']) || !is_int($profile['digits']) || !is_int($profile['period'])) {
            throw new StorageException('Corrupt MFA profile.', 'storage.corrupt');
        }
        try { return new Totp($profile['algorithm'], $profile['digits'], $profile['period']); }
        catch (ConfigurationException $e) { throw new StorageException('Corrupt MFA profile.', 'storage.corrupt', $e); }
    }

    private static function fields(array $record,array $fields):bool{$keys=array_keys($record);sort($keys);sort($fields);return $keys===$fields;}
}
