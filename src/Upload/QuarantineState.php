<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** Internal pure, bounded quarantine ledger validation. */
final class QuarantineState
{
    public static function options(array $values): array
    {
        $defaults = ['maximum_entries' => 64, 'maximum_total_bytes' => 67108864, 'maximum_attempts' => 3, 'lease_seconds' => 60,
            'retry_seconds' => 60, 'lifetime_seconds' => 86400, 'scan_milliseconds' => 30000];
        $limits = ['maximum_entries' => [1, 64], 'maximum_total_bytes' => [1, 1073741824], 'maximum_attempts' => [1, 10], 'lease_seconds' => [2, 300],
            'retry_seconds' => [1, 86400], 'lifetime_seconds' => [60, 2592000], 'scan_milliseconds' => [1, 30000]];
        if (array_diff(array_keys($values), array_keys($defaults))) { throw new ConfigurationException('Unknown quarantine option.', 'configuration.quarantine'); }
        $values += $defaults; $result = [];
        foreach ($defaults as $name => $unused) {
            if (!is_int($values[$name]) || $values[$name] < $limits[$name][0] || $values[$name] > $limits[$name][1]) {
                throw new ConfigurationException('Invalid quarantine limit.', 'configuration.quarantine');
            }
            $result[$name] = $values[$name];
        }
        if ($result['lease_seconds'] * 1000 <= $result['scan_milliseconds']) { throw new ConfigurationException('Scan budget must fit inside its lease.', 'configuration.quarantine'); }
        return $result;
    }
    public static function id(string $id): void
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $id)) { throw new ConfigurationException('Expected a quarantine identifier.', 'configuration.quarantine'); }
    }
    /** Validator canonicalizes accepted .jpeg sources to stored .jpg snapshots. */
    public static function mime(Policy $policy, string $extension): ?string
    {
        if ($extension === 'jpeg') { return null; }
        return $extension === 'jpg' ? ($policy->mime('jpg') ?? $policy->mime('jpeg')) : $policy->mime($extension);
    }
    public static function read(?array $value, string $fingerprint, Policy $policy, array $options, int $now): array
    {
        if ($value === null) { return ['v' => 1, 'policy' => $fingerprint, 'seen' => $now, 'entries' => []]; }
        self::keys($value, ['v', 'policy', 'seen', 'entries']);
        if ($value['v'] !== 1 || $value['policy'] !== $fingerprint || !is_int($value['seen']) || $value['seen'] < 0
            || $value['seen'] > $now || !is_array($value['entries']) || count($value['entries']) > $options['maximum_entries']) { self::corrupt(); }
        $entries = []; $total = 0;
        foreach ($value['entries'] as $id => $entry) {
            if (!is_string($id) || !preg_match('/\A[a-f0-9]{32}\z/D', $id) || !is_array($entry)) { self::corrupt(); }
            self::keys($entry, ['file', 'state', 'attempts', 'generation', 'created', 'expires', 'lease', 'token', 'retry', 'error']);
            if (!is_array($entry['file'])) { self::corrupt(); }
            $file = $entry['file']; self::keys($file, ['extension', 'mime', 'bytes', 'source_bytes', 'sha256', 'width', 'height']);
            if (!is_string($file['extension']) || self::mime($policy, $file['extension']) === null || $file['mime'] !== self::mime($policy, $file['extension'])
                || !is_int($file['bytes']) || $file['bytes'] < 1 || $file['bytes'] > $policy->maximumBytes()
                || !is_int($file['source_bytes']) || $file['source_bytes'] < 1 || $file['source_bytes'] > $policy->maximumBytes()
                || !is_string($file['sha256']) || !preg_match('/\A[a-f0-9]{64}\z/D', $file['sha256'])) { self::corrupt(); }
            $total += $file['bytes']; if ($total > $options['maximum_total_bytes']) { self::corrupt(); }
            if (strpos($file['mime'], 'image/') === 0) {
                if (!is_int($file['width']) || !is_int($file['height']) || $file['width'] < 1 || $file['height'] < 1
                    || $file['width'] > $policy->maximumWidth() || $file['height'] > $policy->maximumHeight()
                    || $file['width'] * $file['height'] > $policy->maximumPixels()) { self::corrupt(); }
            } elseif ($file['width'] !== null || $file['height'] !== null) { self::corrupt(); }
            if (!in_array($entry['state'], ['staging', 'pending', 'scanning', 'retry', 'available', 'rejected', 'failed', 'deleting'], true)
                || !is_int($entry['attempts']) || $entry['attempts'] < 0 || $entry['attempts'] > $options['maximum_attempts']
                || !is_int($entry['generation']) || $entry['generation'] < 1
                || !is_int($entry['created']) || $entry['created'] < 0 || $entry['created'] > $value['seen']
                || !is_int($entry['expires']) || $entry['expires'] !== $entry['created'] + $options['lifetime_seconds']
                || !is_int($entry['lease']) || $entry['lease'] < 0 || !is_int($entry['retry']) || $entry['retry'] < 0
                || !is_string($entry['token']) || !in_array($entry['error'], [null, 'scan.failed', 'scan.timeout', 'content.invalid', 'attempts.exhausted', 'admin.rejected'], true)) { self::corrupt(); }
            if ($entry['state'] === 'scanning') {
                if ($entry['attempts'] === 0 || $entry['lease'] < $entry['created'] || !preg_match('/\A[a-f0-9]{64}\z/D', $entry['token'])) { self::corrupt(); }
            } elseif ($entry['lease'] !== 0 || $entry['token'] !== '') { self::corrupt(); }
            if (($entry['state'] !== 'retry' && $entry['retry'] !== 0) || ($entry['state'] === 'available' && ($entry['attempts'] === 0 || $entry['error'] !== null))) { self::corrupt(); }
            // Detach all references without calling object hooks (the shape above is scalar-only).
            $copy = [];
            foreach ($entry as $name => $item) {
                if ($name === 'file') { $copy[$name] = []; foreach ($file as $field => $scalar) { $copy[$name][$field] = $scalar; } }
                else { $copy[$name] = $item; }
            }
            $entries[$id] = $copy;
        }
        return ['v' => 1, 'policy' => $fingerprint, 'seen' => $now, 'entries' => $entries];
    }
    public static function advance(array $entry): array
    {
        if ($entry['generation'] === PHP_INT_MAX) { throw new StorageException('Quarantine generation exhausted.', 'upload.quarantine_capacity'); }
        ++$entry['generation']; $entry['lease'] = 0; $entry['token'] = ''; $entry['retry'] = 0; return $entry;
    }
    public static function status(string $id, array $entry, int $now): QuarantineStatus
    {
        return new QuarantineStatus(['id' => $id, 'state' => $entry['expires'] <= $now ? 'expired' : $entry['state'],
            'attempts' => $entry['attempts'], 'generation' => $entry['generation'],
            'retry_at' => $entry['state'] === 'scanning' ? $entry['lease'] : $entry['retry'], 'expires_at' => $entry['expires'], 'error' => $entry['error']]);
    }
    private static function keys(array $value, array $fields): void
    {
        if (count($value) !== count($fields) || array_diff(array_keys($value), $fields)) { self::corrupt(); }
    }
    private static function corrupt(): void { throw new StorageException('Quarantine state is invalid or its policy changed.', 'upload.quarantine_corrupt'); }
}
