<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

final class Codec
{
    public static function encode(Change $change): string
    {
        $json = json_encode(['expires' => $change->expiresAt, 'value' => $change->value]);
        if ($json === false || strlen($json) > 65536) {
            throw new StorageException('State cannot be encoded or exceeds 64 KiB.');
        }
        return $json;
    }

    public static function decode(string $json, int $now): ?array
    {
        if (strlen($json) > 65536) {
            throw new StorageException('State exceeds 64 KiB.');
        }
        $state = json_decode($json, true, 32);
        if (!is_array($state) || !isset($state['expires']) || !is_int($state['expires'])
            || $state['expires'] < 0 || !isset($state['value']) || !is_array($state['value'])) {
            throw new StorageException('Corrupt security state.');
        }
        return $state['expires'] !== 0 && $state['expires'] <= $now ? null : $state['value'];
    }
}
