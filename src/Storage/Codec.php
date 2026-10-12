<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

final class Codec
{
    public static function encode(Change $change): string
    {
        $nodes = 0;
        self::validate($change->value(), 0, $nodes);
        $json = json_encode(['expires' => $change->expiresAt(), 'value' => $change->value()]);
        if ($json === false || strlen($json) > 65536) {
            throw new StorageException('State cannot be encoded or exceeds 64 KiB.', 'storage.encoding');
        }
        return $json;
    }

    public static function decode(string $json, int $now): ?array
    {
        if (strlen($json) > 65536) {
            throw new StorageException('State exceeds 64 KiB.', 'storage.capacity');
        }
        $state = json_decode($json, true, 32);
        if (!is_array($state) || !isset($state['expires']) || !is_int($state['expires'])
            || $state['expires'] < 0 || !isset($state['value']) || !is_array($state['value'])) {
            throw new StorageException('Corrupt security state.', 'storage.corrupt');
        }
        return $state['expires'] !== 0 && $state['expires'] <= $now ? null : $state['value'];
    }
    private static function validate($value, int $depth, int &$nodes): void
    {
        if (++$nodes > 8192 || $depth > 30) { throw new StorageException('State complexity exceeds the encoding budget.', 'storage.capacity'); }
        if (is_array($value)) {
            foreach ($value as $item) { self::validate($item, $depth + 1, $nodes); }
        } elseif (!is_null($value) && !is_bool($value) && !is_int($value) && !is_float($value) && !is_string($value)) {
            throw new StorageException('State must contain JSON primitives; object hooks are forbidden.', 'storage.encoding');
        }
    }
}
