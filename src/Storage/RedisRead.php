<?php
declare(strict_types=1);
namespace SoSecurity\Storage;

use SoSecurity\Exception\ConfigurationException;

/** Internal atomic bounded read. An oversized field is never sent to the PHP client. */
final class RedisRead
{
    private const READ = <<<'LUA'
local length = redis.pcall('STRLEN', KEYS[1])
if type(length) ~= 'number' then return {-2, ''} end
if length > tonumber(ARGV[1]) then return {-1, ''} end
local value = redis.pcall('GET', KEYS[1])
if type(value) == 'table' then return {-2, ''} end
if not value then return {0, ''} end
return {1, value}
LUA;

    /** @return string|false False is missing; an empty string is an existing value. */
    public static function value(\Redis $redis, string $key, int $maximum)
    {
        if ($maximum < 1 || $maximum > 65536 || strlen($key) > 512) { throw new ConfigurationException('Use a bounded internal Redis read.', 'configuration.redis_read'); }
        $reply = $redis->eval(self::READ, [$key, (string) $maximum], 1);
        if ($redis->getLastError() !== null || !is_array($reply) || array_keys($reply) !== [0, 1] || !is_int($reply[0]) || !is_string($reply[1])) {
            throw new StorageException('Unexpected bounded Redis reply.', 'storage.protocol');
        }
        if ($reply[0] === -1) { throw new StorageException('Redis value exceeds its byte budget.', 'storage.capacity'); }
        if ($reply[0] === 0 && $reply[1] === '') { return false; }
        if ($reply[0] === 1 && strlen($reply[1]) <= $maximum) { return $reply[1]; }
        throw new StorageException('Bounded Redis read failed.', 'storage.protocol');
    }
}
