<?php
declare(strict_types=1);
namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Dedicated phpredis connection; raw strings, no prefix/serializer or host transactions. */
final class RedisStore implements AtomicStore
{
    // GET inside the same atomic script includes expiry. WATCH on Redis <6.0.9 does not.
    private const COMMIT = <<<'LUA'
local current = redis.call('GET', KEYS[1])
local expected = false
if ARGV[1] == '1' then expected = ARGV[2] end
if current ~= expected then return 0 end
if ARGV[3] == 'delete' then
    redis.call('DEL', KEYS[1])
else
    redis.call('SET', KEYS[1], ARGV[4])
    if ARGV[5] ~= '0' then redis.call('EXPIREAT', KEYS[1], ARGV[5]) end
end
return 1
LUA;
    private $redis;
    private $namespace;
    private $clock;
    private $budgetMs;
    private $attempts;
    private $failed = false;

    public function __construct(\Redis $redis, string $namespace, ?Clock $clock = null, int $budgetMs = 1000, int $attempts = 32)
    {
        Guard::label($namespace);
        new Deadline($budgetMs);
        if ($attempts < 1 || $attempts > 128) {
            throw new \SoSecurity\Exception\ConfigurationException('Redis attempts must be 1-128.');
        }
        try {
            if (!$redis->isConnected()) { throw new StorageException('Use a connected Redis client.', 'storage.connection'); }
            if ($redis->getOption(\Redis::OPT_SERIALIZER) !== \Redis::SERIALIZER_NONE
                || !in_array($redis->getOption(\Redis::OPT_PREFIX), ['', null], true)) {
                throw new \SoSecurity\Exception\ConfigurationException('Use Redis without serializer or prefix.');
            }
        } catch (\RedisException $e) {
            throw new StorageException('Cannot inspect Redis connection.', 'storage.connection', $e);
        }
        $this->redis = $redis;
        $this->namespace = hash('sha256', $namespace);
        $this->clock = $clock ?? new SystemClock();
        $this->budgetMs = $budgetMs;
        $this->attempts = $attempts;
    }

    public function transact(string $key, callable $callback)
    {
        Guard::label($key);
        $key = 'sosecurity:' . $this->namespace . ':' . hash('sha256', $key);
        $deadline = new Deadline($this->budgetMs);
        if ($this->failed) { throw new StorageException('Rebuild the adapter after explicitly reconnecting its failed client.', 'storage.connection'); }
        $originalTimeout = null;
        $restoreAllowed = true;
        try {
            if (!$this->redis->isConnected()) { throw new StorageException('Redis connection is closed.', 'storage.connection'); }
            if ($this->redis->getOption(\Redis::OPT_SERIALIZER) !== \Redis::SERIALIZER_NONE
                || !in_array($this->redis->getOption(\Redis::OPT_PREFIX), ['', null], true)) {
                throw new StorageException('Redis options changed after adapter creation.', 'storage.configuration');
            }
            $originalTimeout = (float) $this->redis->getOption(\Redis::OPT_READ_TIMEOUT);
            // phpredis 4.x's default 0 uses PHP's socket default at connect, but SET 0 creates an immediate timeout.
            if ($originalTimeout <= 0) {
                $default = (float) ini_get('default_socket_timeout');
                $originalTimeout = $default > 0 ? $default : $this->budgetMs / 1000;
            }
            for ($attempt = 0; $attempt < $this->attempts; ++$attempt) {
                $this->prepare($deadline, $originalTimeout);
                $raw = $this->redis->get($key);
                $this->checkProtocol();
                if ($raw !== false && !is_string($raw)) {
                    throw new StorageException('Unexpected Redis response or active host transaction.', 'storage.protocol');
                }
                if ($raw === false) {
                    $this->prepare($deadline, $originalTimeout);
                    if (!$this->redis->ping()) { throw new StorageException('Redis unavailable.', 'storage.connection'); }
                    $this->checkProtocol();
                }
                $value = $raw === false ? null : Codec::decode($raw, $this->clock->now());
                $change = $callback($value);
                if (!$change instanceof Change) { throw new StorageException('Callback must return Change.', 'storage.contract'); }
                $json = $change->value() === null ? '' : Codec::encode($change);
                $this->prepare($deadline, $originalTimeout);
                $result = $this->redis->eval(self::COMMIT, [$key, $raw === false ? '0' : '1', $raw === false ? '' : $raw,
                    $change->value() === null ? 'delete' : 'set', $json, (string) $change->expiresAt()], 1);
                $this->checkProtocol();
                if ($result === 1) { return $change->result(); }
                if ($result !== 0) { throw new StorageException('Redis commit failed.', 'storage.commit'); }
            }
            throw new StorageException('Redis contention exhausted the retry count.', 'storage.contention');
        } catch (\RedisException $e) {
            // A transport failure can mean the server committed but its reply was lost. Never retry that as success.
            $restoreAllowed = false;
            $this->failed = true;
            $this->redis->close();
            throw new StorageException('Redis security operation failed.', $deadline->remaining() <= 0 ? 'storage.timeout' : 'storage.connection', $e);
        } finally {
            if ($restoreAllowed && $originalTimeout !== null && $this->redis->isConnected()) {
                $this->redis->setOption(\Redis::OPT_READ_TIMEOUT, (string) $originalTimeout);
            }
        }
    }

    private function prepare(Deadline $deadline, float $originalTimeout): void
    {
        $deadline->check();
        $remaining = $deadline->remaining();
        $timeout = $originalTimeout > 0 ? min($originalTimeout, $remaining) : $remaining;
        if (!$this->redis->setOption(\Redis::OPT_READ_TIMEOUT, sprintf('%.6f', max(0.000001, $timeout)))) {
            throw new StorageException('Cannot bound Redis socket waiting.', 'storage.timeout');
        }
        $this->redis->clearLastError();
    }
    private function checkProtocol(): void
    {
        if ($this->redis->getLastError() !== null) { throw new StorageException('Redis command failed.', 'storage.protocol'); }
    }
}
