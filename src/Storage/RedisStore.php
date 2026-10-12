<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Use a dedicated connected phpredis connection; serializers and key prefixes must be disabled. */
final class RedisStore implements AtomicStore
{
    private $redis;
    private $namespace;
    private $clock;

    public function __construct(\Redis $redis, string $namespace, ?Clock $clock = null)
    {
        Guard::label($namespace);
        if ($redis->getOption(\Redis::OPT_SERIALIZER) !== \Redis::SERIALIZER_NONE
            || !in_array($redis->getOption(\Redis::OPT_PREFIX), ['', null], true)) {
            throw new StorageException('Use a dedicated Redis connection without serializer or prefix.');
        }
        $this->redis = $redis;
        $this->namespace = hash('sha256', $namespace);
        $this->clock = $clock ?? new SystemClock();
    }

    public function transact(string $key, callable $callback)
    {
        Guard::label($key);
        $key = 'sosecurity:' . $this->namespace . ':' . hash('sha256', $key);
        try {
            if (!$this->redis->isConnected()) {
                throw new StorageException('Redis connection is closed; reconnect explicitly before security operations.');
            }
            for ($attempt = 0; $attempt < 32; ++$attempt) {
                if (!$this->redis->watch($key)) {
                    throw new StorageException('Cannot watch Redis state.');
                }
                $this->redis->clearLastError();
                $raw = $this->redis->get($key);
                if ($raw === false && $this->redis->getLastError() !== null) {
                    throw new StorageException('Redis security record is unreadable.');
                }
                // GET false is ambiguous (missing key or protocol failure): require a successful PING.
                if ($raw === false && !$this->redis->ping()) {
                    throw new StorageException('Redis state unavailable.');
                }
                $value = $raw === false ? null : Codec::decode($raw, $this->clock->now());
                $change = $callback($value);
                if (!$change instanceof Change) {
                    throw new StorageException('Callback must return Change.');
                }
                $json = $change->value === null ? null : Codec::encode($change);
                if ($this->redis->multi() === false) {
                    throw new StorageException('Cannot start Redis transaction.');
                }
                if ($json === null) {
                    $this->redis->del($key);
                } else {
                    $this->redis->set($key, $json);
                    if ($change->expiresAt > 0) {
                        $this->redis->expireAt($key, $change->expiresAt);
                    }
                }
                $results = $this->redis->exec();
                if ($results !== false) {
                    foreach ($results as $result) {
                        if ($result === false) {
                            throw new StorageException('Redis security commit failed.');
                        }
                    }
                    return $change->result;
                }
            }
            throw new StorageException('Redis contention exceeded the retry budget.');
        } catch (\RedisException $e) {
            throw new StorageException('Redis security operation failed.', 0, $e);
        } finally {
            // Never retain WATCH/MULTI state after callback or transport exceptions.
            try {
                $this->redis->discard();
                $this->redis->unwatch();
            } catch (\RedisException $ignored) {
            }
        }
    }
}
