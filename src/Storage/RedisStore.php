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
local identity = string.match(redis.call('INFO', 'server'), 'run_id:([a-f0-9]+)')
if identity ~= ARGV[7] then return -2 end
if redis.call('GET', KEYS[2]) ~= ARGV[6] then return -1 end
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
    private $epoch;

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
        $logicalKey = $key;
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
            $this->prepare($deadline, $originalTimeout);
            $server = $this->serverId();
            $this->prepare($deadline, $originalTimeout);
            $readyRaw = $this->redis->get($this->readyKey());
            $this->checkProtocol();
            if ($readyRaw === false) { throw new StorageException('Initialize Redis security storage explicitly before use.', 'storage.uninitialized'); }
            $ready = $this->decodeReady($readyRaw);
            if ($ready['server'] !== $server) { throw new StorageException('Redis restarted; reviewed recovery is required.', 'storage.restart'); }
            if ($this->epoch !== null && $this->epoch !== $ready['epoch']) { throw new StorageException('Storage epoch changed; rebuild the adapter.', 'storage.reinitialized'); }
            $this->epoch = $ready['epoch'];
            $key = 'sosecurity:' . $this->namespace . ':' . $ready['epoch'] . ':' . hash('sha256', $logicalKey);
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
                $result = $this->redis->eval(self::COMMIT, [$key, $this->readyKey(), $raw === false ? '0' : '1', $raw === false ? '' : $raw,
                    $change->value() === null ? 'delete' : 'set', $json, (string) $change->expiresAt(), $readyRaw, $server], 2);
                $this->checkProtocol();
                if ($result === -1) { throw new StorageException('Redis state changed during the operation.', 'storage.state_lost'); }
                if ($result === -2) { throw new StorageException('Redis restarted during the operation.', 'storage.restart'); }
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

    /** Deployment/maintenance action only. Never invoke automatically from a request or to ignore outages. */
    public function initialize(bool $recover = false): bool
    {
        if ($this->failed) { throw new StorageException('Reconnect and rebuild before initialization.', 'storage.connection'); }
        $deadline = new Deadline($this->budgetMs);
        $original = (float) $this->redis->getOption(\Redis::OPT_READ_TIMEOUT);
        $original = $original > 0 ? $original : max($this->budgetMs / 1000, (float) ini_get('default_socket_timeout'));
        try {
            $this->prepare($deadline, $original); $server = $this->serverId();
            $this->prepare($deadline, $original); $raw = $this->redis->get($this->readyKey()); $this->checkProtocol();
            if ($raw !== false) {
                $ready = $this->decodeReady($raw);
                if ($ready['server'] === $server) { return false; }
                if (!$recover) { throw new StorageException('Explicit reviewed restart recovery is required.', 'storage.restart'); }
            }
            $value = json_encode(['server' => $server, 'epoch' => bin2hex(random_bytes(32))]);
            $this->prepare($deadline, $original);
            $result = $this->redis->eval("if string.match(redis.call('INFO','server'),'run_id:([a-f0-9]+)')~=ARGV[4] then return -2 end; local v=redis.call('GET',KEYS[1]); local e=false; if ARGV[1]=='1' then e=ARGV[2] end; if v~=e then return 0 end; redis.call('SET',KEYS[1],ARGV[3]); return 1",
                [$this->readyKey(), $raw === false ? '0' : '1', $raw === false ? '' : $raw, $value, $server], 1);
            $this->checkProtocol();
            if ($result !== 1) { throw new StorageException('Initialization raced another operator; inspect and retry.', 'storage.contention'); }
            $this->epoch = null;
            return true;
        } catch (\RedisException $e) {
            $this->failed = true; $this->redis->close();
            throw new StorageException('Redis initialization failed.', 'storage.connection', $e);
        } finally {
            if (!$this->failed && $this->redis->isConnected()) { $this->redis->setOption(\Redis::OPT_READ_TIMEOUT, (string) $original); }
        }
    }
    private function readyKey(): string { return 'sosecurity:' . $this->namespace . ':ready'; }
    private function serverId(): string
    {
        $info = $this->redis->info('server'); $this->checkProtocol();
        if (!is_array($info) || !isset($info['run_id']) || !is_string($info['run_id']) || !preg_match('/^[a-f0-9]{40,128}$/D', $info['run_id'])) {
            throw new StorageException('Cannot inspect Redis process identity.', 'storage.identity');
        }
        return $info['run_id'];
    }
    private function decodeReady($raw): array
    {
        $ready = is_string($raw) && strlen($raw) <= 512 ? json_decode($raw, true, 4) : null;
        if (!is_array($ready) || !isset($ready['server'], $ready['epoch']) || !is_string($ready['server']) || !is_string($ready['epoch'])
            || !preg_match('/^[a-f0-9]{40,128}$/D', $ready['server']) || !preg_match('/^[a-f0-9]{64}$/D', $ready['epoch'])) {
            throw new StorageException('Corrupt Redis initialization state.', 'storage.corrupt');
        }
        return $ready;
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
