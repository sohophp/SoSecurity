<?php
declare(strict_types=1);
namespace SoSecurity\Diagnostics;

use SoSecurity\Configuration\Config;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Storage\NamespacedStore;

/** Diagnostic results never contain connection objects, passwords, tokens, raw exception text or filesystem paths. */
final class Inspector
{
    public function inspect(Config $config, array $services = [], ?string $documentRoot = null, bool $probe = false): array
    {
        $checks = [['check' => 'configuration', 'status' => 'pass', 'reason' => 'configuration.valid']];
        foreach (['session', 'gd', 'curl', 'redis'] as $extension) {
            $checks[] = ['check' => 'extension.' . $extension, 'status' => extension_loaded($extension) ? 'pass' : 'optional',
                'reason' => extension_loaded($extension) ? 'dependency.available' : 'dependency.not_installed'];
        }
        foreach (['shared' => $config->storage(), 'tokens' => $config->tokenStorage()] as $kind => $options) {
            $name = 'storage.' . $kind;
            if ($options === null) { $checks[] = ['check' => $name, 'status' => 'not_configured', 'reason' => 'configuration.missing_store']; continue; }
            if ($options['driver'] === 'file') {
                $path = realpath($options['directory']);
                $valid = $path !== false && is_dir($path) && is_writable($path) && (fileperms($path) & 0077) === 0;
                $checks[] = ['check' => $name, 'status' => $valid ? 'pass' : 'fail', 'reason' => $valid ? 'storage.private_directory' : 'storage.directory'];
                $root = $documentRoot === null ? false : realpath($documentRoot);
                $public = $path !== false && $root !== false && ($path === $root || strpos($path, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0);
                $checks[] = ['check' => $name . '.location', 'status' => $public ? 'fail' : ($root === false ? 'manual' : 'pass'),
                    'reason' => $public ? 'storage.web_root' : ($root === false ? 'storage.location_unverified' : 'storage.outside_web_root')];
            } elseif ($options['driver'] === 'session') {
                $active = extension_loaded('session') && session_status() === PHP_SESSION_ACTIVE;
                $checks[] = ['check' => $name, 'status' => $kind === 'shared' ? 'fail' : ($active ? 'pass' : 'manual'),
                    'reason' => $kind === 'shared' ? 'storage.not_shared' : ($active ? 'session.active' : 'session.host_must_start')];
                $checks[] = ['check' => $name . '.locking', 'status' => $active && ini_get('session.save_handler') === 'files' ? 'pass' : 'manual',
                    'reason' => $active && ini_get('session.save_handler') === 'files' ? 'session.native_files_lock' : 'session.locking_unverified'];
            } elseif ($options['driver'] === 'memory') {
                $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'storage.test_only'];
            } elseif ($options['driver'] === 'provided') {
                $store = $services[$options['connection']] ?? null;
                while ($store instanceof NamespacedStore) { $store = $store->underlying(); }
                $unsafe = $store instanceof MemoryStore || ($kind === 'shared' && $store instanceof SessionStore);
                $valid = $store instanceof \SoSecurity\Storage\AtomicStore;
                $checks[] = ['check' => $name, 'status' => $unsafe || !$valid ? 'fail' : 'manual',
                    'reason' => $unsafe ? 'storage.not_shared' : (!$valid ? 'configuration.connection' : 'storage.custom_contract_unverified')];
            } else {
                $redis = $services[$options['connection']] ?? null;
                if (!$redis instanceof \Redis) { $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'configuration.connection']; continue; }
                if (!$probe) { $checks[] = ['check' => $name, 'status' => 'manual', 'reason' => 'storage.connection_unverified']; continue; }
                foreach ($this->redis($redis) as $item) { $item['check'] = $name . '.' . $item['check']; $checks[] = $item; }
            }
        }
        return $checks;
    }
    private function redis(\Redis $redis): array
    {
        $timeout = null; $healthy = true;
        try {
            if (!$redis->isConnected()) { return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']]; }
            if ($redis->getOption(\Redis::OPT_SERIALIZER) !== \Redis::SERIALIZER_NONE
                || !in_array($redis->getOption(\Redis::OPT_PREFIX), ['', null], true)) {
                return [['check' => 'options', 'status' => 'fail', 'reason' => 'storage.configuration']];
            }
            $timeout = (float) $redis->getOption(\Redis::OPT_READ_TIMEOUT);
            $timeout = $timeout > 0 ? $timeout : max(.2, (float) ini_get('default_socket_timeout'));
            $redis->setOption(\Redis::OPT_READ_TIMEOUT, '0.200000');
            if (!$redis->ping()) { return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']]; }
            $redis->clearLastError();
            $policy = $redis->config('GET', 'maxmemory-policy');
            $name = is_array($policy) ? ($policy['maxmemory-policy'] ?? null) : null;
            $result = [['check' => 'connection', 'status' => 'pass', 'reason' => 'storage.connected'],
                ['check' => 'eviction', 'status' => $name === null ? 'manual' : ($name === 'noeviction' ? 'pass' : 'fail'),
                    'reason' => $name === null ? 'storage.eviction_unverified' : ($name === 'noeviction' ? 'storage.noeviction' : 'storage.unsafe_eviction')]];
            $redis->clearLastError();
            $lua = $redis->eval('return 1', [], 0);
            $result[] = ['check' => 'cas_permission', 'status' => $lua === 1 ? 'pass' : 'fail', 'reason' => $lua === 1 ? 'storage.lua_available' : 'storage.lua_unavailable'];
            return $result;
        } catch (\RedisException $e) {
            $healthy = false; $redis->close();
            return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']];
        } finally {
            if ($healthy && $timeout !== null && $redis->isConnected()) { $redis->setOption(\Redis::OPT_READ_TIMEOUT, (string) $timeout); }
        }
    }
}
