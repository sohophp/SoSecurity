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
        foreach (['session', 'gd', 'curl', 'redis', 'pdo_mysql', 'fileinfo'] as $extension) {
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
            } elseif ($options['driver'] === 'mysql') {
                $pdo = $services[$options['connection']] ?? null;
                if (!$pdo instanceof \PDO || $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) !== 'mysql') {
                    $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'configuration.connection']; continue;
                }
                if (!$probe) { $checks[] = ['check' => $name, 'status' => 'manual', 'reason' => 'storage.connection_unverified']; continue; }
                try {
                    new \SoSecurity\Storage\MySqlStore($pdo, $config->site() . ':' . $kind, null, $options['lock_wait_seconds'] ?? 1);
                    $checks[] = ['check' => $name, 'status' => 'pass', 'reason' => 'storage.schema_verified'];
                    $checks[] = ['check' => $name . '.network_timeout', 'status' => 'manual', 'reason' => 'storage.transport_timeout_unverified'];
                } catch (\SoSecurity\Exception\SecurityException $e) {
                    $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => $e->reason()];
                } catch (\SoSecurity\Exception\ConfigurationException $e) {
                    $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => $e->reason()];
                }
            } else {
                $redis = $services[$options['connection']] ?? null;
                if (!$redis instanceof \Redis) { $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'configuration.connection']; continue; }
                if (!$probe) { $checks[] = ['check' => $name, 'status' => 'manual', 'reason' => 'storage.connection_unverified']; continue; }
                foreach ($this->redis($redis, $config->site() . ':' . $kind) as $item) { $item['check'] = $name . '.' . $item['check']; $checks[] = $item; }
            }
        }
        $upload = $config->upload();
        if ($upload === null) { $checks[] = ['check' => 'upload', 'status' => 'not_configured', 'reason' => 'configuration.upload']; }
        else {
            $needsImage = count(array_intersect($upload['extensions'], ['jpg', 'jpeg', 'png', 'webp'])) > 0;
            $ready = extension_loaded('fileinfo') && (!$needsImage || extension_loaded('gd'));
            $checks[] = ['check' => 'upload.inspection', 'status' => $ready ? 'pass' : 'fail',
                'reason' => $ready ? 'dependency.available' : (extension_loaded('fileinfo') ? 'dependency.gd' : 'dependency.fileinfo')];
            $path = realpath($upload['directory']); $root = realpath($upload['document_root']);
            $valid = $path !== false && is_dir($path) && is_writable($path) && (fileperms($path) & 0077) === 0;
            $checks[] = ['check' => 'upload.directory', 'status' => $valid ? 'pass' : 'fail', 'reason' => $valid ? 'storage.private_directory' : 'upload.directory'];
            $public = $path !== false && $root !== false && ($path === $root || strpos($path, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0);
            $actual = $documentRoot === null ? false : realpath($documentRoot);
            $mismatch = $actual !== false && $root !== $actual;
            $checks[] = ['check' => 'upload.location', 'status' => $root === false || $public || $mismatch ? 'fail' : 'pass',
                'reason' => $root === false || $mismatch ? 'configuration.document_root' : ($public ? 'storage.web_root' : 'storage.outside_web_root')];
            $scanner = isset($upload['scanner']) ? ($services[$upload['scanner']] ?? null) : null;
            $checks[] = ['check' => 'upload.scanner', 'status' => $scanner instanceof \SoSecurity\Upload\Scanner ? 'manual' : ($upload['require_scan'] || isset($upload['scanner']) ? 'fail' : 'not_configured'),
                'reason' => $scanner instanceof \SoSecurity\Upload\Scanner ? 'upload.scanner_unverified' : 'configuration.scanner'];
        }
        $outbound = $config->outbound();
        if ($outbound === null) { $checks[] = ['check'=>'outbound', 'status'=>'not_configured', 'reason'=>'configuration.outbound']; }
        else {
            $curl = extension_loaded('curl') && curl_version()['version_number'] >= 0x073900;
            $defaultNeeded = !isset($outbound['resolver']) || !isset($outbound['transport']);
            $checks[] = ['check'=>'outbound.curl', 'status'=>$defaultNeeded && !$curl ? 'fail' : ($defaultNeeded ? 'pass' : 'optional'),
                'reason'=>$curl ? 'dependency.available' : 'dependency.curl'];
            foreach (['resolver'=>\SoSecurity\Http\Outbound\Resolver::class, 'transport'=>\SoSecurity\Http\Outbound\Transport::class] as $kind=>$contract) {
                if (!isset($outbound[$kind])) { continue; }
                $service = $services[$outbound[$kind]] ?? null;
                $checks[] = ['check'=>'outbound.' . $kind, 'status'=>$service instanceof $contract ? 'manual' : 'fail',
                    'reason'=>$service instanceof $contract ? 'http.adapter_unverified' : 'configuration.' . $kind];
            }
            $checks[] = ['check'=>'outbound.network', 'status'=>'manual', 'reason'=>'http.network_unverified'];
        }
        return $checks;
    }
    private function redis(\Redis $redis, string $namespace): array
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
            $redis->clearLastError();
            $info = $redis->info('server');
            $ready = $redis->get('sosecurity:' . hash('sha256', $namespace) . ':ready');
            $metadata = is_string($ready) && strlen($ready) <= 512 ? json_decode($ready, true, 4) : null;
            $initialized = is_array($metadata) && isset($metadata['server'], $metadata['epoch']) && is_array($info)
                && ($info['run_id'] ?? null) === $metadata['server'] && is_string($metadata['epoch']) && preg_match('/^[a-f0-9]{64}$/D', $metadata['epoch']);
            $result[] = ['check' => 'readiness', 'status' => $initialized ? 'pass' : 'fail', 'reason' => $initialized ? 'storage.initialized' : 'storage.initialization_required'];
            return $result;
        } catch (\RedisException $e) {
            $healthy = false; $redis->close();
            return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']];
        } finally {
            if ($healthy && $timeout !== null && $redis->isConnected()) { $redis->setOption(\Redis::OPT_READ_TIMEOUT, (string) $timeout); }
        }
    }
}
