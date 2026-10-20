<?php
declare(strict_types=1);

/** Test-only ownership proof before any Redis/MySQL connection or DDL. */
function quarantineBackendSocket(string $backend): string
{
    if (!in_array($backend, ['redis', 'mysql'], true)) { throw new RuntimeException('Use a selected local test backend.'); }
    $socket = getenv($backend === 'redis' ? 'SOSECURITY_TEST_REDIS_SOCKET' : 'SOSECURITY_TEST_MYSQL_SOCKET');
    $nonce = getenv('SOSECURITY_TEST_QUARANTINE_OWNER');
    $pattern = $backend === 'redis'
        ? '/\A\/tmp\/sosecurity-quarantine-redis-[a-zA-Z0-9_]+\/redis\.sock\z/D'
        : '/\A\/tmp\/sosecurity-mysql-[a-zA-Z0-9_]+\/mysql\.sock\z/D';
    if (!is_string($socket) || !preg_match($pattern, $socket) || !is_string($nonce) || !preg_match('/\A[a-f0-9]{32}\z/D', $nonce)) { throw new RuntimeException('Owned local backend marker required.'); }
    $parent = dirname($socket); $marker = $parent . '/quarantine-backend-owner';
    clearstatcache(); $directory = @lstat($parent); $node = @lstat($socket); $file = @lstat($marker);
    // The PHP 7.2 test binary may omit ext-posix; Linux procfs still identifies this process.
    $process = function_exists('posix_geteuid') ? null : @stat('/proc/self');
    $uid = function_exists('posix_geteuid') ? posix_geteuid() : (is_array($process) ? $process['uid'] : null);
    if (!is_int($uid) || realpath($parent) !== $parent || !is_array($directory) || !is_array($node) || !is_array($file)
        || ($directory['mode'] & 0170000) !== 0040000 || ($directory['mode'] & 0777) !== 0700 || $directory['uid'] !== $uid
        || ($node['mode'] & 0170000) !== 0140000 || $node['uid'] !== $uid || ($file['mode'] & 0170000) !== 0100000
        || ($file['mode'] & 0777) !== 0600 || $file['nlink'] !== 1 || $file['size'] !== 32 || $file['uid'] !== $uid
        || !hash_equals($nonce, (string) file_get_contents($marker, false, null, 0, 33))) { throw new RuntimeException('Owned private backend identity disagrees.'); }
    return $socket;
}
function quarantineBackendConnection(string $backend)
{
    $socket = quarantineBackendSocket($backend);
    if ($backend === 'redis') {
        if (!extension_loaded('redis')) { throw new RuntimeException('NOT RUN owned Redis: phpredis required.'); }
        $client = new Redis(); $client->connect($socket, 0, 2.0); $client->setOption(Redis::OPT_READ_TIMEOUT, '2'); return $client;
    }
    return new PDO('mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4', 'sosecurity_test', 'integration-only',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 1, PDO::ATTR_EMULATE_PREPARES => false]);
}
function quarantineBackendNamespace(): string
{
    $name = getenv('SOSECURITY_TEST_QUARANTINE_NAMESPACE');
    if (!is_string($name) || !preg_match('/\Aquarantine-[a-f0-9]{16}\z/D', $name)) { throw new RuntimeException('Use a fixed owned test namespace.'); }
    return $name;
}
function quarantineBackendStore(string $backend, ?SoSecurity\Support\Clock $clock = null, bool $initialize = false): SoSecurity\Storage\AtomicStore
{
    $client = quarantineBackendConnection($backend); $namespace = quarantineBackendNamespace();
    if ($backend === 'mysql') {
        if ($initialize) { SoSecurity\Storage\MySqlStore::install($client); }
        return new SoSecurity\Storage\MySqlStore($client, $namespace, $clock);
    }
    $store = new SoSecurity\Storage\RedisStore($client, $namespace, $clock);
    if ($initialize) { $store->initialize(); }
    return $store;
}
