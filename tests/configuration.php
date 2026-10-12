<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Security;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\MemoryStore;

$directory = privateDirectory();
try {
    $clock = new TestClock();
    $factory = Security::fromArray(['site' => 'alpha', 'storage' => ['driver' => 'file', 'directory' => $directory],
        'token_storage' => ['driver' => 'file', 'directory' => $directory],
        'rate_limits' => ['login' => ['limit' => 2]]], [], $clock);
    Check::same(PHP_SESSION_NONE, session_status());
    Check::same(false, headers_sent());
    $token = $factory->csrf()->issue('form', 'binding');
    Check::same(true, $factory->csrf()->verify('form', 'binding', $token));
    Check::same(false, Security::fromArray(['site' => 'other', 'token_storage' => ['driver' => 'file', 'directory' => $directory]], [], $clock)
        ->csrf()->verify('form', 'binding', $token));
    $clock->time += 7200;
    Check::same(false, $factory->csrf()->verify('form', 'binding', $token));
    Check::same(true, $factory->rateLimiter('login')->consume('login', 'subject')->allowed);
    Check::same(true, $factory->rateLimiter('login')->consume('login', 'subject')->allowed);
    Check::same(false, $factory->rateLimiter('login')->consume('login', 'subject')->allowed);
    Check::throws(ConfigurationException::class, function () use ($factory) { $factory->rateLimiter('unknown'); });
    Check::throws(ConfigurationException::class, function () { Security::fromArray(['site' => 'a'])->rateLimiter(); });
    foreach (['memory', 'session'] as $driver) {
        Check::throws(ConfigurationException::class, function () use ($driver) { Security::fromArray(['site' => 'a', 'storage' => ['driver' => $driver]])->rateLimiter(); });
    }
    Check::throws(ConfigurationException::class, function () {
        Security::fromArray(['site' => 'a', 'storage' => ['driver' => 'provided', 'connection' => 'bad']], ['bad' => new MemoryStore()])->rateLimiter();
    });
    foreach ([['unknown' => true], ['csrf' => ['ttll' => 1]], ['csrf' => ['ttl' => '30']], ['captcha' => ['attempts' => 0]],
        ['storage' => null], ['token_storage' => null], ['session' => ['path' => null]], ['storage' => ['driver' => 'file']],
        ['storage' => ['driver' => 'redis', 'connection' => 'r', 'attempts' => 0]], ['session' => ['secure' => false, 'same_site' => 'None']],
        ['storage' => ['driver' => 'file', 'directory' => $directory, 'lock_timeout_ms' => null]],
        ['storage' => ['driver' => 'redis', 'connection' => 'r', 'budget_ms' => null]],
        ['storage' => ['driver' => 'redis', 'connection' => 'r', 'attempts' => null]],
        ['storage' => ['driver' => 'mysql', 'connection' => 'm', 'lock_wait_seconds' => null]],
        ['storage' => ['driver' => 'mysql', 'connection' => 'm', 'lock_wait_seconds' => 31]],
        ['session' => ['lifetime' => null]]] as $bad) {
        Check::throws(ConfigurationException::class, function () use ($bad) { Security::fromArray(['site' => 'a'] + $bad); });
    }
    $ttl = 30; $factory = Security::fromArray(['site' => 'a', 'csrf' => ['ttl' => &$ttl]]);
    $ttl = 0; Check::same(30, $factory->config()->csrf()['ttl']);
    Check::throws(ConfigurationException::class, function () use ($factory) { $factory->config()->site = 'other'; });
    $factory = Security::fromArray(['site' => 'a', 'storage' => ['driver' => 'file', 'directory' => $directory]]);
    $checks = $factory->diagnose(sys_get_temp_dir());
    $byName = array_column($checks, null, 'check');
    Check::same('fail', $byName['storage.shared.location']['status']);
    Check::same('manual', $byName['storage.tokens.locking']['status']);
    Check::same(false, strpos(json_encode($checks), $directory) !== false);
    $factory = Security::fromArray(['site' => 'a', 'storage' => ['driver' => 'redis', 'connection' => 'r']], ['r' => 'SECRET-SERVICE-VALUE']);
    $checks = $factory->diagnose();
    Check::same(false, strpos(json_encode($checks), 'SECRET-SERVICE-VALUE') !== false);
    Check::same('fail', array_column($checks, null, 'check')['storage.shared']['status']);
    $factory = Security::fromArray(['site' => 'only-password']);
    $hasher = $factory->passwordHasher();
    Check::same(true, $hasher->verify('test-password-for-factory', $hasher->hash('test-password-for-factory')));
    Check::same(PHP_SESSION_NONE, session_status());
    Check::same(false, headers_sent());
} finally { cleanDirectory($directory); }
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " configuration/diagnostic assertions passed\n";
