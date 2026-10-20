<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Password\PwnedPasswords;
use SoSecurity\Exception\DependencyException;
$checker = new PwnedPasswords(null, 500);
if (getenv('SOSECURITY_PASSWORD_DNS_PINNING') === '1') {
    Check::same(true, $checker('Native-public-pwned-password'));
    echo "PASS native breach DNS pinning: silent OS resolver bypassed by bounded DoH and exact IP connection\n"; exit;
} elseif (getenv('SOSECURITY_PASSWORD_DNS_TIMEOUT') === '1') {
    Check::throws(DependencyException::class, function () use ($checker) { $checker('Native-public-pwned-password'); });
    echo "PASS native breach DNS timeout: bounded refusal while private resolver stays silent\n"; exit;
} elseif (getenv('SOSECURITY_PASSWORD_BAD_CA') === '1') {
    Check::throws(DependencyException::class, function () use ($checker) { $checker('Native-public-pwned-password'); });
} else {
    Check::same(true, $checker('Native-public-pwned-password'));
    Check::same(false, $checker('Native-public-clean-password'));
    Check::same(false, $checker('Native-public-padding-password'));
    foreach (['malformed', 'redirect', 'unavailable', 'body-limit', 'header-limit', 'slow'] as $mode) {
        Check::throws(DependencyException::class, function () use ($checker, $mode) { $checker('Native-public-' . $mode . '-password'); });
    }
}
echo 'PASS native password HTTPS: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION .
    (getenv('SOSECURITY_PASSWORD_BAD_CA') === '1' ? ' (untrusted CA rejection)' : ' (fixed range endpoint, padding, timeout/status/redirect/header/body refusal)') . "\n";
