<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Exception\DependencyException;
$secret = 'native-test-secret-only';
$providers = [new SoSecurity\Captcha\HCaptcha($secret, 'expected-site-key'),
    new SoSecurity\Captcha\Recaptcha($secret, 'www.google.com'),
    new SoSecurity\Captcha\Recaptcha($secret . '-v3', 'www.google.com', 'login', 0.5),
    new SoSecurity\Captcha\Turnstile($secret, 'challenges.cloudflare.com', 'login')];
foreach ($providers as $provider) {
    if (getenv('SOSECURITY_CAPTCHA_BAD_CA') === '1') {
        Check::throws(DependencyException::class, function () use ($provider) { $provider->verify('ok'); }); continue;
    }
    Check::same(true, $provider->verify('ok', '203.0.113.2'));
    Check::same(false, $provider->verify('reject'));
    foreach (['malformed', 'redirect', 'body-limit', 'header-limit', 'unavailable'] as $token) {
        Check::throws(DependencyException::class, function () use ($provider, $token) { $provider->verify($token); });
    }
}
if (getenv('SOSECURITY_CAPTCHA_BAD_CA') !== '1') {
    Check::same(false, (new SoSecurity\Captcha\Recaptcha($secret, 'wrong.example'))->verify('ok'));
    Check::same(false, (new SoSecurity\Captcha\Turnstile($secret, 'wrong.example', 'login'))->verify('ok'));
    Check::same(false, (new SoSecurity\Captcha\Recaptcha($secret . '-v3', 'www.google.com', 'other', 0.5))->verify('ok'));
    Check::same(false, (new SoSecurity\Captcha\Recaptcha($secret . '-v3', 'www.google.com', 'login', 0.9))->verify('ok'));
}
if (getenv('SOSECURITY_CAPTCHA_TIMEOUT_CASE') === '1' && getenv('SOSECURITY_CAPTCHA_BAD_CA') !== '1') {
    Check::throws(DependencyException::class, function () use ($providers) { $providers[0]->verify('slow'); });
}
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . ' native provider HTTPS assertions passed ('
    . (getenv('SOSECURITY_CAPTCHA_BAD_CA') === '1' ? 'untrusted CA rejection' : 'private TLS servers; fixed endpoints, payload binding, size/status/redirect refusal') . ")\n";
