<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Captcha\HCaptcha;
use SoSecurity\Captcha\Recaptcha;
use SoSecurity\Captcha\Turnstile;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

$secret = str_repeat('test-secret-', 3); $payloads = [];
$transport = function (array $payload) use (&$payloads): string { $payloads[] = $payload; return '{"success":true,"hostname":"site.example","action":"login","score":0.7}'; };
$hcaptcha = new HCaptcha($secret, 'expected-site-key', $transport);
Check::same(true, $hcaptcha->verify('token', '203.0.113.2'));
Check::same('expected-site-key', $payloads[0]['sitekey']); Check::same('203.0.113.2', $payloads[0]['remoteip']);
Check::same($secret, $payloads[0]['secret']); Check::same('token', $payloads[0]['response']);
// Hostname is documented as untrusted/statistical by hCaptcha; binding is the expected sitekey parameter.
Check::same(true, (new HCaptcha($secret, 'sitekey', function () { return '{"success":true,"hostname":"not-provided"}'; }))->verify('token'));
$v3 = new Recaptcha($secret, 'site.example', 'login', 0.5, $transport);
Check::same(true, $v3->verify('token')); Check::same(false, isset($payloads[1]['remoteip']));
Check::same(false, (new Recaptcha($secret, 'site.example', 'login', 0.8, $transport))->verify('token'));
Check::same(false, (new Recaptcha($secret, 'other.example', 'login', 0.5, $transport))->verify('token'));
Check::same(false, (new Recaptcha($secret, 'site.example', 'register', 0.5, $transport))->verify('token'));
$v2 = new Recaptcha($secret, 'site.example', null, 0.5, function () { return '{"success":true,"hostname":"site.example"}'; });
Check::same(true, $v2->verify('token', '2001:db8::1'));
Check::same(false, (new Recaptcha($secret, 'site.example', null, 0.5, $transport))->verify('token'));
foreach (['{"success":true,"hostname":"site.example","score":0.9}', '{"success":true,"hostname":"site.example","action":"login"}'] as $body) {
    Check::same(false, (new Recaptcha($secret, 'site.example', null, 0.5, function () use ($body) { return $body; }))->verify('token'));
}
foreach ([-1, 0.49, 1.01, '0.9', null, true] as $score) {
    $body = json_encode(['success'=>true, 'hostname'=>'site.example', 'action'=>'login', 'score'=>$score]);
    Check::same(false, (new Recaptcha($secret, 'site.example', 'login', 0.5, function () use ($body) { return $body; }))->verify('token'));
}
Check::same(true, (new Recaptcha($secret, 'site.example', 'login', 0.5, function () { return '{"success":true,"hostname":"site.example","action":"login","score":0.5}'; }))->verify('token'));
Check::same(true, (new Recaptcha($secret, 'site.example', 'login', 1.0, function () { return '{"success":true,"hostname":"site.example","action":"login","score":1}'; }))->verify('token'));
$constructors = [function ($transport) use ($secret) { return new HCaptcha($secret, 'sitekey', $transport); },
    function ($transport) use ($secret) { return new Recaptcha($secret, 'site.example', null, 0.5, $transport); },
    function ($transport) use ($secret) { return new Turnstile($secret, 'site.example', 'login', $transport); }];
foreach ($constructors as $make) {
    $calls = 0; $provider = $make(function () use (&$calls) { ++$calls; return '{"success":false}'; });
    foreach ([null, [], '', "bad\nvalue", str_repeat('a', 8193)] as $token) { Check::same(false, $provider->verify($token)); }
    Check::same(0, $calls); Check::same(false, $provider->verify('invalid-token')); Check::same(1, $calls);
    Check::throws(ConfigurationException::class, function () use ($provider) { $provider->verify('token', 'not-an-ip'); });
    foreach (['bad-json', '{}', '{"success":"true"}', '{"success":1}', str_repeat('a', 16385), null, ['success'=>true]] as $body) {
        Check::throws(DependencyException::class, function () use ($make, $body) { $make(function () use ($body) { return $body; })->verify('token'); });
    }
    $leaking = $make(function () { throw new RuntimeException('private-token-secret'); });
    try { $leaking->verify('token'); throw new RuntimeException('Expected rejection.'); }
    catch (DependencyException $e) { Check::same(null, $e->getPrevious()); Check::same(false, strpos($e->getMessage(), 'private-token-secret')); }
}
foreach ([-0.1, 1.1, NAN, INF] as $score) { Check::throws(ConfigurationException::class, function () use ($secret, $score) { new Recaptcha($secret, 'site.example', 'login', $score); }); }
Check::throws(ConfigurationException::class, function () { new HCaptcha('short', 'sitekey'); });
Check::throws(ConfigurationException::class, function () use ($secret) { new HCaptcha($secret, 'bad key'); });
Check::throws(ConfigurationException::class, function () use ($secret) { new Recaptcha($secret, 'SITE.EXAMPLE'); });
Check::throws(ConfigurationException::class, function () use ($secret) { new Recaptcha($secret, 'site.example', 'user:42'); });
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " provider contract assertions passed (injected simulated responses, no external service claim)\n";
