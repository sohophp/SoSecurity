<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\DeviceRiskDecision;
use SoSecurity\Auth\DeviceRiskPolicy;
use SoSecurity\Auth\RememberedLogin;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\HmacKeys;

$policy = new DeviceRiskPolicy();
$signals = ['anomalous' => false, 'changed' => false, 'compromised' => false, 'reauth_required' => false];
Check::same('allow', $policy->decide($signals)->action());
Check::same('none', $policy->decide($signals)->reason());
foreach (['anomalous', 'changed', 'reauth_required'] as $reason) {
    $case = $signals; $case[$reason] = true;
    Check::same('step_up', $policy->decide($case)->action());
    Check::same($reason, $policy->decide($case)->reason());
}
$case = $signals; $case['compromised'] = true; $case['changed'] = true;
Check::same('deny', $policy->decide($case)->action());
Check::same('compromised', $policy->decide($case)->reason());
foreach ([[], ['compromised' => true], array_replace($signals, ['changed' => 1]), array_replace($signals, ['extra' => false])] as $bad) {
    Check::throws(ConfigurationException::class, static function () use ($policy, $bad): void { $policy->decide($bad); });
}
Check::throws(ConfigurationException::class, static function (): void { new DeviceRiskDecision('allow', 'compromised'); });

$clock = new TestClock(); $store = new MemoryStore($clock); $account = new Account('tenant', 'subject', '1');
$provider = new CallbackIdentityProvider(
    static function (string $scope, string $identifier, string $password) use ($account): ?Account {
        return $scope === 'tenant' && $identifier === 'user' && $password === 'secret' ? $account : null;
    },
    static function (string $scope, string $subject) use ($account): ?Account {
        return $scope === 'tenant' && $subject === 'subject' ? $account : null;
    }
);
$guard = static function (string $phase, string $scope): bool { return true; };
$calls = 0;
$riskGuard = static function (string $scope, string $subject, string $selector) use (&$signals, &$calls, $policy): DeviceRiskDecision {
    ++$calls;
    Check::same('tenant', $scope); Check::same('subject', $subject); Check::same(32, strlen($selector));
    return $policy->decide($signals);
};
$keys = new HmacKeys('risk', ['risk' => str_repeat('r', 32)]);
$sessions = new SessionRegistry($store, $provider, null, $clock);
$flow = new AuthenticationFlow($store, $provider, $sessions, $guard, null, $clock);
$remember = new RememberedLogin($store, $provider, $sessions, $keys, $guard, null, $clock, 300, 2, 20, 5, $riskGuard);
$login = $flow->password('tenant', 'browser', 'user', 'secret')->credential();
$credential = $remember->issue('tenant', 'subject', $login->token());
$otherLogin = $flow->password('tenant', 'browser-other', 'user', 'secret')->credential();
$otherCredential = $remember->issue('tenant', 'subject', $otherLogin->token());
Check::same('invalid', $remember->resume('tenant', 'bad-token')->status());
Check::same(0, $calls);
$signals['changed'] = true;
$step = $remember->resume('tenant', $credential->token());
Check::same('step_up', $step->status()); Check::same('changed', $step->reason());
Check::same(null, $step->session()); Check::same(null, $step->nextCredential());
Check::same(1, count($remember->all('tenant', 'subject')));
Check::same(null, $sessions->verify('tenant', 'subject', $login->token()));
Check::same(true, $sessions->verify('tenant', 'subject', $otherLogin->token()) !== null);
$signals = ['anomalous' => false, 'changed' => false, 'compromised' => false, 'reauth_required' => false];
Check::same('invalid', $remember->resume('tenant', $credential->token())->status());
Check::same('authenticated', $remember->resume('tenant', $otherCredential->token())->status());
Check::same(true, $remember->revoke('tenant', 'subject', $otherCredential->id()));
$freshLogin = $flow->password('tenant', 'browser', 'user', 'secret')->credential();
$freshCredential = $remember->issue('tenant', 'subject', $freshLogin->token());
$allowed = $remember->resume('tenant', $freshCredential->token());
Check::same('authenticated', $allowed->status()); Check::same(null, $allowed->reason());
Check::same(true, $sessions->verify('tenant', 'subject', $allowed->session()->token()) !== null);
$signals['compromised'] = true;
$blocked = $remember->resume('tenant', $allowed->nextCredential()->token());
Check::same('blocked', $blocked->status()); Check::same('compromised', $blocked->reason());
Check::same(null, $blocked->session()); Check::same(0, count($remember->all('tenant', 'subject')));
Check::same(null, $sessions->verify('tenant', 'subject', $allowed->session()->token()));
Check::same('invalid', $remember->resume('tenant', $allowed->nextCredential()->token())->status());

$invalidRisk = static function (): bool { return true; };
$unsafe = new RememberedLogin($store, $provider, $sessions, $keys, $guard, null, $clock, 300, 2, 20, 5, $invalidRisk);
$login = $flow->password('tenant', 'browser', 'user', 'secret')->credential();
$credential = $unsafe->issue('tenant', 'subject', $login->token());
Check::throws(SecurityException::class, static function () use ($unsafe, $credential): void { $unsafe->resume('tenant', $credential->token()); });
Check::same(1, count($unsafe->all('tenant', 'subject')));
$offlineRisk = static function (): DeviceRiskDecision { throw new SecurityException('Test risk source unavailable.', 'auth.test_risk_offline'); };
$offline = new RememberedLogin($store, $provider, $sessions, $keys, $guard, null, $clock, 300, 2, 20, 5, $offlineRisk);
Check::throws(SecurityException::class, static function () use ($offline, $credential): void { $offline->resume('tenant', $credential->token()); });
Check::same(1, count($offline->all('tenant', 'subject')));

$directory = privateDirectory();
try {
    $config = ['site' => 'device-risk-test', 'storage' => ['driver' => 'file', 'directory' => $directory],
        'authentication' => ['identity_provider' => 'identity', 'request_guard' => 'guard'],
        'remember' => ['keys' => 'remember_keys', 'risk_guard' => 'risk']];
    $services = ['identity' => $provider, 'guard' => $guard, 'remember_keys' => $keys, 'risk' => $riskGuard];
    Check::throws(ConfigurationException::class, static function () use ($config, $services, $clock): void {
        $missing = $services; unset($missing['risk']);
        \SoSecurity\Security::fromArray($config, $missing, $clock)->rememberedLogin();
    });
    Check::throws(ConfigurationException::class, static function () use ($config): void {
        $bad = $config; $bad['remember']['risk_guard'] = ['risk'];
        \SoSecurity\Security::fromArray($bad);
    });
    $factory = \SoSecurity\Security::fromArray($config, $services, $clock);
    $session = $factory->authentication()->password('tenant', 'browser', 'user', 'secret')->credential();
    $grant = $factory->rememberedLogin()->issue('tenant', 'subject', $session->token());
    $signals = ['anomalous' => false, 'changed' => true, 'compromised' => false, 'reauth_required' => false];
    Check::same('step_up', $factory->rememberedLogin()->resume('tenant', $grant->token())->status());
    $signals['changed'] = false;
    Check::same('invalid', $factory->rememberedLogin()->resume('tenant', $grant->token())->status());
    $freshSession = $factory->authentication()->password('tenant', 'browser', 'user', 'secret')->credential();
    $freshGrant = $factory->rememberedLogin()->issue('tenant', 'subject', $freshSession->token());
    Check::same('authenticated', $factory->rememberedLogin()->resume('tenant', $freshGrant->token())->status());
} finally {
    cleanDirectory($directory);
}

echo 'PASS trusted-device risk decisions: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
