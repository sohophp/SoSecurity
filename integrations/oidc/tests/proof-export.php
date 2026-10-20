<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__, 3) . '/tests/bootstrap.php';

use SoSecurity\Oidc\VerifiedLogout;
use SoSecurity\Oidc\VerifiedSubject;

// Only this export test uses reflection; production proofs still require verified OIDC tokens.
$make = static function (string $type, array $parts) {
    $class = new ReflectionClass($type);
    $proof = $class->newInstanceWithoutConstructor();
    $property = $class->getProperty('read');
    if (PHP_VERSION_ID < 80100) { $property->setAccessible(true); }
    $property->setValue($proof, static function () use ($parts): array { return $parts; });
    return $proof;
};
$issuer = 'https://issuer.example.test';
$subject = 'secret-external-subject-1927';
$sid = 'secret-provider-session-2846';
$jti = 'secret-logout-token-id-3765';
$identity = $make(VerifiedSubject::class, [$issuer, $subject, 100000, $sid]);
$logout = $make(VerifiedLogout::class, [$issuer, $subject, $sid, $jti, 100000]);
Check::same($subject, $identity->subject());
Check::same($sid, $identity->providerSessionId());
Check::same(100000, $identity->issuedAt());
Check::same($subject, $logout->subject());
Check::same($sid, $logout->sessionId());
Check::same($jti, $logout->tokenId());
foreach ([$identity, $logout] as $proof) {
    foreach ([var_export($proof, true), print_r($proof, true), json_encode($proof),
        var_export(['proof' => $proof], true), print_r(['proof' => $proof], true)] as $rendered) {
        foreach ([$subject, $sid, $jti] as $secret) { Check::same(false, strpos($rendered, $secret) !== false); }
    }
    Check::throws(RuntimeException::class, static function () use ($proof): void { serialize($proof); });
    $type = get_class($proof);
    Check::throws(RuntimeException::class, static function () use ($type): void {
        unserialize('O:' . strlen($type) . ':"' . $type . '":0:{}');
    });
    Check::throws(RuntimeException::class, static function () use ($proof): void { $proof->injected = 'unsafe'; });
}
echo 'PASS OIDC proof object export: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
