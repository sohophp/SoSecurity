<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\WebAuthn\Ceremonies;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

$checks = 0;
$reject = static function (callable $run) use (&$checks): void {
    try {
        $run();
    } catch (InvalidArgumentException $e) {
        ++$checks;
        return;
    }
    throw new RuntimeException('Expected defensive rejection');
};

$reject(static function (): void { new Ceremonies('Test', 'example.test', 'http://example.test'); });
$reject(static function (): void { new Ceremonies('Test', 'example.test', 'https://other.test'); });
$reject(static function (): void { new Ceremonies('Test', 'example.test', 'https://user@example.test'); });
$service = new Ceremonies('Test', 'example.test', 'https://example.test');
$user = PublicKeyCredentialUserEntity::create('alice', 'alice-id', 'Alice');
$first = $service->beginRegistration($user, []);
$second = $service->beginRegistration($user, []);
if (strlen($first->challenge) !== 32 || hash_equals($first->challenge, $second->challenge)) {
    throw new RuntimeException('Challenge is not fresh and 32 bytes');
}
++ $checks;
if (count($first->pubKeyCredParams) !== 2 ||
    $first->pubKeyCredParams[0]->alg !== -7 || $first->pubKeyCredParams[1]->alg !== -257 ||
    $first->authenticatorSelection->userVerification !== 'required' || $first->attestation !== 'none') {
    throw new RuntimeException('Browser creation options are not constrained');
}
++ $checks;
$reject(static function () use ($service): void { $service->beginAuthentication('alice-id', []); });
$record = CredentialRecord::create('credential-id', 'public-key', [], 'none', EmptyTrustPath::create(),
    Uuid::v4(), 'not-a-real-key', 'alice-id', 0);
$signal = json_decode($service->acceptedCredentialsSignal($user, [$record]), true);
if (!is_array($signal) || $signal['rpId'] !== 'example.test' ||
    $signal['userId'] !== 'YWxpY2UtaWQ' || $signal['allAcceptedCredentialIds'] !== ['Y3JlZGVudGlhbC1pZA']) {
    throw new RuntimeException('Accepted credential signal is incorrect');
}
++ $checks;
$reject(static function () use ($service, $user, $record): void {
    $foreign = clone $record;
    $foreign->userHandle = 'bob-id';
    $service->acceptedCredentialsSignal($user, [$foreign]);
});
$login = $service->beginAuthentication('alice-id', [$record]);
if (strlen($login->challenge) !== 32 || count($login->allowCredentials) !== 1 ||
    $login->userVerification !== 'required') {
    throw new RuntimeException('Authentication options are not constrained');
}
++ $checks;
$reject(static function () use ($service, $record): void { $service->beginAuthentication('bob-id', [$record]); });
$reject(static function () use ($service, $first): void { $service->finishRegistration($first, str_repeat('x', 65537)); });
$reject(static function () use ($service, $first): void { $service->finishRegistration($first, '{}'); });
$reject(static function () use ($service, $login, $record): void {
    $service->finishAuthentication($login, str_repeat('x', 65537), $record, 'alice-id');
});
$reject(static function () use ($service, $login, $record): void {
    $service->finishAuthentication($login, '{}', $record, 'bob-id');
});
echo "WebAuthn optional adapter: {$checks} checks passed\n";
