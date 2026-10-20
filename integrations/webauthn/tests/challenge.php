<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\Clock;
use SoSecurity\WebAuthn\Ceremonies;
use SoSecurity\WebAuthn\ChallengeStore;
use SoSecurity\WebAuthn\BoundCeremonies;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

$clock = new class implements Clock {
    public $time = 1000;
    public function now(): int { return $this->time; }
};
$backend = new MemoryStore($clock);
$store = new ChallengeStore($backend, 'test-site', $clock, 30);
$ceremonies = new Ceremonies('Test', 'example.test', 'https://example.test');
$user = PublicKeyCredentialUserEntity::create('alice', 'alice-id', 'Alice');
$options = $ceremonies->beginRegistration($user, []);
$checks = 0;
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    ++$checks;
};

$handle = $store->issue($options, 'alice-id', 'session-a');
$check(strlen($handle) === 43, 'Handle length');
$check($store->consume($handle, 'authenticate', 'alice-id', 'session-a') === null, 'Wrong ceremony type');
$check($store->consume($handle, 'register', 'bob-id', 'session-a') === null, 'Wrong account');
$check($store->consume($handle, 'register', 'alice-id', 'session-b') === null, 'Wrong session');
$stored = $store->consume($handle, 'register', 'alice-id', 'session-a');
$check($stored instanceof PublicKeyCredentialCreationOptions &&
    hash_equals($options->challenge, $stored->challenge), 'Correct challenge round trip');
$check($store->consume($handle, 'register', 'alice-id', 'session-a') === null, 'Replay rejected');

$expired = $store->issue($options, 'alice-id', 'session-a');
$clock->time += 30;
$check($store->consume($expired, 'register', 'alice-id', 'session-a') === null, 'Expired challenge rejected');

$other = new ChallengeStore($backend, 'other-site', $clock, 30);
$isolated = $store->issue($options, 'alice-id', 'session-a');
$check($other->consume($isolated, 'register', 'alice-id', 'session-a') === null, 'Site isolation');
$check($store->consume($isolated, 'register', 'alice-id', 'session-a') instanceof PublicKeyCredentialCreationOptions,
    'Other site did not consume challenge');
$bound = new BoundCeremonies($ceremonies, $store);
$registration = $bound->beginRegistration($user, [], 'session-a');
try {
    $bound->finishRegistration($registration['handle'], 'bob-id', 'session-a', '{}');
    throw new RuntimeException('Wrong account accepted');
} catch (InvalidArgumentException $e) {
    ++$checks;
}
$check($store->consume($registration['handle'], 'register', 'alice-id', 'session-a') instanceof PublicKeyCredentialCreationOptions,
    'Wrong account consumed challenge');
$registration = $bound->beginRegistration($user, [], 'session-a');
try {
    $bound->finishRegistration($registration['handle'], 'alice-id', 'session-a', str_repeat('x', 65537));
    throw new RuntimeException('Oversize response accepted');
} catch (InvalidArgumentException $e) {
    ++$checks;
}
$check($store->consume($registration['handle'], 'register', 'alice-id', 'session-a') === null,
    'Failed validation replayed challenge');
$record = CredentialRecord::create('credential-id', 'public-key', [], 'none', EmptyTrustPath::create(),
    Uuid::v4(), 'not-a-real-key', 'alice-id', 0);
$authentication = $bound->beginAuthentication('alice-id', [$record], 'session-a');
$check($store->consume($authentication['handle'], 'register', 'alice-id', 'session-a') === null,
    'Login challenge accepted as registration');
$check($store->consume($authentication['handle'], 'authenticate', 'alice-id', 'session-a') instanceof PublicKeyCredentialRequestOptions,
    'Login options round trip');
$authentication = $bound->beginAuthentication('alice-id', [$record], 'session-a');
try {
    $bound->finishAuthentication($authentication['handle'], 'alice-id', 'session-a',
        str_repeat('x', 65537), $record);
    throw new RuntimeException('Oversize assertion accepted');
} catch (InvalidArgumentException $e) {
    ++$checks;
}
$check($store->consume($authentication['handle'], 'authenticate', 'alice-id', 'session-a') === null,
    'Failed login validation replayed challenge');
echo "WebAuthn challenge store: {$checks} checks passed\n";
