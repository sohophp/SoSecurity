<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__, 3) . '/tests/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\VerifiedLogout;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;

$proof = static function (string $type, string $subject, ?string $sid, int $issuedAt) {
    $class = new ReflectionClass($type);
    $value = $class->newInstanceWithoutConstructor();
    $fields = $type === VerifiedSubject::class
        ? ['issuer' => 'https://issuer.example.test', 'subject' => $subject,
            'providerSessionId' => $sid, 'issuedAt' => $issuedAt]
        : ['issuer' => 'https://issuer.example.test', 'subject' => $subject === '' ? null : $subject,
            'sessionId' => $sid, 'issuedAt' => $issuedAt, 'tokenId' => 'test-logout'];
    $parts = $type === VerifiedSubject::class
        ? [$fields['issuer'], $fields['subject'], $fields['issuedAt'], $fields['providerSessionId']]
        : [$fields['issuer'], $fields['subject'], $fields['sessionId'], $fields['tokenId'], $fields['issuedAt']];
    $property = $class->getProperty('read');
    if (PHP_VERSION_ID < 80100) { $property->setAccessible(true); }
    $property->setValue($value, static function () use ($parts): array { return $parts; });
    return $value;
};

$directory = privateDirectory();
try {
    foreach (['memory', 'file'] as $backend) {
        $clock = new TestClock();
        $store = $backend === 'memory' ? new MemoryStore($clock) : new FileStore($directory, 'oidc-fence-test', $clock);
        $fence = new LogoutFence($store, $clock);
        Check::throws(SecurityException::class, static function () use ($fence, $proof): void {
            $fence->record('tenant', $proof(VerifiedLogout::class, '', null, 100000));
        });
        Check::throws(SecurityException::class, static function () use ($fence, $proof): void {
            $fence->record('tenant', $proof(VerifiedLogout::class, 'external-a', null, 13599));
        });
        $oldA = $proof(VerifiedSubject::class, 'external-a', 'sid-a', 99990);
        $otherSid = $proof(VerifiedSubject::class, 'external-a', 'sid-b', 99990);
        $otherSub = $proof(VerifiedSubject::class, 'external-b', 'sid-a', 99990);
        Check::same(true, $fence->allows('tenant', $oldA));
        Check::same(true, $fence->allows('tenant', $otherSid));
        Check::same(true, $fence->allows('tenant', $otherSub));

        // Both claims identify a pair. Neither neighboring subject nor neighboring sid is revoked.
        $fence->record('tenant', $proof(VerifiedLogout::class, 'external-a', 'sid-a', 99991));
        Check::same(false, $fence->allows('tenant', $oldA));
        Check::same(true, $fence->allows('tenant', $otherSid));
        Check::same(true, $fence->allows('tenant', $otherSub));
        Check::same(true, $fence->allows('other-tenant', $oldA));
        Check::same(true, $fence->allows('tenant', $proof(VerifiedSubject::class, 'external-a', 'sid-a', 99992)));
        Check::same(false, $fence->allowsSession('tenant', 'https://issuer.example.test',
            'external-a', 'sid-a', 100001, 99999));
        $clock->time = 100001;
        Check::same(true, $fence->allowsSession('tenant', 'https://issuer.example.test',
            'external-a', 'sid-a', 100001, 100001));
        $fence->record('tenant', $proof(VerifiedLogout::class, 'external-a', 'sid-a', 99989));
        Check::same(false, $fence->allows('tenant', $proof(VerifiedSubject::class, 'external-a', 'sid-a', 99991)));
        Check::same(true, $fence->allowsSession('tenant', 'https://issuer.example.test',
            'external-a', 'sid-a', 100001, 100001));

        // A sid-only token crosses subjects; a sub-only token crosses provider sessions.
        $fence->record('tenant', $proof(VerifiedLogout::class, '', 'sid-a', 99993));
        Check::same(false, $fence->allows('tenant', $otherSub));
        Check::same(true, $fence->allows('tenant', $otherSid));
        $fence->record('tenant', $proof(VerifiedLogout::class, 'external-a', null, 99994));
        Check::same(false, $fence->allows('tenant', $otherSid));
        Check::same(true, $fence->allows('tenant', $proof(VerifiedSubject::class, 'external-b', 'sid-b', 99990)));

        $account = new Account('tenant', 'alice', '1');
        $provider = new CallbackIdentityProvider(
            static function (string $scope, string $identifier, string $password) use ($account): ?Account {
                return $scope === 'tenant' && $identifier === 'alice' && $password === 'secret' ? $account : null;
            },
            static function (string $scope, string $subject) use ($account): ?Account {
                return $scope === 'tenant' && $subject === 'alice' ? $account : null;
            }
        );
        $guard = static function (): bool { return true; };
        $sessions = new SessionRegistry($store, $provider, null, $clock);
        $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, null, $clock);
        $credential = $flow->password('tenant', 'browser', 'alice', 'secret')->credential();
        $links = new LinkRegistry($store, $provider, $sessions, $guard, $clock, $fence);
        Check::throws(SecurityException::class, static function () use ($links, $credential, $oldA): void {
            $links->link('tenant', 'alice', $credential->token(), $oldA);
        });
        $fresh = $proof(VerifiedSubject::class, 'external-a', 'sid-a', 99995);
        Check::same(true, $links->link('tenant', 'alice', $credential->token(), $fresh));
        Check::same('alice', $links->resolve('tenant', $fresh)->subject());
        $fence->record('tenant', $proof(VerifiedLogout::class, 'external-a', null, 99996));
        Check::same(null, $links->resolve('tenant', $fresh));
        Check::same(true, $sessions->verify('tenant', 'alice', $credential->token()) !== null);
        $clock->time += 172801;
        Check::same(false, $fence->allows('tenant', $oldA));
        Check::same(true, $fence->allows('tenant', $proof(VerifiedSubject::class, 'external-a', 'sid-a', $clock->time)));
    }
} finally {
    cleanDirectory($directory);
}
echo 'PASS OIDC logout fence: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
