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
use SoSecurity\Oidc\StrictClient;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;

class LocalOidcClient extends StrictClient
{
    private $pair;
    public function pair(?array $pair): void { $this->pair = $pair; }
    public function authenticateSubject(): ?array { return $this->pair; }
}

$client = new LocalOidcClient('https://issuer.example.test', 'registered-client', str_repeat('s', 32),
    'https://site.example.test/oidc/callback', 'https://issuer.example.test/authorize',
    'https://issuer.example.test/token', 'https://issuer.example.test/keys');
$client->pair(['issuer' => 'https://issuer.example.test', 'subject' => 'external-one']);
Check::throws(RuntimeException::class, static function () use ($client): void { VerifiedSubject::fromClient($client); });
// Only local store tests use reflection to stand in for a successfully verified provider callback.
$testRemote = static function (string $subject): VerifiedSubject {
    $type = new ReflectionClass(VerifiedSubject::class);
    $proof = $type->newInstanceWithoutConstructor();
    $property = $type->getProperty('read');
    if (PHP_VERSION_ID < 80100) { $property->setAccessible(true); }
    $iat = time();
    $property->setValue($proof, static function () use ($subject, $iat): array {
        return ['https://issuer.example.test', $subject, $iat, 'provider-session'];
    });
    return $proof;
};
$remote = $testRemote('external-one');
Check::same('external-one', $remote->subject());
$otherRemote = $testRemote('external-two');

$directory = privateDirectory();
try {
    foreach (['memory', 'file'] as $backend) {
        $clock = new TestClock();
        $store = $backend === 'memory' ? new MemoryStore($clock) : new FileStore($directory, 'oidc-links', $clock);
        $accounts = ['alice' => new Account('tenant', 'alice', '1'), 'bob' => new Account('tenant', 'bob', '1')];
        $provider = new CallbackIdentityProvider(
            static function (string $scope, string $identifier, string $password) use (&$accounts): ?Account {
                return $scope === 'tenant' && $password === 'secret' ? ($accounts[$identifier] ?? null) : null;
            },
            static function (string $scope, string $subject) use (&$accounts): ?Account {
                return $scope === 'tenant' ? ($accounts[$subject] ?? null) : null;
            }
        );
        $allowed = true;
        $guard = static function (string $phase, string $scope) use (&$allowed): bool { return $allowed; };
        $sessions = new SessionRegistry($store, $provider, null, $clock);
        $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, null, $clock);
        $links = new LinkRegistry($store, $provider, $sessions, $guard, $clock);
        $alice = $flow->password('tenant', 'alice-browser', 'alice', 'secret')->credential();
        $bob = $flow->password('tenant', 'bob-browser', 'bob', 'secret')->credential();
        Check::same(null, $links->resolve('tenant', $remote));
        $allowed = false;
        Check::throws(SecurityException::class, static function () use ($links, $alice, $remote): void {
            $links->link('tenant', 'alice', $alice->token(), $remote);
        });
        $allowed = true;
        Check::same(true, $links->link('tenant', 'alice', $alice->token(), $remote));
        ++$clock->time;
        Check::same(true, $links->link('tenant', 'alice', $alice->token(), $remote));
        Check::same('alice', $links->resolve('tenant', $remote)->subject());
        Check::same(null, $links->resolve('other-tenant', $remote));
        Check::throws(SecurityException::class, static function () use ($links, $bob, $remote): void {
            $links->link('tenant', 'bob', $bob->token(), $remote);
        });
        Check::same(true, $links->link('tenant', 'bob', $bob->token(), $otherRemote));
        Check::same('bob', $links->resolve('tenant', $otherRemote)->subject());
        Check::throws(SecurityException::class, static function () use ($links, $bob, $remote): void {
            $links->unlink('tenant', 'bob', $bob->token(), $remote);
        });
        Check::same(true, $links->unlink('tenant', 'alice', $alice->token(), $remote));
        Check::same(false, $links->unlink('tenant', 'alice', $alice->token(), $remote));
        Check::same(null, $links->resolve('tenant', $remote));
        Check::same(true, $links->link('tenant', 'alice', $alice->token(), $remote));
        $accounts['alice'] = new Account('tenant', 'alice', '2');
        Check::same(null, $links->resolve('tenant', $remote));
        Check::throws(SecurityException::class, static function () use ($links, $alice, $remote): void {
            $links->unlink('tenant', 'alice', $alice->token(), $remote);
        });
        $fresh = $flow->password('tenant', 'alice-recovery', 'alice', 'secret')->credential();
        $approvals = 0;
        $approve = static function (string $scope, string $subject, string $issuer, string $external,
            array $details) use (&$approvals): bool {
            ++$approvals;
            Check::same('tenant', $scope); Check::same('alice', $subject);
            Check::same('https://issuer.example.test', $issuer); Check::same('external-one', $external);
            Check::same(64, strlen($details['linked_fingerprint']));
            Check::same(64, strlen($details['current_fingerprint']));
            Check::same(true, is_int($details['linked_at']));
            Check::same($approvals === 1 ? 32 : null,
                $details['binding_id'] === null ? null : strlen($details['binding_id']));
            return true;
        };
        $allowed = false;
        Check::throws(SecurityException::class, static function () use ($links, $fresh, $approve): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', 'external-one', $approve);
        });
        $allowed = true;
        Check::throws(SecurityException::class, static function () use ($links, $bob, $approve): void {
            $links->recoverUnlink('tenant', 'bob', $bob->token(), 'https://issuer.example.test', 'external-one', $approve);
        });
        Check::throws(SecurityException::class, static function () use ($links, $fresh, $approve): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', "external\0one", $approve);
        });
        Check::throws(SecurityException::class, static function () use ($links, $alice, $approve): void {
            $links->recoverUnlink('tenant', 'alice', $alice->token(), 'https://issuer.example.test', 'external-one', $approve);
        });
        Check::throws(SecurityException::class, static function () use ($links, $fresh): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', 'external-one',
                static function (): bool { return false; });
        });
        Check::throws(SecurityException::class, static function () use ($links, $fresh): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', 'external-one',
                static function () { return 1; });
        });
        Check::same(0, $approvals);
        Check::same(null, $links->resolve('tenant', $remote));
        Check::throws(SecurityException::class, static function () use ($links, $fresh, &$accounts): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', 'external-one',
                static function () use (&$accounts): bool {
                    $accounts['alice'] = new Account('tenant', 'alice', '3'); return true;
                });
        });
        $fresh = $flow->password('tenant', 'alice-recovery-new', 'alice', 'secret')->credential();
        $key = SoSecurity\Support\Guard::key('federation-link', 'tenant', hash('sha256',
            strlen('tenant') . ':tenant' . strlen('https://issuer.example.test') . ':https://issuer.example.test'
            . strlen('external-one') . ':external-one'));
        Check::throws(SecurityException::class, static function () use ($links, $fresh, $store, $key, $remote): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', 'external-one',
                static function () use ($links, $fresh, $store, $key, $remote): bool {
                    $store->transact($key, static function () {
                        return new SoSecurity\Storage\Change(null, 0, true);
                    });
                    $links->link('tenant', 'alice', $fresh->token(), $remote);
                    return true;
                });
        });
        Check::same('alice', $links->resolve('tenant', $remote)->subject());
        Check::throws(SecurityException::class, static function () use ($links, $fresh, $store, $key): void {
            $links->recoverUnlink('tenant', 'alice', $fresh->token(), 'https://issuer.example.test', 'external-one',
                static function () use ($store, $key): bool {
                    $store->transact($key, static function ($old) {
                        $old['created']++;
                        return new SoSecurity\Storage\Change($old, 0, true);
                    });
                    return true;
                });
        });
        Check::same(true, $links->recoverUnlink('tenant', 'alice', $fresh->token(),
            'https://issuer.example.test', 'external-one', $approve));
        Check::same(1, $approvals);
        Check::same(false, $links->recoverUnlink('tenant', 'alice', $fresh->token(),
            'https://issuer.example.test', 'external-one', $approve));
        Check::same(1, $approvals);
        Check::same(null, $links->resolve('tenant', $remote));
        Check::same(false, $links->matchesCurrentLink('tenant', 'https://issuer.example.test', 'external-one', $accounts['alice']));
        Check::same(true, $links->link('tenant', 'alice', $fresh->token(), $remote));
        $store->transact($key, static function ($old) {
            unset($old['binding']); $old['v'] = 1;
            return new SoSecurity\Storage\Change($old, 0, true);
        });
        Check::same(true, $links->recoverUnlink('tenant', 'alice', $fresh->token(),
            'https://issuer.example.test', 'external-one', $approve));
        Check::same(2, $approvals);
        Check::same(null, $links->resolve('tenant', $remote));
    }
} finally {
    cleanDirectory($directory);
}
echo 'PASS OIDC local link registry: '.Check::$assertions.' assertions PHP '.PHP_VERSION . "\n";
