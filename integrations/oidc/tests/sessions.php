<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__, 3) . '/tests/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\VerifiedLogout;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Support\Guard;

final class FederatedTestFactor implements SecondFactor
{
    public $current;
    public function binding(string $scope, string $subject): ?string { return $this->current; }
    public function verify(string $scope, string $subject, string $expectedBinding, $proof): ?string { return null; }
}

final class InjectingFederatedStore implements AtomicStore
{
    private $inner;
    public $afterWrite;
    public function __construct(AtomicStore $inner) { $this->inner = $inner; }
    public function transact(string $key, callable $callback)
    {
        $result = $this->inner->transact($key, $callback);
        if (strpos($key, 'oidc-sessions:') === 0 && $this->afterWrite !== null) {
            $after = $this->afterWrite; $this->afterWrite = null; $after();
        }
        return $result;
    }
}

$proof = static function (string $type, string $subject, ?string $sid, int $iat) {
    $class = new ReflectionClass($type);
    $value = $class->newInstanceWithoutConstructor();
    $fields = $type === VerifiedSubject::class
        ? ['issuer' => 'https://issuer.example.test', 'subject' => $subject, 'providerSessionId' => $sid, 'issuedAt' => $iat]
        : ['issuer' => 'https://issuer.example.test', 'subject' => $subject, 'sessionId' => $sid, 'issuedAt' => $iat, 'tokenId' => 'logout-test'];
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
    $selected = $argv[2] ?? '';
    foreach ($selected === 'mysql' ? ['mysql'] : ($selected === 'redis' ? ['redis'] : ['memory', 'file']) as $backend) {
        $clock = new TestClock();
        if ($backend === 'redis') {
            $clock->time = time();
            $socket = getenv('SOSECURITY_TEST_OIDC_REDIS_SOCKET');
            if (!is_string($socket) || !preg_match('~\A/tmp/sosecurity-oidc-redis-[A-Za-z0-9_-]+/redis\.sock\z~D', $socket)
                || is_link(dirname($socket)) || !is_file(dirname($socket) . '/oidc-test-owner')) {
                throw new RuntimeException('Only an owned no-TCP local Redis test instance is allowed.');
            }
            $redis = new Redis();
            if (!$redis->connect($socket, 0, 1.0)) { throw new RuntimeException('Cannot connect to owned Redis test instance.'); }
            $store = new RedisStore($redis, 'oidc-sessions-' . hash('sha256', $directory), $clock);
            $store->initialize();
        } elseif ($backend === 'mysql') {
            $socket = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
            if (!is_string($socket) || !preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D', $socket)
                || is_link(dirname($socket)) || !is_file(dirname($socket) . '/account-test-owner')) {
                throw new RuntimeException('Only an owned no-TCP local MySQL test instance is allowed.');
            }
            $pdo = new PDO('mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4',
                'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $store = new MySqlStore($pdo, 'oidc-sessions-' . hash('sha256', $directory), $clock);
        } else {
            $store = $backend === 'memory' ? new MemoryStore($clock) : new FileStore($directory, 'oidc-sessions-test', $clock);
        }
        $accounts = ['alice' => new Account('tenant', 'alice', '1')];
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
        $localSessions = new SessionRegistry($store, $provider, null, $clock);
        $flow = new AuthenticationFlow($store, $provider, $localSessions, $guard, null, $clock);
        $local = $flow->password('tenant', 'browser', 'alice', 'secret')->credential();
        $fence = new LogoutFence($store, $clock);
        $links = new LinkRegistry($store, $provider, $localSessions, $guard, $clock, $fence);
        $factor = new FederatedTestFactor();
        $sessions = new FederatedSessions($store, $provider, $links, $fence, $guard, $factor, $clock, 1800, 28800, 1);
        $remote = $proof(VerifiedSubject::class, 'external-alice', 'provider-sid', $clock->time);
        Check::same(null, $sessions->issue('tenant', $remote));
        Check::same(true, $links->link('tenant', 'alice', $local->token(), $remote));
        $allowed = false;
        Check::throws(SecurityException::class, static function () use ($sessions, $remote): void { $sessions->issue('tenant', $remote); });
        $allowed = true;
        $issued = $sessions->issue('tenant', $remote, 'browser');
        Check::same(true, $issued !== null);
        Check::same(true, strpos($issued->token(), 'sofs_') === 0);
        Check::same(null, $localSessions->verify('tenant', 'alice', $issued->token()));
        Check::same(null, $sessions->verify('tenant', 'bob', $issued->token()));
        Check::same(null, $sessions->verify('tenant', 'alice', $local->token()));
        Check::same('alice', $sessions->verify('tenant', 'alice', $issued->token())->account()->subject());
        Check::same('oidc', $sessions->verify('tenant', 'alice', $issued->token())->method());
        Check::throws(SecurityException::class, static function () use ($sessions, $remote): void { $sessions->issue('tenant', $remote); });

        ++$clock->time;
        $fence->record('tenant', $proof(VerifiedLogout::class, 'external-alice', 'provider-sid', $clock->time));
        Check::same(null, $sessions->verify('tenant', 'alice', $issued->token()));
        if ($backend === 'file') {
            $reopened = new FileStore($directory, 'oidc-sessions-test', $clock);
            $reopenedFence = new LogoutFence($reopened, $clock);
            $reopenedLocal = new SessionRegistry($reopened, $provider, null, $clock);
            $reopenedLinks = new LinkRegistry($reopened, $provider, $reopenedLocal, $guard, $clock, $reopenedFence);
            $reopenedSessions = new FederatedSessions($reopened, $provider, $reopenedLinks, $reopenedFence,
                $guard, $factor, $clock, 1800, 28800, 1);
            Check::same(null, $reopenedSessions->verify('tenant', 'alice', $issued->token()));
        }
        Check::same(null, $sessions->issue('tenant', $remote));
        Check::same(true, $localSessions->verify('tenant', 'alice', $local->token()) !== null);
        ++$clock->time;
        $fresh = $proof(VerifiedSubject::class, 'external-alice', 'provider-sid', $clock->time);
        $next = $sessions->issue('tenant', $fresh);
        Check::same(true, $next !== null);
        Check::same('alice', $sessions->verify('tenant', 'alice', $next->token())->account()->subject());
        Check::same(true, $links->unlink('tenant', 'alice', $local->token(), $fresh));
        Check::same(null, $sessions->verify('tenant', 'alice', $next->token()));
        Check::same(null, $sessions->issue('tenant', $fresh));
        Check::same(true, $links->link('tenant', 'alice', $local->token(), $fresh));
        $third = $sessions->issue('tenant', $fresh);
        Check::same(true, $third !== null);
        Check::same(true, $links->unlink('tenant', 'alice', $local->token(), $fresh));
        Check::same(true, $links->link('tenant', 'alice', $local->token(), $fresh));
        Check::same(null, $sessions->verify('tenant', 'alice', $third->token()));
        $third = $sessions->issue('tenant', $fresh);
        Check::same(true, $third !== null);
        Check::throws(SecurityException::class, static function () use ($links, $local): void {
            $links->recoverUnlink('tenant', 'alice', $local->token(), 'https://issuer.example.test', 'external-alice',
                static function (): bool { return false; });
        });
        Check::same(true, $sessions->verify('tenant', 'alice', $third->token()) !== null);
        Check::same(true, $links->recoverUnlink('tenant', 'alice', $local->token(),
            'https://issuer.example.test', 'external-alice', static function (): bool { return true; }));
        Check::same(null, $sessions->verify('tenant', 'alice', $third->token()));
        Check::same(true, $localSessions->verify('tenant', 'alice', $local->token()) !== null);
        Check::same(true, $links->link('tenant', 'alice', $local->token(), $fresh));
        $third = $sessions->issue('tenant', $fresh);
        Check::same(true, $third !== null);
        $factor->current = 'factor-generation';
        Check::same(null, $sessions->verify('tenant', 'alice', $third->token()));
        Check::same(null, $sessions->issue('tenant', $fresh));
        $factor->current = null;
        $third = $sessions->issue('tenant', $fresh);
        Check::same(true, $third !== null);
        $accounts['alice'] = new Account('tenant', 'alice', '2');
        Check::same(null, $sessions->verify('tenant', 'alice', $third->token()));
        Check::same(null, $sessions->issue('tenant', $fresh));
    }
    $clock = new TestClock();
    $inner = new MemoryStore($clock);
    $store = new InjectingFederatedStore($inner);
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
    $localSessions = new SessionRegistry($store, $provider, null, $clock);
    $flow = new AuthenticationFlow($store, $provider, $localSessions, $guard, null, $clock);
    $local = $flow->password('tenant', 'race-browser', 'alice', 'secret')->credential();
    $fence = new LogoutFence($store, $clock);
    $links = new LinkRegistry($store, $provider, $localSessions, $guard, $clock, $fence);
    $remote = $proof(VerifiedSubject::class, 'external-alice', 'provider-sid', $clock->time);
    Check::same(true, $links->link('tenant', 'alice', $local->token(), $remote));
    $sessions = new FederatedSessions($store, $provider, $links, $fence, $guard, null, $clock);
    $store->afterWrite = static function () use ($clock, $fence, $proof): void {
        ++$clock->time;
        $fence->record('tenant', $proof(VerifiedLogout::class, 'external-alice', 'provider-sid', $clock->time));
    };
    Check::same(null, $sessions->issue('tenant', $remote));
    Check::same(null, $inner->transact(Guard::key('oidc-sessions', 'tenant', 'alice'),
        static function ($old) { return new Change($old, 0, $old); }));
} finally {
    cleanDirectory($directory);
}
echo 'PASS OIDC federated sessions: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
