<?php
declare(strict_types=1);
if ($argc !== 4) { fwrite(STDERR, "Expected autoload, private directory, and action.\n"); exit(2); }
require $argv[1];
require dirname(__DIR__, 3) . '/tests/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\VerifiedLogout;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Support\Guard;

final class PausingStore implements AtomicStore
{
    private $inner;
    private $directory;
    private $armed;
    public function __construct(AtomicStore $inner, string $directory, bool $armed)
    {
        $this->inner = $inner; $this->directory = $directory; $this->armed = $armed;
    }
    public function transact(string $key, callable $callback)
    {
        $result = $this->inner->transact($key, $callback);
        if ($this->armed && strpos($key, 'oidc-sessions:') === 0) {
            $this->armed = false;
            if (file_put_contents($this->directory . '/ready', '1') !== 1) { throw new RuntimeException('Cannot signal the process race.'); }
            $deadline = microtime(true) + 10.0;
            while (!is_file($this->directory . '/go')) {
                if (microtime(true) >= $deadline) { throw new RuntimeException('Process race was not released.'); }
                usleep(10000);
            }
        }
        return $result;
    }
}

$proof = static function (string $type, int $iat) {
    $class = new ReflectionClass($type);
    $value = $class->newInstanceWithoutConstructor();
    $fields = $type === VerifiedSubject::class
        ? ['issuer' => 'https://issuer.example.test', 'subject' => 'external-alice',
            'providerSessionId' => 'provider-sid', 'issuedAt' => $iat]
        : ['issuer' => 'https://issuer.example.test', 'subject' => 'external-alice',
            'sessionId' => 'provider-sid', 'issuedAt' => $iat, 'tokenId' => 'process-logout'];
    $parts = $type === VerifiedSubject::class
        ? [$fields['issuer'], $fields['subject'], $fields['issuedAt'], $fields['providerSessionId']]
        : [$fields['issuer'], $fields['subject'], $fields['sessionId'], $fields['tokenId'], $fields['issuedAt']];
    $property = $class->getProperty('read');
    if (PHP_VERSION_ID < 80100) { $property->setAccessible(true); }
    $property->setValue($value, static function () use ($parts): array { return $parts; });
    return $value;
};

umask(0077);
$directory = $argv[2];
$action = $argv[3];
$mysqlSocket = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
$redisSocket = getenv('SOSECURITY_TEST_OIDC_REDIS_SOCKET');
if (is_string($redisSocket) && $redisSocket !== '') {
    if (!preg_match('~\A/tmp/sosecurity-oidc-redis-[A-Za-z0-9_-]+/redis\.sock\z~D', $redisSocket)
        || is_link(dirname($redisSocket)) || !is_file(dirname($redisSocket) . '/oidc-test-owner')) {
        throw new RuntimeException('Only an owned no-TCP local Redis test instance is allowed.');
    }
    $redis = new Redis();
    if (!$redis->connect($redisSocket, 0, 1.0)) { throw new RuntimeException('Cannot connect to owned Redis test instance.'); }
    $disk = new RedisStore($redis, 'oidc-process-' . hash('sha256', $directory));
    if ($action === 'setup') { $disk->initialize(); }
} elseif (is_string($mysqlSocket) && $mysqlSocket !== '') {
    if (!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D', $mysqlSocket)
        || is_link(dirname($mysqlSocket)) || !is_file(dirname($mysqlSocket) . '/account-test-owner')) {
        throw new RuntimeException('Only an owned no-TCP local MySQL test instance is allowed.');
    }
    $pdo = new PDO('mysql:unix_socket=' . $mysqlSocket . ';dbname=sosecurity_test;charset=utf8mb4',
        'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $disk = new MySqlStore($pdo, 'oidc-process-' . hash('sha256', $directory));
} else {
    $disk = new FileStore($directory, 'oidc-process-test');
}
$store = new PausingStore($disk, $directory, in_array($action, ['issue_race', 'verify_race'], true));
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
$local = new SessionRegistry($store, $provider);
$fence = new LogoutFence($store);
$links = new LinkRegistry($store, $provider, $local, $guard, null, $fence);
$sessions = new FederatedSessions($store, $provider, $links, $fence, $guard);

if ($action === 'setup') {
    $flow = new AuthenticationFlow($store, $provider, $local, $guard);
    $credential = $flow->password('tenant', 'browser', 'alice', 'secret')->credential();
    if ($credential === null || !$links->link('tenant', 'alice', $credential->token(), $proof(VerifiedSubject::class, time()))) {
        throw new RuntimeException('Could not establish a local federation link.');
    }
    if (file_put_contents($directory . '/local-token', $credential->token()) !== strlen($credential->token())) {
        throw new RuntimeException('Cannot save the private test session.');
    }
    echo "ready\n";
} elseif ($action === 'relink') {
    $token = file_get_contents($directory . '/local-token');
    $remote = $proof(VerifiedSubject::class, time());
    if (!$links->unlink('tenant', 'alice', $token, $remote) || !$links->link('tenant', 'alice', $token, $remote)) {
        throw new RuntimeException('Could not replace the current link.');
    }
    echo "relinked\n";
} elseif ($action === 'logout') {
    $fence->record('tenant', $proof(VerifiedLogout::class, time()));
    echo "logged_out\n";
} elseif ($action === 'issue' || $action === 'issue_race') {
    $credential = $sessions->issue('tenant', $proof(VerifiedSubject::class, time()));
    if ($action === 'issue_race') {
        if ($credential !== null) { throw new RuntimeException('Racing issue returned a usable credential.'); }
        $state = $disk->transact(Guard::key('oidc-sessions', 'tenant', 'alice'),
            static function ($old) { return new Change($old, 0, $old); });
        if ($state !== null) { throw new RuntimeException('Rejected racing issue retained a session.'); }
        echo "rejected\n";
    } else {
        if ($credential === null || file_put_contents($directory . '/token', $credential->token()) !== 102) {
            throw new RuntimeException('Could not issue a baseline federated session.');
        }
        echo "issued\n";
    }
} elseif ($action === 'verify' || $action === 'verify_race') {
    $token = file_get_contents($directory . '/token');
    if (!is_string($token)) { throw new RuntimeException('Missing private test credential.'); }
    $verified = $sessions->verify('tenant', 'alice', $token);
    if ($action === 'verify_race' && $verified !== null) { throw new RuntimeException('Racing verify accepted revoked authority.'); }
    if ($action === 'verify' && $verified === null) { throw new RuntimeException('Baseline federated session was rejected.'); }
    echo $action === 'verify_race' ? "rejected\n" : "verified\n";
} else {
    throw new RuntimeException('Unknown process action.');
}
