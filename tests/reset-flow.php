<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require dirname(__DIR__) . '/examples/password-reset.php';

use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\ResetTokens;
use SoSecurity\Storage\MemoryStore;
use function SoSecurity\Examples\resetPassword;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec('CREATE TABLE accounts (id TEXT PRIMARY KEY, version INTEGER NOT NULL, password_hash TEXT NOT NULL)');
$pdo->exec("INSERT INTO accounts VALUES ('demo', 1, 'OLD')");
$tokens = new ResetTokens(new MemoryStore());
$hasher = new PasswordHasher('bcrypt', ['cost' => 10]);
$first = $tokens->issue('demo:1'); $second = $tokens->issue('demo:1');
Check::same('password.invalid', resetPassword($pdo, $tokens, $hasher, 'demo', 1, $first, 'short'));
Check::same('reset.applied', resetPassword($pdo, $tokens, $hasher, 'demo', 1, $first, 'Replacement-password-one'));
Check::same('reset.invalid', resetPassword($pdo, $tokens, $hasher, 'demo', 1, $first, 'Replacement-password-two'));
Check::same('reset.invalid', resetPassword($pdo, $tokens, $hasher, 'demo', 1, $second, 'Replacement-password-two'));
$row = $pdo->query("SELECT * FROM accounts WHERE id='demo'")->fetch(PDO::FETCH_ASSOC);
Check::same(2, (int) $row['version']); Check::same(true, $hasher->verify('Replacement-password-one', $row['password_hash']));
// The host changed the row after this token was issued: version CAS protects the newer password.
$stale = $tokens->issue('demo:2'); $pdo->exec("UPDATE accounts SET version=3, password_hash='NEWER' WHERE id='demo'");
Check::same('reset.conflict', resetPassword($pdo, $tokens, $hasher, 'demo', 2, $stale, 'Replacement-password-two'));
Check::same('NEWER', $pdo->query("SELECT password_hash FROM accounts WHERE id='demo'")->fetchColumn());
$pdo->beginTransaction();
$token = $tokens->issue('demo:3');
Check::same('reset.applied', resetPassword($pdo, $tokens, $hasher, 'demo', 3, $token, 'Replacement-password-three'));
Check::same(true, $pdo->inTransaction());
$pdo->rollBack();
Check::same(3, (int) $pdo->query("SELECT version FROM accounts WHERE id='demo'")->fetchColumn());
Check::same(false, $tokens->consume('demo:3', $token));
// Cleanup can fail after the database changed. Report the committed result instead of implying no update.
$cleanupFailure = new class implements SoSecurity\Storage\AtomicStore {
    private $memory;
    public function __construct() { $this->memory = new MemoryStore(); }
    public function transact(string $key, callable $callback) {
        return $this->memory->transact($key, function ($value) use ($callback) {
            $change = $callback($value);
            if ($change->result() === null) { throw new SoSecurity\Storage\StorageException('cleanup outage'); }
            return $change;
        });
    }
};
$cleanupTokens = new ResetTokens($cleanupFailure);
$cleanupToken = $cleanupTokens->issue('demo:3');
Check::same('reset.applied_cleanup_pending', resetPassword($pdo, $cleanupTokens, $hasher, 'demo', 3, $cleanupToken, 'Replacement-password-cleanup'));
Check::same(4, (int) $pdo->query("SELECT version FROM accounts WHERE id='demo'")->fetchColumn());
// A host SQL failure does not restore a consumed token.
$token = $tokens->issue('demo:4'); $pdo->exec('DROP TABLE accounts');
Check::throws(PDOException::class, function () use ($pdo, $tokens, $hasher, $token) {
    resetPassword($pdo, $tokens, $hasher, 'demo', 4, $token, 'Replacement-password-four');
});
Check::same(false, $tokens->consume('demo:4', $token));
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " reset host-CAS assertions passed\n";
