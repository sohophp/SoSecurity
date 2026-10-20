<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\Password\PasswordBlocklist;
use SoSecurity\Password\PwnedPasswords;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;

$bcrypt = new PasswordHasher('bcrypt', ['cost' => 10]);
$candidate = 'A long unique test phrase 27!';
Check::same(72, $bcrypt->maximumBytes());
Check::same([], PasswordPolicy::forHasher($bcrypt)->errors($candidate));
Check::throws(ConfigurationException::class, function () use ($bcrypt) { PasswordPolicy::forHasher($bcrypt, 15, 73); });
Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'p', 'password' => ['maximum_bytes' => 73]]); });
$legacy = new PasswordPolicy(); Check::same([], $legacy->errors(str_repeat('a', 15)));
$builtin = PasswordBlocklist::baseline(); Check::same(true, $builtin->count() > 7000);
Check::same(true, $builtin->contains('passwordpassword')); Check::same(false, $builtin->contains('unique passwordpassword phrase 59!'));
$checks = 0; $callback = function (string $password) use (&$checks): bool { ++$checks; return $password === 'Leaked-test-password-29!'; };
$policy = PasswordPolicy::forHasher($bcrypt, 15, null, $builtin, $callback);
Check::same(['password.weak'], $policy->errors('passwordpassword')); Check::same(0, $checks);
Check::same(['password.too_long'], $policy->errors(str_repeat('x', 1048576))); Check::same(0, $checks);
Check::same(['password.too_short'], $policy->errors('short')); Check::same(0, $checks);
Check::same(['password.encoding'], $policy->errors("A long \xff invalid password")); Check::same(0, $checks);
Check::same(['password.compromised'], $policy->errors('Leaked-test-password-29!')); Check::same(1, $checks);
Check::same([], $policy->errors($candidate)); Check::same(2, $checks);
Check::same(['password.compromised'], $policy->errors($candidate, function (): bool { return true; }));
Check::same(['password.weak'], SoSecurity\Security::fromArray(['site' => 'p'])->passwordPolicy()->errors('passwordpassword'));
Check::same([], SoSecurity\Security::fromArray(['site' => 'p', 'password' => ['blocklist' => null]])->passwordPolicy()->errors('passwordpassword'));
$factory = SoSecurity\Security::fromArray(['site' => 'p', 'password' => ['blocklist' => 'local', 'breach_checker' => 'breach']],
    ['local' => PasswordBlocklist::fromPasswords(['my-service-password']), 'breach' => $callback]);
Check::same(['password.weak'], $factory->passwordPolicy()->errors('my-service-password')); Check::same([], $factory->passwordPolicy()->errors($candidate));
foreach (['blocklist', 'breach_checker'] as $field) {
    Check::throws(ConfigurationException::class, function () use ($field) { SoSecurity\Security::fromArray(['site' => 'p', 'password' => [$field => 'missing']])->passwordPolicy(); });
}
foreach ([['minimum' => 7], ['maximum_bytes' => null], ['blocklist' => false], ['breach_checker' => []]] as $bad) {
    Check::throws(ConfigurationException::class, function () use ($bad) { SoSecurity\Security::fromArray(['site' => 'p', 'password' => $bad]); });
}
foreach ([function () { return null; }, function () { throw new RuntimeException('PRIVATE-CANDIDATE-DO-NOT-LOG'); }] as $failure) {
    try { $policy->errors($candidate, $failure); throw new LogicException('Expected failure.'); }
    catch (DependencyException $e) { Check::same('password.breach_unavailable', $e->reason()); Check::same(null, $e->getPrevious()); Check::same(false, strpos($e->getMessage(), 'PRIVATE') !== false); }
}
$directory = privateDirectory();
try {
    $path = $directory . '/blocklist'; $body = hash('sha256', 'my-site-test-password') . "\r\n" . strtoupper(hash('sha256', $candidate)) . "\r\n";
    file_put_contents($path, $body); $list = PasswordBlocklist::fromFile($path, hash('sha256', $body));
    Check::same(2, $list->count()); Check::same(true, $list->contains($candidate)); Check::same(false, $list->contains($candidate . 'x'));
    Check::throws(DependencyException::class, function () use ($path) { PasswordBlocklist::fromFile($path, str_repeat('0', 64)); });
    foreach (['', 'bad', hash('sha256', $candidate) . "\n\n"] as $bad) {
        file_put_contents($path, $bad); Check::throws(DependencyException::class, function () use ($path, $bad) { PasswordBlocklist::fromFile($path, hash('sha256', $bad)); });
    }
    Check::throws(ConfigurationException::class, function () { PasswordBlocklist::fromFile('php://memory', str_repeat('0', 64)); });
    symlink($path, $directory . '/link'); Check::throws(DependencyException::class, function () use ($directory, $body) { PasswordBlocklist::fromFile($directory . '/link', hash('sha256', $body)); });
} finally { cleanDirectory($directory); }
Check::throws(ConfigurationException::class, function () { new PasswordBlocklist(['not-a-hash']); });
Check::throws(ConfigurationException::class, function () { PasswordBlocklist::fromPasswords([null]); });
Check::throws(ConfigurationException::class, function () use ($builtin) { serialize($builtin); });

$sent = []; $suffix = substr(strtoupper(sha1($candidate)), 5);
$breach = new PwnedPasswords(function (string $prefix, array $headers) use (&$sent, $suffix): string {
    $sent[] = [$prefix, $headers]; return $suffix . ":3\r\n" . str_repeat('0', 35) . ":0\r\n";
});
Check::same(true, $breach($candidate)); Check::same([[substr(strtoupper(sha1($candidate)), 0, 5), ['Add-Padding' => 'true', 'Accept' => 'text/plain']]], $sent);
Check::same(false, strpos(json_encode($sent), $candidate) !== false); Check::same(false, strpos(json_encode($sent), $suffix) !== false);
Check::same(false, (new PwnedPasswords(function () use ($suffix) { return $suffix . ':0'; }))($candidate));
Check::same(false, (new PwnedPasswords(function () { return str_repeat('0', 35) . ':4'; }))($candidate));
foreach ([null, [], '', str_repeat('x', 262145), 'invalid', $suffix . ':00', $suffix . ':1000000000000', $suffix . ':1' . "\ninvalid", $suffix . ':1' . "\n" . $suffix . ':2', $suffix . ':1' . "\n\n"] as $bad) {
    Check::throws(DependencyException::class, function () use ($bad, $candidate) { (new PwnedPasswords(function () use ($bad) { return $bad; }))($candidate); });
}
try { (new PwnedPasswords(function () { throw new RuntimeException('PRIVATE-CANDIDATE-DO-NOT-LOG'); }))($candidate); }
catch (DependencyException $e) { Check::same(null, $e->getPrevious()); Check::same('password.breach_unavailable', $e->reason()); Check::same(false, strpos($e->getMessage(), 'PRIVATE') !== false); }
foreach (['', str_repeat('x', 4097), "invalid\xff", "with\0NUL"] as $bad) {
    Check::throws(ValidationException::class, function () use ($breach, $bad) { $breach($bad); });
}
Check::throws(ConfigurationException::class, function () { new PwnedPasswords(null, 499); });
Check::throws(ConfigurationException::class, function () use ($breach) { serialize($breach); });
$hash = $bcrypt->hash($candidate); Check::same(true, $bcrypt->verify($candidate, $hash));
Check::same(false, $bcrypt->verify($candidate, str_replace('$2y$10$', '$2y$17$', $hash)));
Check::same(false, $bcrypt->verify($candidate, '$argon2id$v=19$m=999999,t=10,p=4$' . str_repeat('A', 22) . '$' . str_repeat('A', 43)));
Check::same(false, $bcrypt->verify($candidate, str_repeat('x', 4096)));
Check::same(true, $bcrypt->verify($candidate, str_replace('$2y$', '$2a$', $hash)));
if (defined('PASSWORD_ARGON2ID')) {
    $argon = new PasswordHasher('argon2id'); $factory = SoSecurity\Security::fromArray(['site' => 'p', 'password' => ['profile' => 'argon2id']]);
    Check::same(4096, $argon->maximumBytes()); Check::same(4096, $factory->config()->password()['maximum_bytes']);
    $long = str_repeat('Long unique test phrase. ', 5); Check::same([], $factory->passwordPolicy()->errors($long));
    Check::same(true, $argon->verify($long, $argon->hash($long)));
    $strong = (new PasswordHasher('argon2id', ['memory_cost' => 32768]))->hash($candidate);
    Check::same(false, $argon->needsRehash($strong)); Check::same(null, $argon->verifyAndUpgrade($candidate, $strong)->replacementHash);
    $mixed = new PasswordHasher('argon2id', ['time_cost' => 3]); Check::same(false, $mixed->needsRehash($strong));
    Check::same(true, $mixed->needsRehash($argon->hash($candidate)));
} else {
    Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'p', 'password' => ['profile' => 'argon2id']]); });
    echo "NOT APPLICABLE Argon2id execution on this build; explicit profile refusal verified\n";
}
$diagnostics = array_column(SoSecurity\Security::fromArray(['site' => 'p'])->diagnose(), null, 'check');
Check::same('manual', $diagnostics['password.blocklist']['status']); Check::same('not_configured', $diagnostics['password.breach']['status']);
echo 'PASS password refinement: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "\n";
