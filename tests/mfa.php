<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Crypto\Cipher;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Mfa\Totp;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

// RFC 6238 Appendix B: independently specified expected values, including timestamps after 2038.
$vectors = [59 => ['94287082', '46119246', '90693936'], 1111111109 => ['07081804', '68084774', '25091201'],
    1111111111 => ['14050471', '67062674', '99943326'], 1234567890 => ['89005924', '91819424', '93441116'],
    2000000000 => ['69279037', '90698825', '38618901'], 20000000000 => ['65353130', '77737706', '47863826']];
$binarySecrets = ['12345678901234567890', '12345678901234567890123456789012',
    '1234567890123456789012345678901234567890123456789012345678901234'];
// Additional values independently calculated with Python HMAC: exercise a nonzero counter high word.
$largeCounters = [128849018880 => ['55999456', '66351443', '82894678'],
    9223372036854689407 => ['13116625', '97654020', '69687975']];
foreach (['sha1', 'sha256', 'sha512'] as $i => $algorithm) {
    $totp = new Totp($algorithm, 8); $secret = Totp::encodeSecret($binarySecrets[$i]);
    foreach ($vectors as $time => $expected) {
        Check::same($expected[$i], $totp->codeAt($secret, $time));
        Check::same(intdiv($time, 30), $totp->matchingStep($secret, $expected[$i], $time, 0));
    }
    foreach ($largeCounters as $time => $expected) {
        Check::same($expected[$i], $totp->codeAt($secret, $time));
        Check::same(intdiv($time, 30), $totp->matchingStep($secret, $expected[$i], $time, 0));
    }
    $generated = $totp->generateSecret(); Check::same(8, strlen($totp->codeAt($generated, 59)));
}
$totp = new Totp(); $secret = Totp::encodeSecret($binarySecrets[0]);
Check::same('287082', $totp->codeAt($secret, 59));
Check::same(1, $totp->matchingStep($secret, '287082', 60, 1));
Check::same(null, $totp->matchingStep($secret, '287082', 60, 0));
foreach ([null, [], 287082, "287082\n", ' 287082', str_repeat('1', 10000)] as $bad) { Check::same(null, $totp->matchingStep($secret, $bad, 59)); }
foreach ([strtolower($secret), $secret . '=', $secret . 'B', str_repeat('A', 31)] as $bad) {
    Check::throws(ConfigurationException::class, function () use ($totp, $bad) { $totp->codeAt($bad, 59); });
}
Check::throws(ConfigurationException::class, function () { new Totp('md5'); });
Check::throws(ConfigurationException::class, function () { new Totp('sha1', 4); });
Check::throws(ConfigurationException::class, function () use ($totp, $secret) { $totp->matchingStep($secret, '000000', 59, 3); });
Check::throws(ConfigurationException::class, function () use ($totp, $secret) { $totp->codeAt($secret, -1); });
Check::throws(ConfigurationException::class, function () use ($totp, $secret) { $totp->provisioningUri($secret, 'issuer:bad', 'account'); });
parse_str(parse_url($totp->provisioningUri($secret, 'Demo & Co', 'user@example.test'), PHP_URL_QUERY), $parameters);
Check::same('Demo & Co', $parameters['issuer']); Check::same($secret, $parameters['secret']);
echo 'PASS RFC 6238: all 18 SHA-1/256/512 vectors, independent 64-bit counter values, drift and malformed inputs' . "\n";

Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'demo'])->mfa(); });
Check::throws(ConfigurationException::class, function () { new SoSecurity\Configuration\Config(['site' => 'demo', 'mfa' => []]); });
Check::throws(ConfigurationException::class, function () { new SoSecurity\Configuration\Config(['site' => 'demo', 'mfa' => ['issuer' => 'Demo', 'cipher' => 'cipher', 'attempts' => 0]]); });

if (!extension_loaded('sodium')) {
    Check::throws(DependencyException::class, function () { new Cipher('k1', ['k1' => str_repeat('k', 32)], 'test'); });
    echo 'PASS missing ext-sodium: encryption fails explicitly; TOTP calculation remains available' . "\n";
    if (getenv('SOSECURITY_REQUIRE_CRYPTO') === '1') { throw new RuntimeException('Required ext-sodium is missing.'); }
    echo 'NOT RUN encrypted MFA lifecycle: ext-sodium required; ' . Check::$assertions . ' assertions passed on PHP ' . PHP_VERSION . "\n";
    exit;
}

$cipher = new Cipher('old', ['old' => str_repeat('k', 32)], 'mfa-test', 256);
foreach (['', 'hello', "\0\xffsecret", str_repeat('a', 256)] as $plain) {
    $encrypted = $cipher->encrypt($plain, 'tenant:account');
    Check::same($plain, $cipher->decrypt($encrypted, 'tenant:account'));
    Check::same(false, $encrypted === $cipher->encrypt($plain, 'tenant:account'));
    Check::throws(ValidationException::class, function () use ($cipher, $encrypted) { $cipher->decrypt($encrypted, 'other-account'); });
    Check::throws(ValidationException::class, function () use ($encrypted) { (new Cipher('old', ['old' => str_repeat('k', 32)], 'other-purpose', 256))->decrypt($encrypted, 'tenant:account'); });
}
$encrypted = $cipher->encrypt('secret', 'account');
$rotated = new Cipher('new', ['old' => str_repeat('k', 32), 'new' => str_repeat('n', 32)], 'mfa-test', 256);
Check::same('secret', $rotated->decrypt($encrypted, 'account'));
$replacement = $rotated->reencrypt($encrypted, 'account'); Check::same(true, strpos($replacement, 'sosc1.new.') === 0);
Check::same('secret', (new Cipher('new', ['new' => str_repeat('n', 32)], 'mfa-test', 256))->decrypt($replacement, 'account'));
foreach (['sosc2' . substr($encrypted, 5), str_replace('.old.', '.unknown.', $encrypted), $encrypted . '=',
    substr($encrypted, 0, 15) . ($encrypted[15] === 'a' ? 'b' : 'a') . substr($encrypted, 16), str_repeat('a', 10000)] as $bad) {
    Check::throws(ValidationException::class, function () use ($cipher, $bad) { $cipher->decrypt($bad, 'account'); });
}
Check::throws(ValidationException::class, function () use ($cipher) { $cipher->encrypt(str_repeat('x', 257), 'account'); });
Check::throws(ConfigurationException::class, function () { new Cipher('k1', ['k1' => 'short'], 'test'); });
Check::throws(ConfigurationException::class, function () use ($cipher) { serialize($cipher); });
ob_start(); var_dump($cipher); $dump = ob_get_clean(); Check::same(false, strpos($dump, str_repeat('k', 32)) !== false);

function mfaSecret(SoSecurity\Mfa\Enrollment $enrollment): string
{
    parse_str(parse_url($enrollment->provisioningUri(), PHP_URL_QUERY), $parts); return $parts['secret'];
}

$directory = privateDirectory();
try {
    foreach (['memory', 'file'] as $backend) {
        $clock = new TestClock(); $store = $backend === 'memory' ? new MemoryStore($clock) : new FileStore($directory, 'mfa', $clock);
        $mfa = new TotpFactors($store, $cipher, 'Demo', $clock, 300, 3, 60);
        Check::same(false, $mfa->verify('tenant', 'absent', '000000'));
        Check::same(false, $mfa->status('tenant', 'account')['enabled']);
        $enrollment = $mfa->begin('tenant', 'account', 'user@example.test'); $secret = mfaSecret($enrollment);
        Check::throws(ConfigurationException::class, function () use ($enrollment) { serialize($enrollment); });
        ob_start(); var_dump($enrollment); $dump = ob_get_clean(); Check::same(false, strpos($dump, $secret) !== false);
        $code = $totp->codeAt($secret, $clock->time);
        Check::same(null, $mfa->confirm('other-tenant', 'account', $enrollment->id(), $code));
        Check::same(null, $mfa->confirm('tenant', 'other-account', $enrollment->id(), $code));
        Check::same(null, $mfa->confirm('tenant', 'account', 'stale-id', $code));
        Check::same(false, $mfa->status('tenant', 'account')['enabled']);
        $codes = $mfa->confirm('tenant', 'account', $enrollment->id(), $code); Check::same(10, count($codes));
        Check::same(null, $mfa->confirm('tenant', 'account', $enrollment->id(), $code));
        Check::same(true, $mfa->status('tenant', 'account')['enabled']);
        Check::same(false, $mfa->verify('tenant', 'account', $code)); // enrollment confirmation also consumes the time step
        Check::same(true, $mfa->verifyRecovery('tenant', 'account', $codes[0]));
        Check::same(false, $mfa->verifyRecovery('tenant', 'account', $codes[0]));
        Check::same(9, $mfa->status('tenant', 'account')['recovery_remaining']);
        $clock->time += 30; $code = $totp->codeAt($secret, $clock->time);
        Check::same(true, $mfa->verify('tenant', 'account', $code));
        Check::same(false, $mfa->verify('tenant', 'account', $code));
        Check::same(false, $mfa->verify('tenant', 'account', []));
        Check::same(false, $mfa->verify('tenant', 'account', 'bad'));
        Check::same(60, $mfa->status('tenant', 'account')['retry_after']);
        Check::same(false, $mfa->verifyRecovery('tenant', 'account', $codes[1]));
        Check::throws(SecurityException::class, function () use ($mfa) { $mfa->begin('tenant', 'account', 'user@example.test'); });
        $clock->time += 60; $code = $totp->codeAt($secret, $clock->time);
        $newCodes = $mfa->regenerateRecoveryCodes('tenant', 'account', $code); Check::same(10, count($newCodes));
        Check::same(false, $mfa->verifyRecovery('tenant', 'account', $codes[1]));
        Check::same(true, $mfa->verifyRecovery('tenant', 'account', $newCodes[0]));

        // Snapshot exposes only ciphertext and high-entropy recovery digests, including on disk.
        $key = Guard::key('mfa-totp', 'tenant', 'account');
        $state = $store->transact($key, function ($state) { return new Change($state, 0, $state); });
        Check::same(false, strpos(json_encode($state), $secret) !== false);
        Check::same(false, strpos(json_encode($state), $newCodes[1]) !== false);
        $newManager = new TotpFactors($store, $rotated, 'Demo', $clock);
        Check::same(true, $newManager->reencrypt('tenant', 'account'));
        $newKeyOnly = new Cipher('new', ['new' => str_repeat('n', 32)], 'mfa-test', 256);
        $newManager = new TotpFactors($store, $newKeyOnly, 'Demo', $clock);
        $clock->time += 30; Check::same(true, $newManager->verify('tenant', 'account', $totp->codeAt($secret, $clock->time)));

        $pending = $newManager->begin('tenant', 'account', 'replacement@example.test'); $newSecret = mfaSecret($pending);
        Check::same(true, $newManager->status('tenant', 'account')['enabled']);
        $clock->time += 30; Check::same(true, $newManager->verify('tenant', 'account', $totp->codeAt($secret, $clock->time)));
        $replacedCodes = $newManager->confirm('tenant', 'account', $pending->id(), $totp->codeAt($newSecret, $clock->time));
        Check::same(10, count($replacedCodes)); Check::same(false, $newManager->verifyRecovery('tenant', 'account', $newCodes[1]));
        Check::same(true, $newManager->disable('tenant', 'account', $replacedCodes[0], true));
        Check::same(false, $newManager->status('tenant', 'account')['enabled']);
        Check::same(false, $newManager->verifyRecovery('tenant', 'account', $replacedCodes[1]));

        $pending = $newManager->begin('tenant', 'expires', 'expiry@example.test'); $clock->time += 300;
        Check::same(null, $newManager->confirm('tenant', 'expires', $pending->id(), $totp->codeAt(mfaSecret($pending), $clock->time)));
        Check::same(false, $newManager->status('tenant', 'expires')['pending']);
        $pending = $newManager->begin('tenant', 'cancel', 'cancel@example.test'); $newManager->revoke('tenant', 'cancel');
        Check::same(null, $newManager->confirm('tenant', 'cancel', $pending->id(), $totp->codeAt(mfaSecret($pending), $clock->time)));

        $pending = $newManager->begin('tenant', 'corrupt', 'corrupt@example.test');
        $corruptKey = Guard::key('mfa-totp', 'tenant', 'corrupt');
        $store->transact($corruptKey, function ($state) { $state['pending']['profile']['digits'] = 4; return new Change($state, 0, null); });
        Check::throws(StorageException::class, function () use ($newManager) { $newManager->status('tenant', 'corrupt'); });
        $store->transact($corruptKey, function () { return new Change(['v' => 1], 0, null); });
        Check::throws(StorageException::class, function () use ($newManager) { $newManager->verify('tenant', 'corrupt', '000000'); });

        $pending = $newManager->begin('tenant', 'clock', 'clock@example.test'); --$clock->time;
        Check::throws(SecurityException::class, function () use ($newManager) { $newManager->status('tenant', 'clock'); });
        echo 'PASS ' . $backend . ' encrypted MFA: confirmation, replay, shared budget, recovery rotation, replacement, expiry, revocation, key rotation and corrupt state' . "\n";
    }

    $clock = new TestClock(); $store = new FileStore($directory, 'factory', $clock);
    $security = SoSecurity\Security::fromArray(['site' => 'factory', 'storage' => ['driver' => 'file', 'directory' => $directory],
        'mfa' => ['issuer' => 'Demo', 'cipher' => 'cipher']], ['cipher' => $cipher], $clock);
    Check::same(false, $security->mfa()->status('tenant', 'account')['enabled']);
    $security->mfa()->begin('tenant', 'account', 'factory@example.test');
    Check::same(true, $security->mfa()->status('tenant', 'account')['pending']);
    $bad = SoSecurity\Security::fromArray(['site' => 'bad', 'storage' => ['driver' => 'memory'], 'mfa' => ['issuer' => 'Demo', 'cipher' => 'cipher']], ['cipher' => $cipher]);
    Check::throws(ConfigurationException::class, function () use ($bad) { $bad->mfa(); });
    $failing = new class implements AtomicStore { public function transact(string $key, callable $callback) { throw new StorageException('Offline', 'storage.test'); } };
    $mfa = new TotpFactors($failing, $cipher, 'Demo');
    Check::throws(StorageException::class, function () use ($mfa) { $mfa->verify('tenant', 'account', '000000'); });
    Check::throws(StorageException::class, function () use ($mfa) { $mfa->begin('tenant', 'account', 'offline@example.test'); });

    require dirname(__DIR__) . '/examples/mfa-account.php';
    $exampleStore = new MemoryStore($clock); $exampleMfa = new TotpFactors($exampleStore, $cipher, 'Demo', $clock);
    $yes = static function (): bool { return true; };
    foreach ([false, null, 1, 'true'] as $unconfirmed) {
        $reject = static function () use ($unconfirmed) { return $unconfirmed; };
        Check::throws(SecurityException::class, function () use ($exampleMfa, $reject, $yes) {
            SoSecurity\Examples\beginMfaEnrollment($exampleMfa, 'tenant', 'example', 'example@test', $reject, $yes, $yes);
        });
        Check::same(false, $exampleMfa->status('tenant', 'example')['pending']);
    }
    $pending = SoSecurity\Examples\beginMfaEnrollment($exampleMfa, 'tenant', 'example', 'example@test', $yes, $yes, $yes);
    $notification = static function (string $event): bool { Check::same('mfa.changed', $event); return true; };
    $codes = SoSecurity\Examples\confirmMfaEnrollment($exampleMfa, 'tenant', 'example', $pending->id(), $totp->codeAt(mfaSecret($pending), $clock->time), $yes, $yes, $yes, $yes, $notification);
    Check::same(10, count($codes));
    $completed = 0;
    $complete = static function () use (&$completed): bool { ++$completed; return true; };
    Check::same(false, SoSecurity\Examples\verifyPendingMfaLogin($exampleMfa, 'tenant', 'example', 'wrong', true, $yes, $yes, $yes, $complete));
    Check::same(0, $completed);
    Check::same(true, SoSecurity\Examples\verifyPendingMfaLogin($exampleMfa, 'tenant', 'example', $codes[0], true, $yes, $yes, $yes, $complete));
    Check::same(1, $completed);
} finally { cleanDirectory($directory); }
echo 'PASS encryption/MFA: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "\n";
