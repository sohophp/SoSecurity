<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Storage\Change;

$directory = privateDirectory();
try {
    ini_set('session.save_path', $directory);
    SessionSecurity::configure(false);
    session_id('attackerchosen123456789012345678');
    session_start();
    Check::same(false, session_id() === 'attackerchosen123456789012345678');
    $original = session_id(); $_SESSION['host-data'] = 'preserve';
    $clock = new TestClock(); $session = new SessionSecurity(10, 20, 'test', $clock);
    Check::same(true, $session->touch());
    $clock->time += 9; Check::same(true, $session->touch());
    $clock->time += 9; Check::same(true, $session->touch());
    $clock->time += 2; Check::same(false, $session->touch());
    $clock->time++; Check::same(false, $session->touch());
    $session->rotate(); Check::same(false, $original === session_id());
    Check::same('preserve', $_SESSION['host-data']); Check::same(true, $session->touch());
    Check::same(true, strpos(SessionSecurity::cookieHeader(false), 'SameSite=Lax') !== false);
    $clock->time += 10; Check::same(false, $session->touch());
    $session->rotate(); $session->invalidate(); Check::same(false, $session->touch());
    Check::throws(RuntimeException::class, function () { SessionSecurity::configure(); });
    $store = new SessionStore('test', $clock);
    $csrf = new SoSecurity\Csrf\CsrfTokens($store, 30, 4, $clock);
    $token = $csrf->issue('form', 'binding'); Check::same(true, $csrf->verify('form', 'binding', $token));
    Check::same('preserve', $_SESSION['host-data']);
    $clock->time += 30; Check::same(false, $csrf->verify('form', 'binding', $token));
    for ($i = 0; $i < 128; ++$i) {
        $store->transact('scope-' . $i, function () { return new Change(['n' => 1], 0, null); });
    }
    Check::throws(StorageException::class, function () use ($store) {
        $store->transact('overflow', function () { return new Change(['n' => 1], 0, null); });
    });
    session_write_close();
    Check::throws(StorageException::class, function () use ($store) { $store->transact('key', function () {}); });
    Check::throws(RuntimeException::class, function () use ($session) { $session->touch(); });
    echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " session integration assertions passed\n";
} finally {
    if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
    cleanDirectory($directory);
}
