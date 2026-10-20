<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require dirname(__DIR__) . '/examples/leased-work.php';
use SoSecurity\Concurrency\LeaseManager;
use SoSecurity\Concurrency\LeasePolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use function SoSecurity\Examples\Leases\claim;
use function SoSecurity\Examples\Leases\write;
use function SoSecurity\Examples\Leases\renew;
use function SoSecurity\Examples\Leases\retire;

$mysql = ($argv[1] ?? '') === 'mysql';
if ($mysql) {
    $pdo = new PDO('mysql:unix_socket=' . getenv('SOSECURITY_TEST_MYSQL_SOCKET') . ';dbname=sosecurity_test;charset=utf8mb4', 'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    $pdo->exec('DROP TABLE IF EXISTS jobs');
    $pdo->exec('CREATE TABLE jobs(tenant VARCHAR(255) NOT NULL,id VARCHAR(255) NOT NULL,lease_epoch VARCHAR(32) NOT NULL,fence BIGINT NOT NULL,lease_digest VARCHAR(64) NOT NULL,lease_until BIGINT NOT NULL,revision BIGINT NOT NULL,output MEDIUMTEXT NOT NULL,PRIMARY KEY(tenant,id)) ENGINE=InnoDB');
} else {
    $pdo = PHP_VERSION_ID >= 80500 ? PDO::connect('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]) : new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('CREATE TABLE jobs(tenant TEXT NOT NULL,id TEXT NOT NULL,lease_epoch TEXT NOT NULL,fence INTEGER NOT NULL,lease_digest TEXT NOT NULL,lease_until INTEGER NOT NULL,revision INTEGER NOT NULL,output TEXT NOT NULL,PRIMARY KEY(tenant,id))');
}
$clock = new TestClock(); $clock->time = time(); $store = new SoSecurity\Storage\MemoryStore($clock); $manager = new LeaseManager($store, new LeasePolicy(1, 10, 60), $clock); $epoch = $manager->initialize('tenant', 'a');
$insert = $pdo->prepare('INSERT INTO jobs VALUES(?,?,?,0,?,0,1,?)'); $insert->execute(['tenant','a',$epoch,'','Original']); $insert->execute(['other','a',$epoch,'','Other tenant']);
$snapshot = static function () use ($pdo) { return $pdo->query('SELECT * FROM jobs ORDER BY tenant,id')->fetchAll(PDO::FETCH_ASSOC); };
$transaction = static function (callable $operation) use ($pdo) { $pdo->beginTransaction(); try { $result = $operation(); $pdo->commit(); return $result; } catch (Throwable $e) { $pdo->rollBack(); throw $e; } };
$first = $manager->acquire('tenant', 'a', 'first');
$earlyLedger = $store->transact(SoSecurity\Support\Guard::key('leases','tenant','a'), static function ($state) { return new SoSecurity\Storage\Change($state, 0, $state); });
Check::throws(ConfigurationException::class, function () use ($pdo, $manager, $first) { claim($pdo, $manager, 'tenant', 'a', 'first', $first->token()); });
$verified = $transaction(static function () use ($pdo, $manager, $first) { return claim($pdo, $manager, 'tenant', 'a', 'first', $first->token()); });
$transaction(static function () use ($pdo, $verified) { write($pdo, $verified, 'tenant', 'a', 1, 'First'); });
Check::same('First', $pdo->query("SELECT output FROM jobs WHERE tenant='tenant'")->fetchColumn()); Check::same('Other tenant', $pdo->query("SELECT output FROM jobs WHERE tenant='other'")->fetchColumn());
$before = $snapshot(); Check::throws(SecurityException::class, function () use ($transaction, $pdo, $verified) { $transaction(static function () use ($pdo, $verified) { write($pdo, $verified, 'tenant', 'a', 1, 'Stale revision'); }); }); Check::same($before, $snapshot());
Check::same($verified->expiresAt(), $transaction(static function () use ($pdo, $manager, $first) { return renew($pdo, $manager, 'tenant', 'a', 'first', $first->token()); })->expiresAt());
// Simulate a suspended worker that had already passed its shared-store check before replacement.
Check::same(true, $manager->release('tenant', 'a', 'first', $first->token())); $second = $manager->acquire('tenant', 'a', 'second');
$transaction(static function () use ($pdo, $manager, $second) { claim($pdo, $manager, 'tenant', 'a', 'second', $second->token()); });
$before = $snapshot(); Check::throws(SecurityException::class, function () use ($transaction, $pdo, $verified) { $transaction(static function () use ($pdo, $verified) { write($pdo, $verified, 'tenant', 'a', 2, 'Paused old writer'); }); }); Check::same($before, $snapshot());
$transaction(static function () use ($pdo, $second) { write($pdo, $second, 'tenant', 'a', 2, 'Second'); });
// Retiring the old lease must not retire the replacement's SQL authority.
$transaction(static function () use ($pdo, $verified) { retire($pdo, $verified, 'tenant', 'a'); });
$transaction(static function () use ($pdo, $second) { write($pdo, $second, 'tenant', 'a', 3, 'Third'); });
$transaction(static function () use ($pdo, $second) { retire($pdo, $second, 'tenant', 'a'); });
Check::throws(SecurityException::class, function () use ($transaction, $pdo, $second) { $transaction(static function () use ($pdo, $second) { write($pdo, $second, 'tenant', 'a', 4, 'Retired'); }); });
Check::throws(SecurityException::class, function () use ($transaction, $pdo, $manager, $second) { $transaction(static function () use ($pdo, $manager, $second) { renew($pdo, $manager, 'tenant', 'a', 'second', $second->token()); }); });
// Restoring an old lease-store backup can revive a shared credential, but not its superseded SQL fence.
$latestLedger = $store->transact(SoSecurity\Support\Guard::key('leases','tenant','a'), static function ($state) { return new SoSecurity\Storage\Change($state, 0, $state); });
$store->transact(SoSecurity\Support\Guard::key('leases','tenant','a'), static function () use ($earlyLedger) { return new SoSecurity\Storage\Change($earlyLedger, 0, null); });
$stale = $manager->verify('tenant','a','first',$first->token()); Check::same(1, $stale->fence());
Check::throws(SecurityException::class, function () use ($transaction,$pdo,$stale) { $transaction(static function () use ($pdo,$stale) { write($pdo,$stale,'tenant','a',4,'Restored old worker'); }); });
$store->transact(SoSecurity\Support\Guard::key('leases','tenant','a'), static function () use ($latestLedger) { return new SoSecurity\Storage\Change($latestLedger, 0, null); });
// Even an explicit new ledger cannot silently replace the business resource's pinned epoch.
$manager->release('tenant', 'a', 'second', $second->token()); Check::same(true, $manager->remove('tenant', 'a', $epoch)); $manager->initialize('tenant', 'a'); $new = $manager->acquire('tenant', 'a', 'new');
Check::throws(SecurityException::class, function () use ($transaction, $pdo, $manager, $new) { $transaction(static function () use ($pdo, $manager, $new) { claim($pdo, $manager, 'tenant', 'a', 'new', $new->token()); }); });
// Database clock is evaluated by UPDATE, independent of an already-verified PHP snapshot.
$pastClock = new TestClock(); $pastClock->time = time()-30; $past = new LeaseManager(new SoSecurity\Storage\MemoryStore($pastClock), new LeasePolicy(1, 10, 10), $pastClock); $pastEpoch = $past->initialize('tenant','past'); $insert->execute(['tenant','past',$pastEpoch,'','Past']); $pastLease = $past->acquire('tenant','past','worker');
Check::throws(SecurityException::class, function () use ($transaction,$pdo,$past,$pastLease) { $transaction(static function () use ($pdo,$past,$pastLease) { claim($pdo,$past,'tenant','past','worker',$pastLease->token()); }); });
$shortClock = new TestClock(); $shortClock->time = time(); $short = new LeaseManager(new SoSecurity\Storage\MemoryStore($shortClock), new LeasePolicy(1, 2, 2), $shortClock); $shortEpoch = $short->initialize('tenant','short'); $insert->execute(['tenant','short',$shortEpoch,'','Short']); $lease = $short->acquire('tenant','short','worker');
$transaction(static function () use ($pdo, $short, $lease) { claim($pdo, $short, 'tenant', 'short', 'worker', $lease->token()); });
usleep(2100000);
Check::throws(SecurityException::class, function () use ($transaction, $pdo, $lease) { $transaction(static function () use ($pdo, $lease) { write($pdo, $lease, 'tenant', 'short', 1, 'Expired snapshot'); }); });
Check::same('Short', $pdo->query("SELECT output FROM jobs WHERE id='short'")->fetchColumn());
$slowClock = new TestClock(); $slowClock->time = time(); $slow = new LeaseManager(new SoSecurity\Storage\MemoryStore($slowClock), new LeasePolicy(1, 2, 2), $slowClock); $slowEpoch = $slow->initialize('tenant','slow'); $insert->execute(['tenant','slow',$slowEpoch,'','Slow']); $slowLease = $slow->acquire('tenant','slow','worker');
$transaction(static function () use ($pdo,$slow,$slowLease) { claim($pdo,$slow,'tenant','slow','worker',$slowLease->token()); });
if ($mysql) {
    $pdo->exec("CREATE TRIGGER lease_delay BEFORE UPDATE ON jobs FOR EACH ROW BEGIN IF NEW.id='slow' AND NEW.output='Late' THEN DO SLEEP(3); END IF; END");
} else {
    $pause = static function () { usleep(3000000); return 1; };
    if (PHP_VERSION_ID >= 80500) { $pdo->createFunction('lease_pause',$pause,0); } else { $pdo->sqliteCreateFunction('lease_pause',$pause,0); }
    $pdo->exec("CREATE TRIGGER lease_delay BEFORE UPDATE ON jobs WHEN NEW.id='slow' AND NEW.output='Late' BEGIN SELECT lease_pause(); END");
}
Check::throws(SecurityException::class, function () use ($transaction,$pdo,$slowLease) { $transaction(static function () use ($pdo,$slowLease) { write($pdo,$slowLease,'tenant','slow',1,'Late'); }); });
Check::same('Slow', $pdo->query("SELECT output FROM jobs WHERE id='slow'")->fetchColumn());
$pdo->exec('DROP TRIGGER lease_delay');
Check::same(false, $pdo->inTransaction()); Check::same(PHP_SESSION_NONE, session_status()); Check::same(false, headers_sent());
if ($mysql) { $pdo->exec('DROP TABLE jobs'); }
echo 'PASS lease SQL fencing: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . '; actual ' . ($mysql ? 'MySQL native prepares' : 'SQLite') . " revision/tenant/epoch/holder predicates, paused-writer/old-backup rejection, database expiry and host rollback\n";
