<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require dirname(__DIR__) . '/examples/authorization.php';
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use function SoSecurity\Examples\Authorization\read;
use function SoSecurity\Examples\Authorization\update;
use function SoSecurity\Examples\Authorization\policy;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec('CREATE TABLE documents(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,confidential_note TEXT NOT NULL,PRIMARY KEY(tenant,id))');
$insert = $pdo->prepare('INSERT INTO documents VALUES(?,?,?,?,?,?,?)');
foreach ([['tenant','a','alice'],['tenant','b','bob'],['tenant','c','alice'],['other','a','alice']] as $entry) { $insert->execute(array_merge($entry,[1,'Original','Body','PRIVATE-NOTE'])); }
$actor = new Account('tenant', 'alice', '1', true, ['editor']); $current = $actor; $offline = false;
$source = new CallbackIdentityProvider(function () { return null; }, function () use (&$current, &$offline) { if ($offline) { throw new RuntimeException('Test authority outage'); } return $current; });
$auth = new Authorizer($source, policy());
$snapshot = function () use ($pdo) { return $pdo->query('SELECT * FROM documents ORDER BY tenant,id')->fetchAll(PDO::FETCH_ASSOC); };
$apply = function (array $operations) use ($pdo, $auth, &$actor): int {
    $pdo->beginTransaction();
    try { $count = update($pdo, $auth, $actor, 'tenant', $operations); $pdo->commit(); return $count; }
    catch (Throwable $e) { $pdo->rollBack(); throw $e; }
};
$operation = function (string $id, int $version = 1, array $changes = ['title' => 'Updated']): array { return ['id' => $id, 'version' => $version, 'changes' => $changes]; };
Check::same(['id','version','title'], array_keys(read($pdo, $auth, $actor, 'tenant', 'a')));
Check::throws(SecurityException::class, function () use ($pdo, $auth, $actor) { read($pdo, $auth, $actor, 'tenant', 'a', ['confidential_note']); });
Check::throws(SecurityException::class, function () use ($pdo, $auth, $actor) { read($pdo, $auth, $actor, 'other', 'a'); });
Check::throws(SecurityException::class, function () use ($pdo, $auth) { read($pdo, $auth, null, 'tenant', 'a'); });
$before = $snapshot();
foreach ([[$operation('b')],[$operation('a'),$operation('b')],[$operation('a'),$operation('missing')],[$operation('a',1,['owner'=>'alice'])]] as $bad) {
    Check::throws(SecurityException::class, function () use ($apply, $bad) { $apply($bad); }); Check::same($before, $snapshot());
}
// Unauthorized wrong versions must not reveal a conflict or override the generic denial.
try { $apply([$operation('b', 99)]); throw new LogicException('Expected denial.'); }
catch (SecurityException $e) { Check::same('authorization.denied', $e->reason()); }
foreach ([[$operation('a'),$operation('a')],[$operation('a',1,['title'=>['nested'=>'value']])],[]] as $bad) {
    Check::throws(ValidationException::class, function () use ($apply, $bad) { $apply($bad); }); Check::same($before, $snapshot());
}
Check::throws(ConfigurationException::class, function () use ($pdo, $auth, $actor, $operation) { update($pdo, $auth, $actor, 'tenant', [$operation('a')]); });
$offline = true; Check::throws(DependencyException::class, function () use ($apply, $operation) { $apply([$operation('a')]); }); $offline = false; Check::same($before, $snapshot());
Check::same(2, $apply([$operation('a'),$operation('c',1,['body'=>'Updated body'])]));
Check::same(2, (int) $pdo->query("SELECT version FROM documents WHERE tenant='tenant' AND id='a'")->fetchColumn());
Check::same('Body', $pdo->query("SELECT body FROM documents WHERE tenant='tenant' AND id='a'")->fetchColumn());
Check::same('PRIVATE-NOTE', $pdo->query("SELECT confidential_note FROM documents WHERE tenant='tenant' AND id='a'")->fetchColumn());
Check::same(1, (int) $pdo->query("SELECT version FROM documents WHERE tenant='other' AND id='a'")->fetchColumn());
$before = $snapshot();
try { $apply([$operation('a',1)]); throw new LogicException('Expected conflict.'); } catch (SecurityException $e) { Check::same('authorization.conflict', $e->reason()); }
Check::same($before, $snapshot());
// Real database trigger changes the second target after the first write. CAS fails; host rollback restores the entire batch.
$pdo->exec("CREATE TRIGGER competing_version AFTER UPDATE ON documents WHEN NEW.tenant='tenant' AND NEW.id='a' BEGIN UPDATE documents SET version=version+1 WHERE tenant='tenant' AND id='c'; END");
try { $apply([$operation('a',2),$operation('c',2)]); throw new LogicException('Expected competing update.'); }
catch (SecurityException $e) { Check::same('authorization.conflict', $e->reason()); }
Check::same($before, $snapshot()); Check::same(false, $pdo->inTransaction()); $pdo->exec('DROP TRIGGER competing_version');
$current = new Account('tenant', 'alice', '2', true, ['reader']);
Check::throws(SecurityException::class, function () use ($apply, $operation) { $apply([$operation('a',2)]); }); Check::same($before, $snapshot());
$current = new Account('tenant', 'alice', '3', true, ['manager']); $actor = $current;
Check::same('PRIVATE-NOTE', read($pdo,$auth,$actor,'tenant','a',['confidential_note'],true)['confidential_note']);
Check::throws(SecurityException::class, function () use ($apply, $operation) { $apply([$operation('a',2)]); });
// A real SQLite function in a view proves unselected/unauthorized confidential columns are never evaluated.
$reads = 0; $protect = function ($value) use (&$reads) { ++$reads; return $value; };
if (PHP_VERSION_ID >= 80500) {
    $view = PDO::connect('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); $view->createFunction('protected_value', $protect, 1);
} else {
    $view = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); $view->sqliteCreateFunction('protected_value', $protect, 1);
}
$view->exec('CREATE TABLE document_rows(tenant TEXT,id TEXT,owner TEXT,version INTEGER,title TEXT,body TEXT,confidential_note TEXT)');
$view->exec("INSERT INTO document_rows VALUES('tenant','a','alice',1,'Title','Body','PRIVATE-NOTE')");
$view->exec('CREATE VIEW documents AS SELECT tenant,id,owner,version,title,protected_value(body) AS body,protected_value(confidential_note) AS confidential_note FROM document_rows');
Check::same(['id','version','title'], array_keys(read($view,$auth,$actor,'tenant','a'))); Check::same(0, $reads);
Check::throws(SecurityException::class, function () use ($view,$auth,$actor) { read($view,$auth,$actor,'tenant','a',['confidential_note']); }); Check::same(0, $reads);
Check::same('PRIVATE-NOTE', read($view,$auth,$actor,'tenant','a',['confidential_note'],true)['confidential_note']); Check::same(1, $reads);
echo 'PASS authorization SQL: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "; tenant/owner/fields, all-before-write, generic denial, real trigger conflict and complete host rollback\n";
