<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/operation-support.php';
require dirname(__DIR__).'/examples/operation-work.php';
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use function SoSecurity\Examples\Operations\apply;

$mysql=($argv[1] ?? '')==='mysql';
if ($mysql) {
    $pdo=new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    foreach (['operation_receipts','operation_documents','operation_accounts'] as $table) {$pdo->exec('DROP TABLE IF EXISTS '.$table);}
    $pdo->exec('CREATE TABLE operation_accounts(tenant VARCHAR(128) NOT NULL,subject VARCHAR(128) NOT NULL,version VARCHAR(256) NOT NULL,enabled INT NOT NULL,PRIMARY KEY(tenant,subject)) ENGINE=InnoDB');
    $pdo->exec('CREATE TABLE operation_documents(tenant VARCHAR(128) NOT NULL,id VARCHAR(128) NOT NULL,owner VARCHAR(128) NOT NULL,version BIGINT NOT NULL,title TEXT NOT NULL,PRIMARY KEY(tenant,id)) ENGINE=InnoDB');
    $pdo->exec('CREATE TABLE operation_receipts(tenant VARCHAR(128) NOT NULL,id VARCHAR(32) NOT NULL,subject VARCHAR(128) NOT NULL,intent_hash VARCHAR(64) NOT NULL,resource_id VARCHAR(128) NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(tenant,id)) ENGINE=InnoDB');
} else {
    $pdo=PHP_VERSION_ID>=80500 ? PDO::connect('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]) : new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('CREATE TABLE operation_accounts(tenant TEXT NOT NULL,subject TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,PRIMARY KEY(tenant,subject))');
    $pdo->exec('CREATE TABLE operation_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,PRIMARY KEY(tenant,id))');
    $pdo->exec('CREATE TABLE operation_receipts(tenant TEXT NOT NULL,id TEXT NOT NULL,subject TEXT NOT NULL,intent_hash TEXT NOT NULL,resource_id TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(tenant,id))');
}
$pdo->exec("INSERT INTO operation_accounts VALUES('site','alice','1',1)");$pdo->exec("INSERT INTO operation_documents VALUES('site','a','alice',1,'Original'),('other','a','alice',1,'Other tenant')");
$snapshot=static function () use ($pdo) {return $pdo->query('SELECT * FROM operation_documents ORDER BY tenant,id')->fetchAll(PDO::FETCH_ASSOC);};
$receipts=static function () use ($pdo):int {return (int)$pdo->query('SELECT COUNT(*) FROM operation_receipts')->fetchColumn();};
$transaction=static function (callable $operation) use ($pdo) {$pdo->beginTransaction();try{$operation();$pdo->commit();}catch(Throwable $error){$pdo->rollBack();throw $error;}};
$e=new OperationEnvironment(null,time());$grant=$e->approved();$intent=$e->intent();$before=$snapshot();
Check::throws(ConfigurationException::class,function () use ($pdo,$e,$intent,$grant) {apply($pdo,$e->grants,'site','alice',$e->credential->token(),$intent,$grant->token());});
Check::same($before,$snapshot());Check::same(0,$receipts());
$saved=$e->store->states;
$transaction(static function () use ($pdo,$e,$intent,$grant) {apply($pdo,$e->grants,'site','alice',$e->credential->token(),$intent,$grant->token());});
Check::same('PRIVATE-APPROVED-TITLE',$pdo->query("SELECT title FROM operation_documents WHERE tenant='site'")->fetchColumn());Check::same('Other tenant',$pdo->query("SELECT title FROM operation_documents WHERE tenant='other'")->fetchColumn());Check::same(1,$receipts());
// Restoring a granted cache record still cannot repeat a committed operation ID in the authoritative SQL transaction.
$e->store->states=$saved;
// Restore the document's old version too: the receipt must be the remaining replay barrier.
$pdo->exec("UPDATE operation_documents SET version=1,title='Restored document' WHERE tenant='site'");$before=$snapshot();
Check::throws(SecurityException::class,function () use ($transaction,$pdo,$e,$intent,$grant) {$transaction(static function () use ($pdo,$e,$intent,$grant) {apply($pdo,$e->grants,'site','alice',$e->credential->token(),$intent,$grant->token());});});
Check::same($before,$snapshot());Check::same(1,$receipts());
$pdo->exec("UPDATE operation_documents SET version=2,title='PRIVATE-APPROVED-TITLE' WHERE tenant='site'");
$e=new OperationEnvironment(null,time());$pending=$e->begin($e->intent(['title'=>'New'],'2'));$e->reauthenticate();$grant=$e->confirm($pending,$e->intent(['title'=>'New'],'2'));
$pdo->exec("UPDATE operation_accounts SET version='2' WHERE tenant='site'");$before=$snapshot();
Check::throws(SecurityException::class,function () use ($transaction,$pdo,$e,$grant) {$transaction(static function () use ($pdo,$e,$grant) {apply($pdo,$e->grants,'site','alice',$e->credential->token(),$e->intent(['title'=>'New'],'2'),$grant->token());});});
Check::same($before,$snapshot());Check::same(1,$receipts());Check::same(null,$e->consume($grant,$e->intent(['title'=>'New'],'2')));
$pdo->exec("UPDATE operation_accounts SET version='1' WHERE tenant='site'");
// Resource conflict rolls back the receipt and burns the shared grant, rather than silently retrying different data.
$e=new OperationEnvironment(null,time());$grant=$e->approved();$before=$snapshot();
Check::throws(SecurityException::class,function () use ($transaction,$pdo,$e,$grant) {$transaction(static function () use ($pdo,$e,$grant) {apply($pdo,$e->grants,'site','alice',$e->credential->token(),$e->intent(),$grant->token());});});
Check::same($before,$snapshot());Check::same(1,$receipts());Check::same(null,$e->consume($grant));
// Slow SQL cannot use a timestamp frozen when UPDATE began; rollback covers both the receipt and document.
$e=new OperationEnvironment(new SoSecurity\Operation\Policy(2),time());$pending=$e->begin($e->intent(['title'=>'Late'],'2'));$e->reauthenticate();$grant=$e->confirm($pending,$e->intent(['title'=>'Late'],'2'));
if ($mysql) {$pdo->exec("CREATE TRIGGER operation_delay BEFORE UPDATE ON operation_documents FOR EACH ROW BEGIN IF NEW.title='Late' THEN DO SLEEP(3); END IF; END");}
else {$pause=static function () {usleep(3000000);return 1;};if(PHP_VERSION_ID>=80500){$pdo->createFunction('operation_pause',$pause,0);}else{$pdo->sqliteCreateFunction('operation_pause',$pause,0);}$pdo->exec("CREATE TRIGGER operation_delay BEFORE UPDATE ON operation_documents WHEN NEW.title='Late' BEGIN SELECT operation_pause(); END");}
$before=$snapshot();
try {$transaction(static function () use ($pdo,$e,$grant) {apply($pdo,$e->grants,'site','alice',$e->credential->token(),$e->intent(['title'=>'Late'],'2'),$grant->token());});throw new LogicException('Expected late SQL rejection.');}
catch (SecurityException $error) {Check::same('operation.expired',$error->reason());}
Check::same($before,$snapshot());Check::same(1,$receipts());$pdo->exec('DROP TRIGGER operation_delay');
// Actual password-provider effective versions differ from the authoritative raw SQL version.
$pdo->exec('ALTER TABLE operation_accounts ADD COLUMN password_hash VARCHAR(255)');
$passwordHasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);$passwordHash=$passwordHasher->hash('SQL-operation-test-password');
$setHash=$pdo->prepare('UPDATE operation_accounts SET password_hash=:hash WHERE tenant=:tenant');$setHash->execute(['hash'=>$passwordHash,'tenant'=>'site']);
$passwordRecord=new SoSecurity\Auth\PasswordRecord(new SoSecurity\Auth\Account('site','alice','1',true,['editor']),$passwordHash);
$source=new SoSecurity\Auth\PasswordIdentityProvider(static function () use ($passwordRecord) {return $passwordRecord;},static function () use ($passwordRecord) {return $passwordRecord;},$passwordHasher,$passwordHasher->hash('SQL-operation-dummy-password'));
Check::same('1',$passwordRecord->account()->version());Check::same($source->find('site','alice')->fingerprint(),$passwordRecord->identity()->fingerprint());
$passwordClock=new TestClock();$passwordClock->time=time();$passwordStore=new SoSecurity\Storage\MemoryStore($passwordClock);
$passwordSessions=new SoSecurity\Auth\SessionRegistry($passwordStore,$source,null,$passwordClock);$guard=static function ():bool {return true;};
$passwordFlow=new SoSecurity\Auth\AuthenticationFlow($passwordStore,$source,$passwordSessions,$guard,null,$passwordClock);
$passwordAuthorizer=new SoSecurity\Authorization\Authorizer($source,new SoSecurity\Authorization\RolePolicy(['document.update'=>['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner']]));
$passwordGrants=new SoSecurity\Operation\Grants($passwordStore,$passwordSessions,$passwordAuthorizer,$guard,new SoSecurity\Operation\Policy(120,8,300,1,['password']),$passwordClock);
$passwordSession=$passwordFlow->password('site','sql-test-browser','alice','SQL-operation-test-password')->credential();
$approvePassword=static function () use ($pdo,$passwordFlow,$passwordGrants,&$passwordSession):array {
    $intent=SoSecurity\Examples\Operations\intent($pdo,'site','a','Password-provider reviewed title');$pending=$passwordGrants->begin('site','alice',$passwordSession->token(),$intent);
    $passwordSession=$passwordFlow->password('site','sql-test-browser','alice','SQL-operation-test-password','',$passwordSession->token())->credential();
    $grant=$passwordGrants->confirm('site','alice',$passwordSession->token(),$intent,$pending->token());Check::same(true,$grant!==null);return [$intent,$grant];
};
list($passwordIntent,$passwordGrant)=$approvePassword();
$transaction(static function () use ($pdo,$passwordGrants,$passwordSession,$passwordIntent,$passwordGrant,$passwordRecord) {apply($pdo,$passwordGrants,'site','alice',$passwordSession->token(),$passwordIntent,$passwordGrant->token(),$passwordRecord);});
Check::same('Password-provider reviewed title',$pdo->query("SELECT title FROM operation_documents WHERE tenant='site'")->fetchColumn());Check::same(2,$receipts());
// Deliberately stale identity adapter: authoritative SQL still rejects raw-version/hash changes.
foreach (['version','password_hash'] as $changedColumn) {
    list($passwordIntent,$passwordGrant)=$approvePassword();$before=$snapshot();
    if($changedColumn==='version'){$pdo->exec("UPDATE operation_accounts SET version='2' WHERE tenant='site'");}
    else {$setHash->execute(['hash'=>$passwordHasher->hash('SQL-replaced-test-password'),'tenant'=>'site']);}
    Check::throws(SecurityException::class,static function () use ($transaction,$pdo,$passwordGrants,$passwordSession,$passwordIntent,$passwordGrant,$passwordRecord) {$transaction(static function () use ($pdo,$passwordGrants,$passwordSession,$passwordIntent,$passwordGrant,$passwordRecord) {apply($pdo,$passwordGrants,'site','alice',$passwordSession->token(),$passwordIntent,$passwordGrant->token(),$passwordRecord);});});
    Check::same($before,$snapshot());Check::same(2,$receipts());Check::same(null,$passwordGrants->consume('site','alice',$passwordSession->token(),$passwordIntent,$passwordGrant->token()));
    $pdo->exec("UPDATE operation_accounts SET version='1' WHERE tenant='site'");$setHash->execute(['hash'=>$passwordHash,'tenant'=>'site']);
}
list($passwordIntent,$passwordGrant)=$approvePassword();$before=$snapshot();
$wrongRecord=new SoSecurity\Auth\PasswordRecord(new SoSecurity\Auth\Account('site','someone-else','1',true,['editor']),$passwordHash);
Check::throws(SecurityException::class,static function () use ($transaction,$pdo,$passwordGrants,$passwordSession,$passwordIntent,$passwordGrant,$wrongRecord) {$transaction(static function () use ($pdo,$passwordGrants,$passwordSession,$passwordIntent,$passwordGrant,$wrongRecord) {apply($pdo,$passwordGrants,'site','alice',$passwordSession->token(),$passwordIntent,$passwordGrant->token(),$wrongRecord);});});
Check::same($before,$snapshot());Check::same(2,$receipts());Check::same(null,$passwordGrants->consume('site','alice',$passwordSession->token(),$passwordIntent,$passwordGrant->token()));
Check::same(false,$pdo->inTransaction());Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
if($mysql){foreach(['operation_receipts','operation_documents','operation_accounts'] as $table){$pdo->exec('DROP TABLE '.$table);}}
echo 'PASS operation SQL: '.Check::$assertions.' assertions on PHP '.PHP_VERSION.'; actual '.($mysql?'MySQL native prepares':'SQLite')." receipt uniqueness, tenant/resource/account versions, backup replay and slow-SQL rollback\n";
