<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    $x=new EntryEnvironment($e,true);$old=$e->pdo->query("SELECT credential_version,password FROM account_example WHERE scope='foreign' AND subject='foreign-user'")->fetch(PDO::FETCH_ASSOC);$record=$e->accounts->find('foreign','foreign-user');$e->accounts->replacePassword($record,(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->hash('Owned foreign replacement password 49!'));
    $q=$e->pdo->prepare("UPDATE account_example SET credential_version=?,password=? WHERE scope='foreign' AND subject='foreign-user'");$q->execute([$old['credential_version'],$old['password']]);$q->closeCursor();
    $before=$x->inspect();$lookups=$x->lookups;$files=entryFiles($x);$error=null;$login=null;
    try{$login=$x->auth->password('foreign','owned-cross-scope','foreign@example.test','Owned foreign account password 49!');}catch(Throwable $caught){$error=$caught;}
    if($login!==null&&$login->status()==='authenticated'){throw new RuntimeException('UNSAFE_TENANT_WITNESS_AUTHENTICATED_FOREIGN_RESTORED_CREDENTIALS');}
    Check::same(true,$error instanceof SoSecurity\Exception\ConfigurationException);Check::same('configuration.state_scope',$error->reason());Check::same($lookups,$x->lookups);Check::same($before,$x->inspect());Check::same($files,entryFiles($x));Check::same([], $x->guards);
    $queries=$e->pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{$x->sessions->verify('foreign','foreign-user','soss_'.str_repeat('a',32).'.'.str_repeat('b',64));});Check::same($queries,$e->pdo->queries);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{$x->remember->resume('foreign','malformed');});Check::same($queries,$e->pdo->queries);
    $login=$x->login();Check::same('authenticated',$login->status());
});
echo 'PASS exact operation scope: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; foreign restored credentials cannot use tenant authority, no source/provider/store reads and original tenant login remains usable\n";
