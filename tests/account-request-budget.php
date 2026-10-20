<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected the owned disposable local MySQL.');}$GLOBALS['registrationMySQLSocket']=$socket;}
function requestBudgetRoots(RegistrationEnvironment $e):array {return [$e->observer->query('SELECT * FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$e->observer->query('SELECT * FROM sosecurity_outbox_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC)];}
function requestBudgetRolledBack(RegistrationEnvironment $e,array $roots):void {Check::same(0,$e->count('account_example'));Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,$e->count('sosecurity_outbox_records'));Check::same($roots,requestBudgetRoots($e));Check::same(0,$e->hashCalls);}
foreach(['after','commit','final'] as $when){registrationCase(static function(RegistrationEnvironment $e)use($when):void{
    $s=$e->service();$s->initialize();$roots=requestBudgetRoots($e);
    $expire=static function()use($e):void{$e->clock->time=$e->reservations['request:expiry-probe']+1;};
    if($when==='final'){$e->onBudget=static function(string $action,string $phase)use($expire):bool{if($action==='request'&&$phase==='final'){$expire();}return true;};}
    else{$e->onAuthority=static function(string $action,string $phase)use($when,$expire):bool{if($action==='request'&&$phase===$when){$expire();}return true;};}
    $reason=null;try{$s->request('budget@example.com','expiry-probe');}catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();}
    Check::same('account.budget',$reason);requestBudgetRolledBack($e,$roots);
});}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$roots=requestBudgetRoots($e);$subject=null;
    $e->onBudget=static function(string $action,string $phase,string $scope,string $source,?SoSecurity\Account\Address $address,?string $known)use(&$subject):bool{if($phase==='final'){$subject=$known;return false;}return true;};
    Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($s):void{$s->request('budget@example.com','denied-probe');});requestBudgetRolledBack($e,$roots);
    // Committed external charges survive SQL rollback; only the synthetic database writes roll back.
    $bindings=['site'=>'all','source'=>hash_hmac('sha256','denied-probe',str_repeat('b',32)),'target'=>hash_hmac('sha256','request:budget@example.com',str_repeat('b',32))];
    foreach($e->limiter->inspect('registration-tenant',$bindings)->decisions() as $decision){Check::same(999,$decision->remaining());}
    Check::same(999,$e->subjects->inspect('registration-subject-tenant',$subject)->remaining());
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$roots=requestBudgetRoots($e);$e->onBudget=static function(string $action,string $phase):bool{if($phase==='final'){throw new RuntimeException('PRIVATE-SYNTHETIC-BUDGET-FAILURE');}return true;};
    Check::throws(SoSecurity\Exception\DependencyException::class,static function()use($s):void{$s->request('budget@example.com','dependency-probe');});requestBudgetRolledBack($e,$roots);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$roots=requestBudgetRoots($e);$e->onBudget=static function(string $action,string $phase)use($e):bool{if($phase==='final'){$e->pdo->exec("UPDATE account_example SET status='disabled'");}return true;};
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s):void{$s->request('budget@example.com','changed-probe');});requestBudgetRolledBack($e,$roots);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$phases=[];$e->onBudget=static function(string $action,string $phase)use(&$phases):bool{$phases[]=$phase;return true;};$s->request('budget@example.com','allowed-probe');
    Check::same(['public','subject','final'],$phases);Check::same(1,$e->count('account_example'));Check::same(3,$e->count('sosecurity_account_records'));Check::same(1,$e->count('sosecurity_outbox_records'));
});
echo 'PASS registration request commit budget: '.Check::$assertions.' assertions on '.($socket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."; expiry/refusal/unavailable/changed host roll back intent and retain external charges\n";
