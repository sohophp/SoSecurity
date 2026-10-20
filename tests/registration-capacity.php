<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';
$registrationSocket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));
if($registrationSocket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$registrationSocket)||!is_file(dirname($registrationSocket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable local MySQL instance.');}$GLOBALS['registrationMySQLSocket']=$registrationSocket;}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$first=$s->notification($e->notices()[0]);Check::same(3,$e->count('sosecurity_account_records'));$e->clock->time+=86400;$s->request('owner@example.com','ip');
    Check::same(5,$e->count('sosecurity_account_records'));Check::same(2,count($e->notices()));$next=$s->notification($e->notices()[1]);Check::same(false,$first->selector()===$next->selector());Check::same(false,$s->confirm($first->selector(),$first->notice()->token(),'owner-confirmation-password','ip'));Check::same(null,$e->account()['password']);
},['maximum_entries'=>5]);
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$before=$e->pdo->query('SELECT revision,history_digest,entries FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);$account=$e->account();$e->clock->time+=86400;
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($s):void{$s->request('owner@example.com','ip');});Check::same($before,$e->pdo->query('SELECT revision,history_digest,entries FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));Check::same($account,$e->account());Check::same(3,$e->count('sosecurity_account_records'));Check::same(1,count($e->notices()));
},['maximum_entries'=>4]);
echo 'PASS registration exact capacity: '.Check::$assertions.' assertions on '.($registrationSocket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."; existing pointer consumes no new slot, insufficient capacity retains account/history/notices\n";
