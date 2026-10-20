<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable local test database.');}$GLOBALS['registrationMySQLSocket']=$socket;}
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$account=$e->account();
    Check::same(false,$s->cancel(str_repeat('a',64),$d->notice()->token(),'ip'));Check::same(false,$s->cancel($d->selector(),str_repeat('f',64),'ip'));Check::same(1,$e->flow($d->selector())['attempts']);
    Check::same(true,$s->cancel($d->selector(),$d->notice()->token(),'ip'));Check::same('cancelled',$e->flow($d->selector())['state']);Check::same($account,$e->account());Check::same(0,$e->hashCalls);Check::same(1,count($e->notices()));Check::same(null,$s->notification($d->notice()->id()));
    Check::same(false,$s->cancel($d->selector(),$d->notice()->token(),'ip'));Check::same(false,$s->confirm($d->selector(),$d->notice()->token(),'owner-confirmation-password','ip'));$s->request('owner@example.com','ip');Check::same(1,count($e->notices()));
    $e->clock->time+=60;$s->request('owner@example.com','ip');$next=$s->notification($e->notices()[1]);Check::same(false,$next->selector()===$d->selector());Check::same($d->notice()->expiresAt(),$next->notice()->expiresAt());Check::same(1,$e->flow($next->selector())['resends']);Check::same(false,$s->cancel($d->selector(),$d->notice()->token(),'ip'));Check::same(0,$e->flow($next->selector())['attempts']);Check::same(true,$s->confirm($next->selector(),$next->notice()->token(),'owner-confirmation-password','ip'));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$first=$s->notification($e->notices()[0]);$d=$first;
    for($n=0;$n<4;++$n){Check::same(true,$s->cancel($d->selector(),$d->notice()->token(),'ip'));$e->clock->time+=60;$s->request('owner@example.com','ip');if($n<3){$d=$s->notification($e->notices()[$n+1]);Check::same($first->notice()->expiresAt(),$d->notice()->expiresAt());}}
    Check::same(4,count($e->notices()));Check::same('cancelled',$e->flow($d->selector())['state']);Check::same(3,$e->flow($d->selector())['resends']);Check::same(null,$e->account()['password']);
});
foreach(['credential_version','address_version','status'] as $field){registrationCase(static function(RegistrationEnvironment $e)use($field):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$e->pdo->exec('UPDATE account_example SET '.$field."='".($field==='status'?'disabled':'changed')."'");Check::same(false,$s->cancel($d->selector(),$d->notice()->token(),'ip'));Check::same('pending',$e->flow($d->selector())['state']);
});}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$e->onAuthority=static function(string $action,string $phase):bool{return $action!=='cancel'||$phase!=='commit';};
    Check::throws(SecurityException::class,static function()use($s,$d):void{$s->cancel($d->selector(),$d->notice()->token(),'ip');});Check::same('pending',$e->flow($d->selector())['state']);Check::same(0,$e->flow($d->selector())['attempts']);$e->onAuthority=null;Check::same(true,$s->cancel($d->selector(),$d->notice()->token(),'ip'));
});
foreach(['statement','commit'] as $phase){registrationCase(static function(RegistrationEnvironment $e)use($phase):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);
    if($phase==='statement'){$e->pdo->afterStatement=static function(string $sql)use($e):void{if(strpos($sql,'UPDATE '.($e->mysql?'':'main.').'sosecurity_account_records SET ')===0){$e->clock->time+=2;}};}else{$e->pdo->beforeCommit=static function()use($e):void{$e->clock->time+=2;};}
    Check::throws(StorageException::class,static function()use($s,$d):void{$s->cancel($d->selector(),$d->notice()->token(),'ip');});$e->pdo->afterStatement=null;$e->pdo->beforeCommit=null;Check::same($phase==='statement'?'pending':'cancelled',$e->flow($d->selector())['state']);Check::same(null,$e->account()['password']);
},['registration_seconds'=>2]);}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$account=$e->account();$queue=$e->pdo->query('SELECT revision,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
    Check::same(0,$s->maintain()['removed']);$e->clock->time+=172800;$after='';$removed=0;$pages=0;
    do{$result=$s->maintain(1,$after);$removed+=$result['removed'];$after=$result['after'];Check::same(true,$result['removed']<=2);if(++$pages>6){throw new RuntimeException('Unexpected maintenance progress.');}}while(!$result['done']);
    Check::same(3,$removed);Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,(int)$e->observer->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());Check::same($account,$e->account());Check::same($queue,$e->pdo->query('SELECT revision,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));Check::same(1,count($e->notices()));Check::same(false,$s->confirm($d->selector(),$d->notice()->token(),'owner-confirmation-password','ip'));
    $s->request('owner@example.com','ip');$next=$s->notification($e->notices()[1]);Check::same(false,$d->selector()===$next->selector());Check::same(true,$s->confirm($next->selector(),$next->notice()->token(),'owner-confirmation-password','ip'));Check::same(1,$e->count('account_example'));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$e->clock->time+=172800;$before=$e->count('sosecurity_account_records');$e->onManagement=static function(string $action,string $phase):bool{return $action!=='maintain'||$phase!=='commit';};Check::throws(SecurityException::class,static function()use($s):void{$s->maintain();});Check::same($before,$e->count('sosecurity_account_records'));$e->onManagement=null;Check::same(3,$s->maintain()['removed']);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$first=$s->notification($e->notices()[0]);$e->clock->time+=172799;$s->request('owner@example.com','ip');$next=$s->notification($e->notices()[1]);++$e->clock->time;
    Check::same(2,$s->maintain()['removed']);Check::same(3,$e->count('sosecurity_account_records'));Check::same($next->notice()->encode(),$s->notification($next->notice()->id())->notice()->encode());Check::same(false,$s->confirm($first->selector(),$first->notice()->token(),'owner-confirmation-password','ip'));Check::same(true,$s->confirm($next->selector(),$next->notice()->token(),'owner-confirmation-password','ip'));
});
foreach(['expired','live'] as $when){registrationCase(static function(RegistrationEnvironment $e)use($when):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$queue=$e->pdo->query('SELECT revision,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);$account=$e->account();if($when==='expired'){$e->clock->time+=86400;}
    $keys=new SoSecurity\Support\HmacKeys('next',['account'=>str_repeat('a',32),'next'=>str_repeat('n',32)]);$codec=new SoSecurity\Account\Notifications('next',['mail'=>str_repeat('m',32),'next'=>str_repeat('z',32)],$e->clock);$rotator=$e->service(null,null,'tenant','',$keys,$codec);$after='';$resealed=0;$encrypted=0;$pages=0;
    do{$r=$rotator->rotate(1,$after);$after=$r['after'];$resealed+=$r['resealed'];$encrypted+=$r['reencrypted'];if(++$pages>5){throw new RuntimeException('Unexpected rotation progress.');}}while(!$r['done']);
    Check::same(3,$resealed);Check::same(1,$encrypted);Check::same('next',$e->pdo->query('SELECT seal_key FROM sosecurity_account_roots')->fetchColumn());Check::same(['next'],$e->pdo->query('SELECT DISTINCT seal_key FROM sosecurity_account_records')->fetchAll(PDO::FETCH_COLUMN));Check::same($queue,$e->pdo->query('SELECT revision,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));Check::same($account,$e->account());Check::same(0,$rotator->rotate()['resealed']);Check::same(0,$rotator->rotate()['reencrypted']);
    Check::throws(StorageException::class,static function()use($s):void{$s->maintain();});$retired=$e->service(null,null,'tenant','',new SoSecurity\Support\HmacKeys('next',['next'=>str_repeat('n',32)]),new SoSecurity\Account\Notifications('next',['next'=>str_repeat('z',32)],$e->clock));
    if($when==='expired'){Check::same(null,$retired->notification($d->notice()->id()));$e->clock->time+=86400;Check::same(3,$retired->maintain()['removed']);}
    else{$new=$retired->notification($d->notice()->id());Check::same($d->notice()->encode(),$new->notice()->encode());Check::same($d->selector(),$new->selector());Check::same(true,$retired->confirm($new->selector(),$new->notice()->token(),'owner-confirmation-password','ip'));}
});}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$before=$e->pdo->query('SELECT revision,seal_key,history_digest FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);$keys=new SoSecurity\Support\HmacKeys('next',['account'=>str_repeat('a',32),'next'=>str_repeat('n',32)]);$rotator=$e->service(null,null,'tenant','',$keys,new SoSecurity\Account\Notifications('next',['mail'=>str_repeat('m',32),'next'=>str_repeat('z',32)],$e->clock));$e->onManagement=static function(string $action,string $phase):bool{return $action!=='rotate'||$phase!=='commit';};Check::throws(SecurityException::class,static function()use($rotator):void{$rotator->rotate();});Check::same($before,$e->pdo->query('SELECT revision,seal_key,history_digest FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));Check::same(['account'],$e->pdo->query('SELECT DISTINCT seal_key FROM sosecurity_account_records')->fetchAll(PDO::FETCH_COLUMN));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$queries=$e->pdo->queries;$calls=$e->authorityCalls;foreach([[0,''],[51,''],[1,'bad'],[1,str_repeat('a',65)]] as $args){foreach(['maintain','rotate'] as $method){Check::throws(ConfigurationException::class,static function()use($s,$method,$args):void{$s->$method($args[0],$args[1]);});}}Check::same($queries,$e->pdo->queries);Check::same($calls,$e->authorityCalls);
    $keys=new SoSecurity\Support\HmacKeys('next',['account'=>str_repeat('a',32),'next'=>str_repeat('n',32)]);$rotator=$e->service(null,null,'tenant','',$keys);Check::same(true,$rotator->rotate()['root_rotated']);Check::same('next',$e->pdo->query('SELECT seal_key FROM sosecurity_account_roots')->fetchColumn());
});
echo 'PASS account cancellation/maintenance: '.Check::$assertions.' assertions on '.($socket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."; current proof cancellation, bounded cleanup, private-key rotation, unchanged Outbox/account data; no SMTP/browser acceptance\n";
