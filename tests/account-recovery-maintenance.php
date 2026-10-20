<?php
declare(strict_types=1);
require __DIR__.'/recovery-support.php';
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
function recoveryRows(RecoveryEnvironment $r):array {$id=$r->delivery()->selector();$q=$r->e->pdo->prepare('SELECT namespace FROM sosecurity_account_records WHERE record_id=?');$q->execute([$id]);return [$q->fetchColumn(),$id];}
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$expected=$d->notice()->encode();$ids=$r->ids();$r->keys=new SoSecurity\Support\HmacKeys('next',['recovery'=>str_repeat('r',32),'next'=>str_repeat('n',32)]);$r->notices=new SoSecurity\Account\Notifications('next',['mail'=>str_repeat('m',32),'next'=>str_repeat('x',32)],$r->e->clock);$r->service=$r->build();$after='';$total=0;
    do{$page=$r->service->rotate(1,$after);$total+=$page['resealed'];$after=$page['after'];}while(!$page['done']);Check::same(3,$total);Check::same($ids,$r->ids());$r->keys=new SoSecurity\Support\HmacKeys('next',['next'=>str_repeat('n',32)]);$r->notices=new SoSecurity\Account\Notifications('next',['next'=>str_repeat('x',32)],$r->e->clock);$r->service=$r->build();Check::same($expected,$r->delivery()->notice()->encode());Check::same(true,$r->confirm($d));
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();list($namespace)=recoveryRows($r);$before=$r->e->account();$q=$r->e->pdo->prepare('SELECT namespace,record_id,seal FROM sosecurity_account_records WHERE namespace<>? ORDER BY namespace,record_id');$q->execute([$namespace]);$others=$q->fetchAll(PDO::FETCH_ASSOC);$r->e->clock->time+=900+86400;$after='';$removed=0;
    do{$page=$r->service->maintain(1,$after);Check::same(true,$page['examined']<=1);$removed+=$page['removed'];$after=$page['after'];}while(!$page['done']);Check::same(3,$removed);Check::same($before,$r->e->account());Check::same(1,count($r->ids()));$q->execute([$namespace]);Check::same($others,$q->fetchAll(PDO::FETCH_ASSOC));Check::same(null,$r->service->notification($d->notice()->id()));
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();list($namespace)=recoveryRows($r);$before=$r->e->account();$ns=$r->e->pdo->quote($namespace);
    $trigger=$r->e->mysql?"CREATE TRIGGER recovery_password_fault BEFORE UPDATE ON account_example FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned fault'":"CREATE TRIGGER recovery_password_fault BEFORE UPDATE ON account_example BEGIN SELECT RAISE(ABORT,'owned fault'); END";
    $r->e->pdo->exec($trigger);Check::throws(SoSecurity\Exception\DependencyException::class,static function()use($r,$d):void{$r->confirm($d,['type'=>'recovery','code'=>$r->codes[0]]);});Check::same($before,$r->e->account());Check::same(1,count($r->ids()));Check::same('pending',$r->flow($d->selector())['state']);Check::same(1,$r->flow($d->selector())['attempts']);Check::same(false,$r->t->factors->verifyRecovery('tenant',$r->t->subject,$r->codes[0]));Check::same(true,$r->t->factors->status('tenant',$r->t->subject)['enabled']);
},true);
recoveryCase(static function(RecoveryEnvironment $r):void{
    $queries=$r->e->pdo->queries;$r->onBudget=static function():bool{return false;};Check::throws(SecurityException::class,static function()use($r):void{$r->service->request('owner@example.com','owned-source');});Check::same($queries,$r->e->pdo->queries);Check::same([], $r->ids());
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$expression=$r->e->mysql?'REPEAT(CHAR(0),2097152)':'zeroblob(16777216)';$q=$r->e->pdo->prepare('UPDATE sosecurity_account_records SET payload='.$expression.' WHERE record_id=?');$q->execute([$d->selector()]);
    foreach([static function()use($r,$d):void{$r->confirm($d);},static function()use($r,$d):void{$r->service->notification($d->notice()->id());},static function()use($r):void{$r->service->maintain();},static function()use($r):void{$r->service->rotate();}] as $operation){Check::throws(StorageException::class,$operation);}Check::same($before,$r->e->account());Check::same(1,count($r->ids()));Check::same(true,memory_get_peak_usage(true)<8388608);
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$r->e->pdo->exec($r->e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');try{$r->e->pdo->exec("UPDATE account_example SET credential_version='owned-uncommitted'");Check::throws(Throwable::class,static function()use($r,$d):void{$r->confirm($d);});Check::same($before,$r->e->account());$r->e->pdo->exec('COMMIT');}catch(Throwable $error){$r->e->pdo->exec('ROLLBACK');throw $error;}Check::same('owned-uncommitted',$r->e->account()['credential_version']);Check::same(1,count($r->ids()));
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$contexts=[];$used=false;$r->onStrong=static function(string $phase,string $scope,string $subject,string $context)use(&$contexts,&$used):bool{if($phase==='verify'){$contexts[]=$context;if($used){return false;}$used=true;}return true;};$r->onPolicy=static function():bool{return true;};Check::same(false,$r->confirm($d,['type'=>'approved','code'=>'owned-once']));$r->password='A different owner password 49!';Check::same(false,$r->confirm($d,['type'=>'approved','code'=>'owned-once']));Check::same(2,count($contexts));Check::same(true,$contexts[0]!==$contexts[1]);Check::same($before,$r->e->account());
},true,true);
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$r->allowed=false;Check::throws(SecurityException::class,static function()use($r,$d):void{$r->confirm($d);});$r->allowed=true;$r->managed=false;Check::throws(SecurityException::class,static function()use($r):void{$r->service->maintain();});$r->delivered=false;Check::throws(SecurityException::class,static function()use($r,$d):void{$r->service->notification($d->notice()->id());});
    foreach([$d->notice()->token(),$d->notice()->recipient()->value(),str_repeat('r',32),str_repeat('m',32)] as $secret){Check::same(false,strpos(var_export($r->service,true),$secret)!==false);Check::same(false,strpos(var_export($d,true),$secret)!==false);}Check::same('{}',json_encode($d));Check::same('{}',json_encode($r->service));Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($r):void{serialize($r->service);});
});
echo 'PASS recovery maintenance/safety: '.Check::$assertions.' assertions on '.(($argv[1] ?? '')==='mysql'?'MySQL':'SQLite').' PHP '.PHP_VERSION."; purpose-scoped rotation/cleanup, real SQL failure rollback, consumed code not refunded, bounded corrupt reads and host transaction preservation\n";
