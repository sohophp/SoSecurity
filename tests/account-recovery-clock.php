<?php
declare(strict_types=1);
require __DIR__.'/recovery-support.php';
final class RecoverySequenceClock implements SoSecurity\Support\Clock {
    public $base;public $sequence=[];
    public function __construct(TestClock $base){$this->base=$base;}
    public function now():int {return $this->sequence?array_shift($this->sequence):$this->base->time;}
}
recoveryCase(static function(RecoveryEnvironment $r):void{
    $clock=new RecoverySequenceClock($r->e->clock);$r->e->clock=$clock;$r->service=$r->build();$d=$r->begin();$before=$r->e->account();
    $r->onPolicy=static function()use($clock):bool{$clock->sequence=[$clock->base->time+1,$clock->base->time+1,$clock->base->time+1,$clock->base->time,$clock->base->time];return false;};
    try{$r->confirm($d);throw new RuntimeException('Clock rollback between hashing and SQL must refuse recovery.');}catch(SoSecurity\Exception\SecurityException $error){Check::same('sql.authority',$error->reason());}
    Check::same($before,$r->e->account());Check::same('pending',$r->flow($d->selector())['state']);Check::same(1,count($r->ids()));
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$r->onAuthority=static function(string $action,string $phase)use($r):bool{if($action==='confirm'&&$phase==='commit'){$r->e->clock->time+=60;}return true;};
    try{$r->confirm($d);throw new RuntimeException('Expired request budget after commit authority must roll back recovery.');}catch(SoSecurity\Exception\SecurityException $error){Check::same('account.budget',$error->reason());}
    Check::same($before,$r->e->account());Check::same('pending',$r->flow($d->selector())['state']);Check::same(1,count($r->ids()));
});
echo 'PASS recovery clock/final budget: '.Check::$assertions.' assertions on '.(($argv[1] ?? '')==='mysql'?'MySQL':'SQLite').' PHP '.PHP_VERSION."; monotonic handoff after hashing and last-stage budget after commit authority; both old-code counterexamples retained\n";
