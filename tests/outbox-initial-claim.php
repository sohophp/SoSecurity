<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)!==1||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required');}}
outboxCase($mysql,static function(OutboxEnvironment $e):void{
 $s=$e->service();$s->initialize('tenant','orders','admin');$one=$e->message('first','owned first body','aggregate');$two=$e->message('second','owned second body','aggregate');$e->append($s,$one);$e->append($s,$two);$before=$e->rows();
 Check::same(null,$s->claimInitialMessage('tenant','orders','worker',$two->id()));Check::same($before,$e->rows());
 $e->allowed=false;Check::same(null,$s->claimInitialMessage('tenant','orders','worker',$one->id()));Check::same($before,$e->rows());$e->allowed=true;
 $claim=$s->claimInitialMessage('tenant','orders','worker',$one->id());Check::same($one->id(),$claim->message()->id());Check::same('owned first body',$claim->message()->body());Check::same(1,$claim->status()->attempts());Check::same('leased',$claim->status()->state());
 $leased=$e->rows();Check::same(null,$s->claimInitialMessage('tenant','orders','worker',$one->id()));Check::same($leased,$e->rows());
 $e->clock->time+=$e->policy->leaseSeconds()+1;Check::same(null,$s->claimInitialMessage('tenant','orders','another-worker',$one->id()));Check::same($leased,$e->rows());
 // No send, settlement, lease takeover or requeue is executed.
 $e->clock->time+=$e->policy->messageAge();Check::same(null,$s->claimInitialMessage('tenant','orders','worker',$two->id()));Check::same($leased,$e->rows());Check::same(0,$e->business(true));
});
foreach(['commit','return'] as $phase){outboxCase($mysql,static function(OutboxEnvironment $e)use($phase):void{
 $s=$e->service();$s->initialize('tenant','orders','admin');$message=$e->message();$e->append($s,$message);
 $e->onAuthority=static function(string $action,string $p)use($e,$phase):bool{if($action==='claim_initial'&&$p===$phase){$e->clock->time+=$e->policy->leaseSeconds();}return true;};
 outboxRefused('outbox.lease',static function()use($s,$message){$s->claimInitialMessage('tenant','orders','worker',$message->id());});
 $e->onAuthority=null;$rows=$e->rows();Check::same($phase==='commit'?'pending':'leased',$rows[0]['status']);Check::same($phase==='commit'?0:1,(int)$rows[0]['attempts']);
});}
echo 'PASS initial outbox claim: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
