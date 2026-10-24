<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
final class FaultWebhookClock implements SoSecurity\Support\Clock
{
    public $time=100000;public $calls=0;public $failAt=0;
    public function now():int {if(++$this->calls===$this->failAt){throw new RuntimeException('SYNTHETIC-CLOCK-PRIVATE-CREDENTIAL');}return 100000;}
}
function clockFailure(callable $operation):void
{
    try{$operation();throw new LogicException('Expected clock failure');}
    catch(SoSecurity\Storage\StorageException $error){Check::same('webhook.clock',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'SYNTHETIC')!==false);}
}
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET')?:'';if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned MySQL required');}}
$mode=$argv[2]??'all';
if($mode!=='inbox'){
    inboxCase($mysql,static function(InboxEnvironment $e):void{
        for($n=1;$n<=6;++$n){$clock=new FaultWebhookClock();$clock->failAt=$n;$keys=$e->keys;$verifier=new SoSecurity\Webhook\Verifier($e->endpoint,static function()use($keys){return $keys;},static function(){return true;},$clock);clockFailure(static function()use($e,$verifier):void{$verifier->verify($e->request());});Check::same(0,$e->count());}
    });
}
if($mode!=='verifier'){
    foreach(['before','commit','cleanup'] as $phase){inboxCase($mysql,static function(InboxEnvironment $e)use($phase):void{
        $clock=new FaultWebhookClock();$e->clock=$clock;$service=$e->service();
        if($phase==='before'){$clock->failAt=1;}else{$hook=static function()use($clock,$phase):void{$clock->failAt=$clock->calls+($phase==='commit'?1:2);};$e->pdo->afterCommit=$hook;$e->pdo->afterExec=static function(string $sql)use($hook):void{if($sql==='COMMIT'){$hook();}};}
        clockFailure(static function()use($e,$service):void{$service->accept($e->request(),$e->mapper());});Check::same($phase==='before'?0:1,$e->count());Check::same(false,$e->pdo->inTransaction());
        if($phase==='before'){Check::same(0,$e->mapCalls);Check::same(0,$e->keyCalls);Check::same(0,$e->associationCalls);}
    });}
}
echo 'PASS webhook clock exception boundaries: '.Check::$assertions.' assertions; '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION.PHP_EOL;
