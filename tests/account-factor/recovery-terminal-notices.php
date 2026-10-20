<?php
declare(strict_types=1);
require __DIR__.'/recovery-notice-support.php';

function terminalNoticeRetireAt(ManagedEnvironment $e,string $selector):int
{
    $q=$e->observer->prepare('SELECT retire_at FROM sosecurity_account_records WHERE record_id=?');$q->execute([$selector]);$value=$q->fetchColumn();$q->closeCursor();if($value===false){throw new RuntimeException('Owned retained recovery record required.');}return (int)$value;
}

managedCase(static function(ManagedEnvironment $e):void{
    list($f)=closedSetup($e);$receipt=[];$source=null;$service=replacementNoticeService($e,$f,$receipt,$source,static function():bool{return true;});
    $pending=$service->begin('user','owned-terminal-notice-start');Check::same(true,$service->cancel($pending->selector(),'owned-terminal-notice-cancel'));
    Check::same(['factor_recovery_cancelled','factor_recovery_started'],replacementNoticeTypes($e,$source));
    $e->clock->time=terminalNoticeRetireAt($e,$pending->selector());$result=$service->drainAndPurge($pending->selector(),'owned-terminal-notice-purge');Check::same(2,$result['removed']);
    Check::same(['factor_recovery_cancelled','factor_recovery_purged','factor_recovery_started'],replacementNoticeTypes($e,$source));
});

managedCase(static function(ManagedEnvironment $e):void{
    list($f)=closedSetup($e);$receipt=[];$deny=false;$source=null;$service=replacementNoticeService($e,$f,$receipt,$source,static function()use(&$deny):bool{return !$deny;});
    $pending=$service->begin('user','owned-refused-cancel-start');$before=replacementNoticeState($e);$flow=switchReadFlow($e,$pending->selector());$deny=true;
    try{$service->cancel($pending->selector(),'owned-refused-cancel-notice');throw new RuntimeException('Expected cancellation refusal.');}
    catch(SoSecurity\Exception\SecurityException $error){Check::same('account.factor_event',$error->reason());}
    Check::same($before,replacementNoticeState($e));Check::same($flow,switchReadFlow($e,$pending->selector()));
    $deny=false;Check::same(true,$service->cancel($pending->selector(),'owned-retry-cancel-notice'));
    Check::same(['factor_recovery_cancelled','factor_recovery_started'],replacementNoticeTypes($e,$source));
});

managedCase(static function(ManagedEnvironment $e):void{
    list($f)=closedSetup($e);$receipt=[];$deny=false;$source=null;$service=replacementNoticeService($e,$f,$receipt,$source,static function()use(&$deny):bool{return !$deny;});
    $pending=$service->begin('user','owned-refused-purge-start');$service->cancel($pending->selector(),'owned-refused-purge-cancel');$e->clock->time=terminalNoticeRetireAt($e,$pending->selector());$before=replacementNoticeState($e);$flow=switchReadFlow($e,$pending->selector());$deny=true;
    try{$service->drainAndPurge($pending->selector(),'owned-refused-purge-notice');throw new RuntimeException('Expected purge refusal.');}
    catch(SoSecurity\Exception\SecurityException $error){Check::same('account.completion_unknown',$error->reason());}
    Check::same($before,replacementNoticeState($e));Check::same($flow,switchReadFlow($e,$pending->selector()));
    $deny=false;$result=$service->drainAndPurge($pending->selector(),'owned-retry-purge-notice');Check::same(2,$result['removed']);
    Check::same(['factor_recovery_cancelled','factor_recovery_purged','factor_recovery_started'],replacementNoticeTypes($e,$source));
});

echo 'PASS factor recovery terminal notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." cancellation, purge and refusal recovery\n";
