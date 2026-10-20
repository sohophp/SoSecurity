<?php
declare(strict_types=1);
require __DIR__.'/recovery-notice-support.php';

managedCase(static function(ManagedEnvironment $e):void{
    list($f)=closedSetup($e);$receipt=[];$source=null;$service=replacementNoticeService($e,$f,$receipt,$source,static function():bool{return true;});
    list($pending)=switchPrepareProven($e,$service,$receipt);Check::same(true,$service->confirm($pending->selector(),'owned-replacement-notice',['type'=>'approved','code'=>'owned-strong-approval']));
    $ids=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);Check::same(2,count($ids));$types=[];foreach($ids as $id){$dispatch=$source->notificationForDispatch($id);Check::same(true,$dispatch!==null);$types[]=$dispatch->notice()->type();}sort($types);Check::same(['factor_recovery_started','factor_replaced'],$types);
});

managedCase(static function(ManagedEnvironment $e):void{
    list($f)=closedSetup($e);$receipt=[];$deny=false;$source=null;$service=replacementNoticeService($e,$f,$receipt,$source,static function()use(&$deny):bool{return !$deny;});
    list($pending)=switchPrepareProven($e,$service,$receipt);$before=replacementNoticeState($e);$flow=switchReadFlow($e,$pending->selector());$binding=$e->registry->current('user')->binding();$deny=true;
    try{$service->confirm($pending->selector(),'owned-refused-replacement-notice',['type'=>'approved','code'=>'owned-strong-approval']);throw new RuntimeException('Expected refusal.');}
    catch(SoSecurity\Exception\SecurityException $error){Check::same('account.factor_event',$error->reason());}
    $after=replacementNoticeState($e);Check::same($before['account_example'],$after['account_example']);Check::same($before['sosecurity_outbox_roots'],$after['sosecurity_outbox_roots']);Check::same($before['sosecurity_outbox_records'],$after['sosecurity_outbox_records']);
    $next=switchReadFlow($e,$pending->selector());Check::same($flow['attempts']+1,$next['attempts']);unset($flow['attempts'],$next['attempts']);Check::same($flow,$next);
    Check::same($binding,$e->registry->current('user')->binding());Check::same(1,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn());
});

echo 'PASS factor replacement notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." exact event and refusal rollback\n";
