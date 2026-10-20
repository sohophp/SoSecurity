<?php
declare(strict_types=1);
require __DIR__.'/restoration-support.php';

function ownedRestorationNotices(ManagedEnvironment $e,callable $publish):SoSecurity\Account\FactorNotices
{
    return new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
}

managedCase(static function(ManagedEnvironment $e):void{
    $f=restorationSetup($e);$source=ownedRestorationNotices($e,static function():bool{return true;});$source->initialize();
    $r=restorationService($e,$f,null,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    list($v)=restorationProven($e,$r);$review=$r->operationReview($v['operation'],'owned-activation-notice-review');Check::same(true,$r->activate($review,'owned-activation-notice',normalProof())['restored']);
    $rows=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);Check::same(2,count($rows));$types=[];foreach($rows as $id){$notice=$source->notificationForDispatch($id);Check::same(true,$notice!==null);$types[]=$notice->notice()->type();}sort($types);Check::same(['factor_restoration_activated','factor_restoration_started'],$types);
});

foreach(['activated','cancelled'] as $refused){managedCase(static function(ManagedEnvironment $e)use($refused):void{
    $f=restorationSetup($e);$deny=false;$source=ownedRestorationNotices($e,static function()use(&$deny):bool{return !$deny;});$source->initialize();
    $r=restorationService($e,$f,null,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    if($refused==='activated'){list($v)=restorationProven($e,$r);$review=$r->operationReview($v['operation'],'owned-refused-activation-review');}
    else{list($v)=restorationPrepared($e,$r);$review=$r->operationReview($v['operation'],'owned-refused-cancel-review','cancel');}
    $before=restorationState($e);$physical=['old'=>modeSnapshot($e),'new'=>restorationPhysical($e,$v)];$deny=true;
    migrationReason($refused==='activated'?'account.completion_unknown':'account.restoration_event',static function()use($r,$refused,$review):void{if($refused==='activated'){$r->activate($review,'owned-refused-activation-notice',normalProof());}else{$r->cancel($review,'owned-refused-cancel-notice',normalProof());}});
    Check::same($before,restorationState($e));Check::same($physical,['old'=>modeSnapshot($e),'new'=>restorationPhysical($e,$v)]);Check::same($refused==='activated'?'proven':'pending',$f->drain(static function()use($r,$v):array{return $r->inspectClosed($v['operation'],'owned-refusal-inspect');},static function():bool{return true;})['state']);
    Check::same(1,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn());
});}

echo 'PASS independent restoration notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." same-PDO activation and cancellation refusal rollback\n";
