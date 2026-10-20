<?php
declare(strict_types=1);
require __DIR__.'/restoration-support.php';

function cleanupNoticeSource(ManagedEnvironment $e,callable $publish):SoSecurity\Account\FactorNotices
{
    return new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
}

function cleanupNoticeTypes(ManagedEnvironment $e,SoSecurity\Account\FactorNotices $source):array
{
    $rows=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);$types=[];
    foreach($rows as $id){$notice=$source->notificationForDispatch($id);Check::same(true,$notice!==null);$types[]=$notice->notice()->type();}sort($types);return $types;
}

foreach(['previous','cancelled'] as $mode){managedCase(static function(ManagedEnvironment $e)use($mode):void{
    $f=restorationSetup($e);$source=cleanupNoticeSource($e,static function():bool{return true;});$source->initialize();
    $r=restorationService($e,$f,null,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    if($mode==='previous'){
        list($v)=restorationProven($e,$r);$activate=$r->operationReview($v['operation'],'owned-notice-activate');Check::same(true,$r->activate($activate,'owned-notice-activated',normalProof())['restored']);
        $clean=$f->drain(static function()use($r,$v):array{return $r->operationReviewClosed($v['operation'],'owned-notice-previous-review','clean_previous');},static function():bool{return true;});
        Check::same(true,$f->drain(static function()use($r,$clean):array{return $r->cleanClosed($clean,'owned-notice-previous-clean',normalProof());},static function():bool{return true;})['old_cleaned']);
        Check::same(['factor_restoration_activated','factor_restoration_previous_cleaned','factor_restoration_started'],cleanupNoticeTypes($e,$source));
    }else{
        list($v)=restorationPrepared($e,$r);$cancel=$r->operationReview($v['operation'],'owned-notice-cancel-review','cancel');Check::same(true,$r->cancel($cancel,'owned-notice-cancelled',normalProof())['cancelled']);
        $clean=$r->operationReview($v['operation'],'owned-notice-clean-review','clean');Check::same(true,$r->clean($clean,'owned-notice-cleaned',normalProof())['removed']);
        Check::same(['factor_restoration_cancelled','factor_restoration_cleaned','factor_restoration_started'],cleanupNoticeTypes($e,$source));
    }
});}

foreach(['previous','cancelled'] as $mode){managedCase(static function(ManagedEnvironment $e)use($mode):void{
    $f=restorationSetup($e);$deny=false;$source=cleanupNoticeSource($e,static function()use(&$deny):bool{return !$deny;});$source->initialize();
    $r=restorationService($e,$f,null,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    if($mode==='previous'){
        list($v)=restorationProven($e,$r);$activate=$r->operationReview($v['operation'],'owned-refusal-activate');$r->activate($activate,'owned-refusal-activated',normalProof());
        $review=$f->drain(static function()use($r,$v):array{return $r->operationReviewClosed($v['operation'],'owned-refusal-previous-review','clean_previous');},static function():bool{return true;});
    }else{
        list($v)=restorationPrepared($e,$r);$cancel=$r->operationReview($v['operation'],'owned-refusal-cancel-review','cancel');$r->cancel($cancel,'owned-refusal-cancelled',normalProof());
        $review=$r->operationReview($v['operation'],'owned-refusal-clean-review','clean');
    }
    $before=restorationState($e);$notices=(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn();$deny=true;
    migrationReason('account.completion_unknown',static function()use($mode,$f,$r,$review):void{if($mode==='previous'){$f->drain(static function()use($r,$review):void{$r->cleanClosed($review,'owned-refused-previous-notice',normalProof());},static function():bool{return true;});}else{$r->clean($review,'owned-refused-clean-notice',normalProof());}});
    Check::same($before,restorationState($e));Check::same($notices,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn());
    $deny=false;
    if($mode==='previous'){$retry=$f->drain(static function()use($r,$v):array{return $r->operationReviewClosed($v['operation'],'owned-retry-previous-review','clean_previous');},static function():bool{return true;});Check::same(true,$f->drain(static function()use($r,$retry):array{return $r->cleanClosed($retry,'owned-retry-previous-notice',normalProof());},static function():bool{return true;})['old_cleaned']);}
    else{$retry=$f->drain(static function()use($r,$v):array{return $r->operationReviewClosed($v['operation'],'owned-retry-clean-review','clean');},static function():bool{return true;});Check::same(true,$f->drain(static function()use($r,$retry):array{return $r->cleanClosed($retry,'owned-retry-clean-notice',normalProof());},static function():bool{return true;})['removed']);}
    Check::same($notices+1,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn());
});}

echo 'PASS restoration cleanup notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." terminal events and refusal recovery\n";
