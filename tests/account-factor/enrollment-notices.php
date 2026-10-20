<?php
declare(strict_types=1);
require __DIR__.'/enroll-support.php';

function enrollmentNoticeSource(ManagedEnvironment $e,callable $publish):SoSecurity\Account\FactorNotices
{
    return new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
}

function enrollmentNoticeTypes(ManagedEnvironment $e,SoSecurity\Account\FactorNotices $source):array
{
    $ids=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);$types=[];
    foreach($ids as $id){$dispatch=$source->notificationForDispatch($id);Check::same(true,$dispatch!==null);$types[]=$dispatch->notice()->type();}sort($types);return $types;
}

function enrollmentNoticeOperations(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?SoSecurity\Account\FactorNotices &$source,callable $publish,?callable $beforePublish=null):SoSecurity\Account\FactorOperations
{
    $ops=normalOperations($e,$f,null,null,null,static function(string $type,array $review)use(&$source,$beforePublish):bool{if($beforePublish!==null){$beforePublish($type,$review);}$source->publish($type,$review['subject'],$review['operation']);return true;});
    $source=enrollmentNoticeSource($e,$publish);$source->initialize();$ops->initialize();return $ops;
}

managedCase(static function(ManagedEnvironment $e):void{
    $e->registry->initialize('user');$f=purgeFence($e);$source=null;$ops=enrollmentNoticeOperations($e,$f,$source,static function():bool{return true;});
    list($review,$pending,$secret)=ownedEnrollment($ops,$e);$codes=$ops->confirmEnrollment($review,'owned-notice-confirm',normalProof(),enrollmentCode($e,$secret));Check::same(10,count($codes));
    Check::same(['factor_enrolled','factor_enrollment_prepared','factor_enrollment_started'],enrollmentNoticeTypes($e,$source));
    $e->secret=$secret;$disable=$ops->review('disable','user','owned-notice-disable-review');Check::same(true,$ops->execute($disable,'owned-notice-disable',normalProof(),normalFactor($e))['completed']);Check::same(1,$ops->clean($disable['operation'],'owned-notice-management-clean')['absent']);
    Check::same(['factor_enrolled','factor_enrollment_prepared','factor_enrollment_started','factor_management_cleaned','factor_management_completed','factor_management_started'],enrollmentNoticeTypes($e,$source));
},false);

managedCase(static function(ManagedEnvironment $e):void{
    $e->registry->initialize('user');$f=purgeFence($e);$source=null;$ops=enrollmentNoticeOperations($e,$f,$source,static function():bool{return true;});
    list($review)=ownedEnrollment($ops,$e);Check::same(['cancelled'=>true,'absent'=>1,'conflicts'=>0],$ops->cancelEnrollment($review['operation'],'owned-notice-cancel'));
    Check::same(['factor_enrollment_cancelled','factor_enrollment_cleaned','factor_enrollment_prepared','factor_enrollment_started'],enrollmentNoticeTypes($e,$source));
},false);

managedCase(static function(ManagedEnvironment $e):void{
    $e->registry->initialize('user');$f=purgeFence($e);$source=null;$deny=false;$armed=true;$ops=enrollmentNoticeOperations($e,$f,$source,static function()use(&$deny):bool{return !$deny;},static function(string $type)use(&$deny,&$armed):void{if($armed&&$type==='factor_enrolled'){$deny=true;$armed=false;}});
    list($review,$pending,$secret)=ownedEnrollment($ops,$e);$before=$e->row();enrollmentReason('account.completion_unknown',static function()use($ops,$review,$e,$secret):void{$ops->confirmEnrollment($review,'owned-refused-enrolled-notice',normalProof(),enrollmentCode($e,$secret));});
    Check::same($before,$e->row());Check::same('pending',$ops->inspect($review['operation'],'owned-refused-enrolled-inspect')['state']);Check::same(['factor_enrollment_prepared','factor_enrollment_started'],enrollmentNoticeTypes($e,$source));
    $deny=false;Check::same(['cancelled'=>true,'absent'=>1,'conflicts'=>0],$ops->cancelEnrollment($review['operation'],'owned-refused-enrolled-cleanup'));
},false);

echo 'PASS enrollment and management cleanup notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." active account binding, cancellation and exact cleanup\n";
