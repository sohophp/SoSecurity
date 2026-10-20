<?php
declare(strict_types=1);
require __DIR__.'/migration-support.php';

function migrationNoticeService(ManagedEnvironment $e,SoSecurity\Mfa\TotpFactors $legacy,SoSecurity\Account\LocalEpochFence $f,?SoSecurity\Account\FactorNotices &$source,callable $publish,?callable $beforePublish=null):SoSecurity\Account\FactorMigration
{
    $service=migrationService($e,$legacy,$f,null,null,null,null,null,static function(string $type,array $review)use(&$source,$beforePublish):bool{
        if($beforePublish!==null){$beforePublish($type,$review);}
        $id=hash('sha256',json_encode(['SoSecurity.Account.FactorMigration.Notice.1',$review['operation'],$review['nonce']],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $source->publish($type,$review['subject'],$id);return true;
    });
    $source=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
    $source->initialize();$service->initialize('owned-migration-notice-bootstrap');return $service;
}

function migrationNoticeTypes(ManagedEnvironment $e,SoSecurity\Account\FactorNotices $source):array
{
    $rows=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);$types=[];
    foreach($rows as $id){$dispatch=$source->notificationForDispatch($id);Check::same(true,$dispatch!==null);$types[]=$dispatch->notice()->type();}sort($types);return $types;
}

managedCase(static function(ManagedEnvironment $e):void{
    list($f,$legacy)=migrationSetup($e,true);$source=null;$service=migrationNoticeService($e,$legacy,$f,$source,static function():bool{return true;});
    $review=$service->review('user','owned-migration-notice-review',migrationStop());Check::same(true,$service->execute($review,'owned-migration-notice-execute',migrationProof())['completed']);
    Check::same(['factor_migration_activated','factor_migration_completed','factor_migration_reserved'],migrationNoticeTypes($e,$source));
});

managedCase(static function(ManagedEnvironment $e):void{
    list($f,$legacy)=migrationSetup($e,true);$source=null;$deny=false;$armed=true;$service=migrationNoticeService($e,$legacy,$f,$source,static function()use(&$deny):bool{return !$deny;},static function(string $type)use(&$deny,&$armed):void{if($armed&&$type==='factor_migration_completed'){$deny=true;$armed=false;}});
    $review=$service->review('user','owned-refused-migration-review',migrationStop());
    migrationReason('account.completion_unknown',static function()use($service,$review):void{$service->execute($review,'owned-refused-migration-notice',migrationProof());});
    Check::same('reserved',$service->inspect($review['operation'],'owned-refused-migration-inspect')['state']);Check::same(['factor_migration_reserved'],migrationNoticeTypes($e,$source));
    $deny=false;$fresh=$service->reviewPending($review['operation'],'owned-migration-reapproval',migrationStop());Check::same(true,$service->resume($fresh,'owned-migration-resume',migrationProof())['completed']);
    Check::same(['factor_migration_activated','factor_migration_completed','factor_migration_reapproved','factor_migration_reserved'],migrationNoticeTypes($e,$source));
});

managedCase(static function(ManagedEnvironment $e):void{
    $armed=true;list($f,$legacy)=migrationSetup($e,false,static function(string $action,string $phase)use(&$armed):bool{if($armed&&$action==='adoptManagedExact'&&$phase==='before'){$armed=false;return false;}return true;});
    $source=null;$service=migrationNoticeService($e,$legacy,$f,$source,static function():bool{return true;});$review=$service->review('user','owned-cancelled-migration-review',migrationStop());
    migrationReason('account.completion_unknown',static function()use($service,$review):void{$service->execute($review,'owned-cancelled-migration-reserve',migrationProof());});
    $cancel=$service->reviewPending($review['operation'],'owned-cancelled-migration-review',migrationStop(),true);Check::same(true,$service->cancel($cancel,'owned-cancelled-migration-notice',migrationProof())['cancelled']);
    Check::same(['factor_migration_cancelled','factor_migration_reserved'],migrationNoticeTypes($e,$source));
});

echo 'PASS factor migration notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." fixed phase notifications and refusal recovery\n";
