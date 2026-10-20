<?php
declare(strict_types=1);
require __DIR__.'/resolution-support.php';

function resolutionNoticeSource(ManagedEnvironment $e,callable $publish):SoSecurity\Account\FactorNotices
{
    return new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
}
function resolutionNoticeService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,SoSecurity\Account\FactorNotices $source):SoSecurity\Account\FactorOperationResolution
{
    return resolutionService($e,$f,null,null,null,null,static function(string $type,array $v)use($source):bool{$source->publish($type,$v['subject'],$v['operation']);return true;});
}
managedCase(static function(ManagedEnvironment $e):void{
    list($f,$legacy,$ops,$operation)=unresolvedOperation($e,'reencrypt');
    $source=resolutionNoticeSource($e,static function():bool{return true;});$source->initialize();$resolution=resolutionNoticeService($e,$f,$source);
    $queued=(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn();$review=$resolution->review($operation['operation'],'owned-notice-abandon-review');$result=$resolution->abandon($review['context'],'owned-notice-abandon',normalProof());Check::same(true,$result['abandoned']);
    $ids=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);Check::same(1,count($ids));
    Check::same('factor_management_abandoned',$source->notificationForDispatch($ids[0])->notice()->type());
    Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM factor_resolution_audit')->fetchColumn());
    Check::same($queued+2,(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
});
managedCase(static function(ManagedEnvironment $e):void{
    list($f,$legacy,$ops,$operation)=unresolvedOperation($e,'reencrypt');$deny=true;
    $source=resolutionNoticeSource($e,static function()use(&$deny):bool{return !$deny;});$source->initialize();$resolution=resolutionNoticeService($e,$f,$source);
    $review=$resolution->review($operation['operation'],'owned-refused-abandon-review');$before=$e->row();$queued=(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn();
    migrationReason('account.completion_unknown',static function()use($resolution,$review):void{$resolution->abandon($review['context'],'owned-refused-abandon',normalProof());});
    Check::same($before,$e->row());Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM factor_resolution_audit')->fetchColumn());
    Check::same(0,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn());
    Check::same($queued,(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
    Check::same('prepared',$f->drain(static function()use($resolution,$operation):array{return $resolution->inspectClosed($operation['operation'],'owned-refused-abandon-inspect');},static function():bool{return true;})['state']);
});
echo 'PASS normal-operation abandonment notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." same-PDO success and refusal rollback\n";
