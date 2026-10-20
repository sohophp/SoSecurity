<?php
declare(strict_types=1);
require __DIR__.'/revocation-support.php';

function ownedRevocationNotices(ManagedEnvironment $e,callable $publish):SoSecurity\Account\FactorNotices
{
    return new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
}

managedCase(static function(ManagedEnvironment $e):void{
    $f=revocationSetup($e);$source=ownedRevocationNotices($e,static function():bool{return true;});$source->initialize();
    $service=revocationService($e,$f,null,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    $review=$service->review('user','owned-revocation-notice');$before=$e->row();$result=$service->execute($review['context'],'owned-revoke-with-notice',normalProof());Check::same(true,$result['revoked']);Check::same(false,$before['credential_version']===$e->row()['credential_version']);
    $rows=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);Check::same(1,count($rows));Check::same('factor_privileged_revoked',$source->notificationForDispatch($rows[0])->notice()->type());
    $urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}$templates=new SoSecurity\Account\MailTemplates('managed-test',new SoSecurity\Account\Address('security@example.test'),$urls);
    $policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',2,60);}mkdir($e->directory.'/revocation-notice-budgets',0700);$budgets=new SoSecurity\Account\SendBudgets(new SoSecurity\Storage\FileStore($e->directory.'/revocation-notice-budgets','revocation-notice-test',$e->clock),'managed-test',str_repeat('b',32),$policies,$e->clock,1);
    $transport=new class implements SoSecurity\Account\MailTransport {public $sent=0;public function name():string{return 'local-relay';}public function send(SoSecurity\Account\MailMessage $message,int $milliseconds,callable $gate):SoSecurity\Account\MailResult{Check::same(true,$gate());++$this->sent;return new SoSecurity\Account\MailResult('accepted','smtp.accepted');}};
    $worker=$source->dispatcher('worker',$budgets,$templates,$transport,static function():bool{return true;});Check::same('submitted',$worker->sendNext()['state']);Check::same(1,$transport->sent);Check::same('idle',$worker->sendNext()['state']);
});

managedCase(static function(ManagedEnvironment $e):void{
    $f=revocationSetup($e);$source=ownedRevocationNotices($e,static function():bool{return false;});$source->initialize();
    $service=revocationService($e,$f,null,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    $review=$service->review('user','owned-refused-notice');$before=revocationState($e);$factor=modeSnapshot($e);
    migrationReason('account.completion_unknown',static function()use($service,$review):void{$service->execute($review['context'],'owned-refused-notice',normalProof());});
    Check::same($before,revocationState($e));Check::same($factor,modeSnapshot($e));Check::same(0,(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn());
});

echo 'PASS privileged revocation notices: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." same-PDO delivery and refusal rollback\n";
