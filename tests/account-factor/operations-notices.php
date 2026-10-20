<?php
declare(strict_types=1);
require __DIR__.'/operations-support.php';

managedCase(static function(ManagedEnvironment $e):void{
    $e->registry->initialize('user');$f=purgeFence($e);
    $source=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    $operations=normalOperations($e,$f,null,null,null,static function(string $type,array $review)use($source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});$source->initialize();$operations->initialize();
    $review=$operations->review('reencrypt','user','owned-factor-notice-review');$result=$operations->execute($review,'owned-factor-notice-execute',normalProof());Check::same(true,$result['completed']);
    $count=(int)$e->observer->query("SELECT COUNT(*) FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn();Check::same(2,$count);
    $urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}
    $templates=new SoSecurity\Account\MailTemplates('managed-test',new SoSecurity\Account\Address('security@example.test'),$urls);
    $policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',10,60);}
    mkdir($e->directory.'/notice-budgets',0700);$budgets=new SoSecurity\Account\SendBudgets(new SoSecurity\Storage\FileStore($e->directory.'/notice-budgets','managed-notice-test',$e->clock),'managed-test',str_repeat('b',32),$policies,$e->clock);
    $transport=new class implements SoSecurity\Account\MailTransport {public $sent=0;public function name():string{return 'local-relay';}public function send(SoSecurity\Account\MailMessage $message,int $milliseconds,callable $gate):SoSecurity\Account\MailResult{Check::same(true,$gate());++$this->sent;return new SoSecurity\Account\MailResult('accepted','smtp.accepted');}};
    $worker=$source->dispatcher('worker',$budgets,$templates,$transport,static function():bool{return true;});Check::same('submitted',$worker->sendNext()['state']);Check::same('submitted',$worker->sendNext()['state']);Check::same('idle',$worker->sendNext()['state']);Check::same(2,$transport->sent);
    $id=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice' ORDER BY record_id LIMIT 1")->fetchColumn();$before=$source->notificationForDispatch($id)->notice()->encode();$queue=$e->observer->query('SELECT payload_digest,created_at FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);
    $rotated=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('new',['test'=>str_repeat('s',32),'new'=>str_repeat('x',32)]),$e->keys,$e->accounts,new SoSecurity\Account\Notifications('new',['notice'=>str_repeat('n',32),'new'=>str_repeat('z',32)],$e->clock),static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    $page=$rotated->rotate(1);$next=$rotated->rotate(1,$page['next']);Check::same(1,$page['reencrypted']);Check::same(1,$next['reencrypted']);Check::same(true,$rotated->rotate(1,$next['next'])['done']);
    $retired=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('x',32)]),$e->keys,$e->accounts,new SoSecurity\Account\Notifications('new',['new'=>str_repeat('z',32)],$e->clock),static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);Check::same($before,$retired->notificationForDispatch($id)->notice()->encode());Check::same($queue,$e->observer->query('SELECT payload_digest,created_at FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
});
echo 'PASS managed factor notification callback: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." same-PDO operation and bounded worker\n";
