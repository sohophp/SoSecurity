<?php
declare(strict_types=1);
require __DIR__.'/operations-support.php';

$config=json_decode(file_get_contents($argv[1]),true);if(!is_array($config)||!isset($config['port'],$config['ca'],$config['coordination'])){throw new RuntimeException('Owned SMTP test configuration required.');}
$e=new ManagedEnvironment();
try{
    $e->registry->initialize('user');$f=purgeFence($e);$source=null;
    $operations=normalOperations($e,$f,null,null,null,static function(string $type,array $review)use(&$source):bool{if($type==='factor_management_started'){$source->publish($type,$review['subject'],$review['operation']);}return true;});
    $source=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    $source->initialize();$operations->initialize();$review=$operations->review('reencrypt','user','owned-smtp-factor-review');Check::same(true,$operations->execute($review,'owned-smtp-factor-execute',normalProof())['completed']);
    $noticeId=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchColumn();Check::same('factor_management_started',$source->notificationForDispatch($noticeId)->notice()->type());
    file_put_contents($config['coordination'],json_encode(['database'=>$e->directory.'/managed.sqlite']));chmod($config['coordination'],0600);
    $urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}
    $templates=new SoSecurity\Account\MailTemplates('managed-test',new SoSecurity\Account\Address('security@example.test'),$urls);
    $policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',10,60);}
    mkdir($e->directory.'/smtp-budgets',0700);$budgets=new SoSecurity\Account\SendBudgets(new SoSecurity\Storage\FileStore($e->directory.'/smtp-budgets','factor-smtp-test',$e->clock),'managed-test',str_repeat('b',32),$policies,$e->clock);
    $transport=new SoSecurity\Account\SmtpTransport('owned-factor-relay','smtp.example.test',$config['port'],'127.0.0.1','tls',null,$config['ca']);
    $worker=$source->dispatcher('worker',$budgets,$templates,$transport,static function():bool{return true;});$result=null;$error=null;
    try{$result=$worker->sendNext();}catch(SoSecurity\Exception\SecurityException $failure){$error=$failure->reason();}catch(SoSecurity\Storage\StorageException $failure){$error=$failure->reason();}
    $state=$e->observer->query("SELECT status FROM sosecurity_outbox_records WHERE topic='account.notice'")->fetchColumn();$e->clock->time+=61;
    try{$next=$worker->sendNext();}catch(SoSecurity\Exception\SecurityException $failure){$next=['error'=>$failure->reason()];}catch(SoSecurity\Storage\StorageException $failure){$next=['error'=>$failure->reason()];}
    $after=$e->observer->query("SELECT status FROM sosecurity_outbox_records WHERE topic='account.notice'")->fetchColumn();
    echo json_encode(['result'=>$result,'error'=>$error,'queue_state'=>$state,'next'=>$next,'after'=>$after,'account_status'=>$e->row()['status'],'notice_type'=>'factor_management_started'])."\n";
}finally{$e->close();}
