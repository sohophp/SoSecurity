<?php
declare(strict_types=1);
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Use only owned local MySQL state.');}
$GLOBALS['registrationMySQLSocket']=$socket;
require __DIR__.'/account-dispatch-support.php';
$config=json_decode(file_get_contents($argv[1]),true);$e=new RegistrationEnvironment();try{
    $source=$e->service();$source->initialize();$source->request('owner@example.com','owned-source');file_put_contents($config['coordination'],json_encode(['socket'=>$socket]));chmod($config['coordination'],0600);
    $transport=new SoSecurity\Account\SmtpTransport('local-test','smtp.example.test',$config['port'],'127.0.0.1','tls',null,$config['ca']);$sender=dispatcher($e,$source,$transport);$result=null;$exception=null;
    try{$result=$sender->sendNext();}catch(SoSecurity\Exception\SecurityException $error){$exception=$error->reason();}
    $state=$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn();$e->clock->time+=61;$next=$sender->sendNext();$after=$e->pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn();
    echo json_encode(['result'=>$result,'exception'=>$exception,'queue_state'=>$state,'next'=>$next,'after'=>$after,'account_status'=>$e->account()['status']])."\n";
}finally{$e->close();}
