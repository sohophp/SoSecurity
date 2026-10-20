<?php
declare(strict_types=1);
require __DIR__.'/recovery-support.php';
$config=json_decode(file_get_contents($argv[1]),true);$action=$argv[2];
if($config['mysql']){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$config['socket'])||!is_file(dirname($config['socket']).'/account-test-owner')){throw new RuntimeException('Expected an owned no-TCP local MySQL instance.');}$dsn='mysql:unix_socket='.$config['socket'].';dbname=sosecurity_test;charset=utf8mb4';}else{$dsn='sqlite:'.$config['database'];}
$opts=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>5];if($config['mysql']){$opts[PDO::ATTR_EMULATE_PREPARES]=false;}$pdo=new InboxTestConnection($dsn,$config['mysql']?'sosecurity_test':null,$config['mysql']?'integration-only':null,$opts);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);
$clock=new TestClock();$clock->time=$config['time'];$accounts=new SoSecurity\Account\Example\SqlAccounts($pdo);$hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);$guard=static function():bool{return true;};$policies=[];foreach(['site','source','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
$budget=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($config['directory'].'/budgets','recovery-budgets',$clock,5000),'account-test',str_repeat('p',32),$policies,$clock);$factor=null;
if($config['mfa']){$factor=new SoSecurity\Auth\TotpSecondFactor(new SoSecurity\Mfa\TotpFactors(new SoSecurity\Storage\FileStore($config['directory'].'/budgets','recovery-race-factors',$clock,5000),new SoSecurity\Crypto\Cipher('factor',['factor'=>str_repeat('f',32)],'recovery-race-factor',256),'Recovery race',$clock));}
$service=new SoSecurity\Account\Recovery($pdo,'account-test','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('recovery',['recovery'=>str_repeat('r',32)]),new SoSecurity\Support\HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts,new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$clock),$hasher,SoSecurity\Password\PasswordPolicy::forHasher($hasher,15),$guard,$budget,null,$clock,$guard,$guard,$factor);
if($config['pause']!==''){
    $pause=static function()use($pdo,$config,$hasher):void{$hash=$pdo->query('SELECT password FROM account_example')->fetchColumn();if(is_string($hash)&&$hasher->verify($config['password'],$hash)){file_put_contents($config['ready'],'ready');while(true){usleep(100000);}}};
    if($config['pause']==='before'){$pdo->beforeCommit=$pause;}else{$pdo->afterCommit=$pause;}
}
try{if($action==='request'){$service->request('owner@example.com','shared-race-source');$result=true;}else{$proof=$config['mfa']?['type'=>'recovery','code'=>$config['recovery_code']]:[];$result=$service->confirm($config['selector'],$config['token'],$config['password'],'shared-race-source',$proof);}echo json_encode(['result'=>$result])."\n";}
catch(SoSecurity\Exception\SecurityException $error){echo json_encode(['result'=>false,'reason'=>$error->reason()])."\n";exit(10);}
