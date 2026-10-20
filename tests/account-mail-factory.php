<?php
declare(strict_types=1);
if(($argv[1] ?? '')==='mysql'){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
require __DIR__.'/account-dispatch-support.php';require __DIR__.'/recovery-support.php';
function mailFactoryChecks(RegistrationEnvironment $e,$source):void {
    $policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
    $budgets=new SoSecurity\Account\SendBudgets(new SoSecurity\Storage\FileStore($e->directory.'/budgets','factory-send',$e->clock),'account-test',str_repeat('s',32),$policies,$e->clock);
    $transport=new TestMailTransport();$queries=$e->pdo->queries;$callbacks=0;$session=session_status();$headers=headers_list();
    $sender=$source->dispatcher('mail-worker',$budgets,dispatchTemplates(),$transport,static function()use(&$callbacks):bool{++$callbacks;return false;});
    Check::same($queries,$e->pdo->queries);Check::same(0,$callbacks);Check::same(0,$transport->calls);Check::same($session,session_status());Check::same($headers,headers_list());
    Check::same('idle',$sender->sendNext()['state']);Check::same(0,$transport->calls);Check::same(true,$callbacks>0);
}
registrationCase(static function(RegistrationEnvironment $e):void{mailFactoryChecks($e,$e->service());});
changeCase(static function(ChangeEnvironment $t):void{mailFactoryChecks($t->e,$t->service);});
recoveryCase(static function(RecoveryEnvironment $r):void{mailFactoryChecks($r->e,$r->service);});
// A missing CA or unreachable pinned endpoint is consulted only by explicit send().
$transport=new SoSecurity\Account\SmtpTransport('owned','smtp.example.test',465,'192.0.2.1','tls',null,'/nonexistent-owned-mail-ca.pem');Check::same('owned',$transport->name());
foreach([
 ['owned','smtp.example.test',465,'not-an-address','tls'],
 ['owned','smtp.example.test',465,'127.0.0.1','plain'],
 ['owned','smtp.example.test',465,'127.0.0.1','tls',['username'=>"bad\r\nuser",'password'=>'owned']],
 ['owned','smtp.example.test',465,'127.0.0.1','tls',['username'=>'owned','password'=>"bad\0secret"]],
 ['owned','smtp.example.test',465,'127.0.0.1','tls',null,"/tmp/ca\0pem"]
] as $args){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($args):void{new SoSecurity\Account\SmtpTransport(...$args);});}
echo 'PASS side-effect-free account mail factories: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; all three service factories and worker denial, constructor validation; no external endpoint contacted\n";
