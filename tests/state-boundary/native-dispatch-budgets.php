<?php
declare(strict_types=1);
use SoSecurity\Account as A;
use SoSecurity\Storage as S;
final class OwnedBudgetMailTransport implements A\MailTransport
{
    public $calls=0;
    public $names=0;
    public function name():string{++$this->names;return 'owned-budget-relay';}
    public function send(A\MailMessage $message,int $milliseconds,callable $gate):A\MailResult{Check::same(true,$gate());++$this->calls;return new A\MailResult('accepted','smtp.accepted');}
}
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($oldBudgetDispatcher):void{$oldBudgetDispatcher->sendNext();});
$callbacks=0;$allow=static function()use(&$callbacks):bool{++$callbacks;return true;};$never=static function(){throw new RuntimeException('Recovery execution is outside this test');};$p=new A\Policy();$passwordPolicy=SoSecurity\Password\PasswordPolicy::forHasher($hasher);
$servicesToCheck=[
 'registration'=>new A\Registration($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$hasher,$passwordPolicy,$allow,$allow,$p,$clock,$allow,$allow,$accountConnection),
 'address'=>new A\AddressChange($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$sessions,$sdk->operations(),$allow,$allow,$p,$clock,$allow,$allow,$accountConnection),
 'recovery'=>new A\Recovery($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$hasher,$passwordPolicy,$never,$never,$p,$clock,$never,$never,null,$never,$accountConnection),
 'mailbox'=>new A\MailboxRecovery($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$never,$never,$never,$p,$clock,$never,$never,null,$accountConnection),
 'factor'=>new A\FactorNotices($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$allow,$allow,$allow,$p,$clock,$accountConnection),
];
$urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account','recover_address'] as $action){$urls[$action]='https://owned.example/'.$action;}$templates=new A\MailTemplates('fresh-site',new A\Address('security@owned.example'),$urls);$transport=new OwnedBudgetMailTransport();
$policies=[];foreach(['site','transport','target','subject'] as $dimension){$policies[$dimension]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
$makeBudgets=static function(S\AtomicStore $storage)use($policies,$clock):A\SendBudgets{return new A\SendBudgets($storage,'fresh-site',str_repeat('b',32),$policies,$clock);};
$foreignBefore=glob($directory.'/budget/*');$foreign=new S\FileStore($directory.'/budget','send',$clock);$bad=$makeBudgets($foreign);$before=$witness->inspect(static function():bool{return true;});$sourceBefore=$source->digest();
foreach($servicesToCheck as $service){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($service,$bad,$templates,$transport,$allow):void{$service->dispatcher('owned-worker',$bad,$templates,$transport,$allow);});}
Check::same(0,$callbacks);Check::same(0,$transport->calls);Check::same(0,$transport->names);Check::same($sourceBefore,$source->digest());Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($foreignBefore,glob($directory.'/budget/*'));
$covered=new S\FileStore($directory.'/files','send-budget',$clock);$wrapped=$boundary->protect($covered);$good=$makeBudgets($wrapped);$nested=$makeBudgets(new S\NamespacedStore($wrapped,'owned-send'));
foreach($servicesToCheck as $service){Check::same(true,$service->dispatcher('owned-worker',$good,$templates,$transport,$allow) instanceof A\Dispatcher);Check::same(true,$service->dispatcher('owned-worker',$nested,$templates,$transport,$allow) instanceof A\Dispatcher);}
Check::same(0,$callbacks);Check::same(0,$transport->names);
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($good,$witness,$clock):void{$good->validateState(new A\StateBoundary($witness,static function():bool{return true;}),'fresh-site',$clock);});
$rawQueue=new SoSecurity\Outbox\SqlOutbox($pdo,'fresh-site',$epoch,$keys,$allow,null,$clock);
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($rawQueue,$servicesToCheck,$good,$templates,$transport,$clock):void{new A\Dispatcher('fresh-site','tenant','owned-worker',$rawQueue,$servicesToCheck['factor'],$good,$templates,$transport,$clock);});
// Only one fresh factor notification is published and sent through an in-process test transport.
$factor=$servicesToCheck['factor'];$boundary->run('owned.send.initialize',static function()use($factor):void{$factor->initialize();});
$boundary->run('owned.send.publish',static function()use($factor,$pdo):void{$pdo->beginTransaction();try{$factor->publish('factor_management_completed','fresh-user',str_repeat('a',64));$pdo->commit();}catch(Throwable $error){if($pdo->inTransaction()){$pdo->rollBack();}throw $error;}});
if(($argv[3]??'')==='native_dispatch'){require __DIR__.'/native-dispatch-first.php';return;}
$sender=$factor->dispatcher('owned-worker',$good,$templates,$transport,$allow);Check::throws(SoSecurity\Storage\StorageException::class,static function()use($sender):void{$sender->sendNext();});Check::same(0,$transport->calls);
$result=$boundary->run('owned.send.first',static function()use($sender):array{return $sender->sendNext();});Check::same(['state'=>'submitted','code'=>'smtp.accepted'],$result);Check::same(1,$transport->calls);Check::same('sent',$pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same('current',$witness->inspect(static function():bool{return true;})['status']);Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);Check::same($foreignBefore,glob($directory.'/budget/*'));
echo 'PASS protected send budget composition: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; five factories, one first local simulated delivery, no recovery execution'.PHP_EOL;
