<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
use SoSecurity\Storage as S;
final class RejectedBudgetStore implements S\AtomicStore
{
 private $store;public $states=[];
 public function __construct(TestClock $clock){$this->store=new S\MemoryStore($clock);}
 public function transact(string $key,callable $callback){return $this->store->transact($key,function($state)use($key,$callback):S\Change{$change=$callback($state);$this->states[$key]=$change->value();return $change;});}
}
function rejectedBudget(int $maximum=3):array{$clock=new TestClock();$store=new RejectedBudgetStore($clock);$policies=[];foreach(['site','transport','target','subject'] as $dimension){$policies[$dimension]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',10,60);}return [$clock,$store,new A\SendBudgets($store,'owned-site',str_repeat('b',32),$policies,$clock,$maximum)];}
$delivery=new A\DispatchNotice(new A\Notice('tenant',str_repeat('a',64),'factor_management_completed',new A\Address('owner@owned.test'),'',100000,100900),'','owned-user');$urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $name){$urls[$name]='https://owned.test/'.$name;}$templates=new A\MailTemplates('owned-site',new A\Address('security@owned.test'),$urls);$mail=$templates->render($delivery);$deliveryId=str_repeat('d',64);
list($clock,$store,$budget)=rejectedBudget();Check::throws(S\StorageException::class,static function()use($budget,$delivery,$mail,$deliveryId):void{$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,2);});
Check::same(true,$budget->reserve($delivery,$mail,'owned-relay',$deliveryId,1)!==null);$before=$store->states;Check::throws(S\StorageException::class,static function()use($budget,$delivery,$mail,$deliveryId):void{$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,2);});Check::same($before,$store->states);
Check::same(true,$budget->started($delivery,$mail,$deliveryId,1));$before=$store->states;Check::throws(S\StorageException::class,static function()use($budget,$delivery,$mail,$deliveryId):void{$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,2);});Check::same($before,$store->states);
Check::same(true,$budget->settle($delivery,$mail,$deliveryId,1,new A\MailResult('rejected','smtp.temporary',true)));$before=$store->states;
Check::throws(S\StorageException::class,static function()use($budget,$delivery,$mail,$deliveryId):void{$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,1);});Check::same($before,$store->states);
$changed=new A\MailMessage(new A\Address('security@owned.test'),$mail->recipient(),$mail->messageId(),'Changed','Changed body',100000);Check::throws(S\StorageException::class,static function()use($budget,$delivery,$changed,$deliveryId):void{$budget->reserveRejected($delivery,$changed,'owned-relay',$deliveryId,2);});Check::same($before,$store->states);
Check::same(true,$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,2)!==null);Check::same(true,$budget->started($delivery,$mail,$deliveryId,2));Check::same(true,$budget->settle($delivery,$mail,$deliveryId,2,new A\MailResult('accepted','smtp.accepted')));$before=$store->states;Check::throws(S\StorageException::class,static function()use($budget,$delivery,$mail,$deliveryId):void{$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,3);});Check::same($before,$store->states);
list($clock,$store,$budget)=rejectedBudget(1);Check::same(true,$budget->reserve($delivery,$mail,'owned-relay',$deliveryId,1)!==null);Check::same(true,$budget->started($delivery,$mail,$deliveryId,1));Check::same(true,$budget->settle($delivery,$mail,$deliveryId,1,new A\MailResult('rejected','smtp.temporary',true)));$before=$store->states;Check::same(null,$budget->reserveRejected($delivery,$mail,'owned-relay',$deliveryId,2));Check::same($before,$store->states);
echo 'PASS known rejection budget: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; no quota reset, no original reservation reuse'.PHP_EOL;
