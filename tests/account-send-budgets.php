<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\Address;
use SoSecurity\Account\Notice;
use SoSecurity\Account\DispatchNotice;
use SoSecurity\Account\MailTemplates;
use SoSecurity\Account\MailMessage;
use SoSecurity\Account\MailResult;
use SoSecurity\Account\SendBudgets;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ConfigurationException;
final class MailBudgetStore implements AtomicStore {
    public $store;public $calls=0;public $retry=false;public $states=[];public $after;public $mutate;
    public function __construct(TestClock $clock){$this->store=new MemoryStore($clock);}
    public function transact(string $key,callable $callback){++$this->calls;$result=$this->store->transact($key,function($state)use($key,$callback):Change{if($this->mutate!==null){$state=($this->mutate)($key,$state);}$change=$callback($state);if($this->retry){$again=$callback($state);Check::same($change->value(),$again->value());Check::same($change->expiresAt(),$again->expiresAt());Check::same(true,$change->result()==$again->result());}$this->states[$key]=$change->value();return $change;});if($this->after!==null){($this->after)($key);}return $result;}
    public function eraseNotice():void {foreach(array_keys($this->states) as $key){if(strpos($key,'account-send-notice:')===0){$this->store->transact($key,static function():Change{return new Change(null,0,null);});}}}
}
function sendPolicies(array $limits=[]):array {$policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new BudgetPolicy('fixed_window',$limits[$name] ?? 1000,60);}return $policies;}
function mailTemplates():MailTemplates {$urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $name){$urls[$name]='https://account.example.test/'.$name;}return new MailTemplates('site',new Address('security@example.test'),$urls,'Private site','zh-CN');}
function sendFixture(array $limits=[],int $maximum=3):array {$clock=new TestClock();$store=new MailBudgetStore($clock);return [$clock,$store,new SendBudgets($store,'site',str_repeat('s',32),sendPolicies($limits),$clock,$maximum)];}
function dispatchValue(int $id=1,string $recipient='owner@example.test',string $subject='private-account-subject',string $scope='tenant'):DispatchNotice {return new DispatchNotice(new Notice($scope,str_pad(dechex($id),64,'0',STR_PAD_LEFT),'recover_account',new Address($recipient),str_repeat('b',64),100000,100900),str_repeat('c',64),$subject);}
function reserveSend(SendBudgets $budget,DispatchNotice $notice,int $attempt=1,string $provider='relay'):?int {return $budget->reserve($notice,mailTemplates()->render($notice),$provider,str_repeat('d',64),$attempt);}
list($clock,$store,$budget)=sendFixture();Check::same(0,$store->calls);$delivery=dispatchValue();$mail=mailTemplates()->render($delivery);Check::same(100060,reserveSend($budget,$delivery));Check::same(null,reserveSend($budget,$delivery));Check::same(true,$budget->started($delivery,$mail,str_repeat('d',64),1));Check::same(false,$budget->started($delivery,$mail,str_repeat('d',64),1));Check::same(true,$budget->settle($delivery,$mail,str_repeat('d',64),1,new MailResult('accepted','smtp.accepted')));Check::same(null,reserveSend($budget,$delivery,2));
$factorNotice=new Notice('tenant',str_repeat('a',64),'factor_privileged_revoked',new Address('owner@example.test'),'',100000,100900);$factorDelivery=new DispatchNotice($factorNotice,'','private-account-subject');$factorMail=mailTemplates()->render($factorDelivery);Check::same(true,strpos($factorMail->wire(),'Factor privileged revoked')!==false);Check::same(false,strpos($factorMail->wire(),'https://account.example.test/')!==false);list($clock,$store,$budget)=sendFixture(['target'=>1]);Check::same(true,$budget->reserve($factorDelivery,$factorMail,'relay',str_repeat('d',64),1)!==null);Check::same(null,$budget->reserve($factorDelivery,$factorMail,'relay',str_repeat('d',64),2));
$migrationNotice=new Notice('tenant',str_repeat('b',64),'factor_migration_reapproved',new Address('owner@example.test'),'',100000,100900);
$migrationMail=mailTemplates()->render(new DispatchNotice($migrationNotice,'','private-account-subject'));
Check::same(true,strpos($migrationMail->wire(),'Factor migration reapproved')!==false);Check::same(false,strpos($migrationMail->wire(),'https://account.example.test/')!==false);
foreach(['started','unknown','accepted'] as $phase){list($clock,$store,$budget)=sendFixture();$n=dispatchValue();$m=mailTemplates()->render($n);reserveSend($budget,$n);$budget->started($n,$m,str_repeat('d',64),1);if($phase!=='started'){$budget->settle($n,$m,str_repeat('d',64),1,new MailResult($phase,$phase==='accepted'?'smtp.accepted':'smtp.unconfirmed'));}Check::same(null,reserveSend($budget,$n,2,'other-provider'));$clock->time+=61;Check::same(null,reserveSend($budget,$n,3));}
list($clock,$store,$budget)=sendFixture([],2);$n=dispatchValue();$m=mailTemplates()->render($n);foreach([1,2] as $attempt){Check::same(true,reserveSend($budget,$n,$attempt)!==null);Check::same(true,$budget->started($n,$m,str_repeat('d',64),$attempt));Check::same(true,$budget->settle($n,$m,str_repeat('d',64),$attempt,new MailResult('rejected','smtp.temporary',true)));}Check::same(null,reserveSend($budget,$n,3));
// A prepared record survives global refusal, but a missing prior record never becomes a fresh retry allowance.
list($clock,$store,$budget)=sendFixture(['site'=>1]);Check::same(true,reserveSend($budget,dispatchValue())!==null);Check::same(null,reserveSend($budget,dispatchValue(2)));$clock->time+=60;Check::same(true,reserveSend($budget,dispatchValue(2),2)!==null);
list($clock,$store,$budget)=sendFixture();Check::throws(StorageException::class,static function()use($budget):void{reserveSend($budget,dispatchValue(),2);});reserveSend($budget,dispatchValue());$store->eraseNotice();Check::throws(StorageException::class,static function()use($budget):void{reserveSend($budget,dispatchValue(),2);});
foreach(['target','subject','transport','site'] as $dimension){list($clock,$store,$budget)=sendFixture([$dimension=>1]);Check::same(true,reserveSend($budget,dispatchValue())!==null);Check::same(null,reserveSend($budget,dispatchValue(2)));}
list($clock,$store,$budget)=sendFixture(['target'=>1]);reserveSend($budget,dispatchValue());Check::same(null,reserveSend($budget,dispatchValue(2,'owner@example.test','other','other-scope')));
list($clock,$store,$budget)=sendFixture(['subject'=>1]);reserveSend($budget,dispatchValue());Check::same(true,reserveSend($budget,dispatchValue(2,'owner@example.test','private-account-subject','other-scope'))!==null);
list($clock,$store,$budget)=sendFixture();reserveSend($budget,$delivery);$changed=new MailMessage(new Address('other@example.test'),$mail->recipient(),$mail->messageId(),'Changed subject','Changed body',100000);Check::throws(StorageException::class,static function()use($budget,$delivery,$changed):void{$budget->reserve($delivery,$changed,'relay',str_repeat('d',64),2);});
foreach(['used','phase','seal'] as $field){list($clock,$store,$budget)=sendFixture();reserveSend($budget,$delivery);$store->mutate=static function(string $key,$state)use($field){if(strpos($key,'account-send-notice:')===0&&is_array($state)){$state[$field]=$field==='used'?0:($field==='phase'?'accepted':str_repeat('0',64));}return $state;};Check::throws(StorageException::class,static function()use($budget,$delivery):void{reserveSend($budget,$delivery,2);});}
list($clock,$store,$budget)=sendFixture();$store->retry=true;reserveSend($budget,$delivery);Check::same(true,$budget->started($delivery,$mail,str_repeat('d',64),1));Check::same(true,$budget->settle($delivery,$mail,str_repeat('d',64),1,new MailResult('unknown','smtp.unconfirmed')));
list($clock,$store,$budget)=sendFixture();reserveSend($budget,$delivery);$other=new SendBudgets($store,'site',str_repeat('z',32),sendPolicies(),$clock);Check::throws(StorageException::class,static function()use($other,$delivery):void{reserveSend($other,$delivery,2);});
list($clock,$store,$budget)=sendFixture();reserveSend($budget,$delivery);--$clock->time;Check::throws(StorageException::class,static function()use($budget,$delivery):void{reserveSend($budget,$delivery,2);});
list($clock,$store,$budget)=sendFixture();$store->after=static function()use($clock):void{$clock->time+=60;};Check::same(null,reserveSend($budget,$delivery));Check::same(1,$store->calls);
list($clock,$store,$budget)=sendFixture();reserveSend($budget,$delivery);foreach(['owner@example.test','private-account-subject',str_repeat('s',32),str_repeat('b',64)] as $secret){Check::same(false,strpos(json_encode($store->states),$secret)!==false);Check::same(false,strpos(var_export($budget,true),$secret)!==false);Check::same(false,strpos(var_export($mail,true),$secret)!==false);}Check::same('{}',json_encode($mail));Check::throws(ConfigurationException::class,static function()use($budget):void{serialize($budget);});Check::throws(ConfigurationException::class,static function()use($mail):void{serialize($mail);});
Check::same($mail->messageId(),mailTemplates()->render($delivery)->messageId());Check::same($mail->wire(),mailTemplates()->render($delivery)->wire());Check::same(false,strpos($mail->wire(),'Bcc:')!==false);
echo 'PASS isolated mail budgets/templates: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; shared quotas, signed per-notice lifecycle, no refund/reset, unknown/accepted quarantine, privacy and immutable wire\n";
