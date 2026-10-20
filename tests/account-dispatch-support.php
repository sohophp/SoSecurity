<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/address-change-support.php';
use SoSecurity\Account\MailMessage;use SoSecurity\Account\MailResult;use SoSecurity\Account\MailTransport;use SoSecurity\Account\MailTemplates;use SoSecurity\Account\SendBudgets;use SoSecurity\Account\Dispatcher;
final class TestMailTransport implements MailTransport {
    public $calls=0;public $before;public $after;public $result;public $messages=[];
    public function name():string {return 'owned-relay';}
    public function send(MailMessage $message,int $milliseconds,callable $gate):MailResult {++$this->calls;if($this->before!==null){($this->before)($message);}Check::same(true,$gate());$this->messages[]=$message;if($this->after!==null){($this->after)();}return $this->result ?? new MailResult('accepted','smtp.accepted');}
}
function dispatchTemplates():MailTemplates {$urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}return new MailTemplates('account-test',new SoSecurity\Account\Address('security@example.test'),$urls);}
function dispatchQueue(RegistrationEnvironment $e):SoSecurity\Outbox\SqlOutbox {
    return new SoSecurity\Outbox\SqlOutbox($e->pdo,'account-test',str_repeat('e',64),new SoSecurity\Support\HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),static function():bool{return true;},new SoSecurity\Outbox\Policy(['message_age'=>86400,'recovery_age'=>86400,'maximum_entries'=>1000,'maximum_payload_bytes'=>64,'io_milliseconds'=>10000]),$e->clock,static function():bool{return true;});
}
function dispatcher(RegistrationEnvironment $e,$service,MailTransport $transport):Dispatcher {
    $p=[];foreach(['site','transport','target','subject'] as $name){$p[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}$budgets=new SendBudgets(new SoSecurity\Storage\FileStore($e->directory.'/budgets','dispatch-budget',$e->clock,5000),'account-test',str_repeat('s',32),$p,$e->clock);
    return $service->dispatcher('mail-worker',$budgets,dispatchTemplates(),$transport,static function():bool{return true;},10000,3000);
}
