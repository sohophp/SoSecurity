<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/recovery-support.php';
if(($argv[1] ?? '')==='mysql'){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
final class MailboxEnvironment {
    public $r;public $e;public $service;public $approved=true;public $onApproval;public $onAuthority;public $onManager;public $onDelivery;public $onBudget;public $phases=[];public $contexts=[];public $requests=[];public $newAddress='rescued@example.com';
    public function __construct(bool $mfa=false,array $options=[]){
        $this->r=new RecoveryEnvironment($mfa,false,$options);$this->e=$this->r->e;$this->service=$this->build();$this->service->initialize();
    }
    public function build(?SoSecurity\Account\Notifications $notices=null,?SoSecurity\Support\HmacKeys $keys=null,string $epoch=''):SoSecurity\Account\MailboxRecovery {
        $e=$this->e;$policies=[];foreach(['site','source','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
        $budgets=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/budgets','mailbox-request',$e->clock,5000),'account-test',str_repeat('p',32),$policies,$e->clock);
        $authority=function(...$args):bool{return $this->onAuthority===null||($this->onAuthority)(...$args)===true;};$manager=function(...$args):bool{return $this->onManager===null||($this->onManager)(...$args)===true;};$delivery=function(...$args):bool{return $this->onDelivery===null||($this->onDelivery)(...$args)===true;};
        $budget=function(...$args)use($budgets):bool{return ($this->onBudget===null||($this->onBudget)(...$args)===true)&&$budgets(...$args);};
        $approval=function(string $phase,SoSecurity\Account\RecoveryApproval $request,array $proof):bool{$this->phases[]=$phase;$this->contexts[]=$request->context();$this->requests[]=$request;return $this->approved&&($this->onApproval===null||($this->onApproval)($phase,$request,$proof)===true);};
        return new SoSecurity\Account\MailboxRecovery($e->pdo,'account-test','tenant',$epoch?:str_repeat('e',64),$keys??new SoSecurity\Support\HmacKeys('mailbox',['mailbox'=>str_repeat('l',32)]),$this->r->queueKeys,$e->accounts,$notices??$this->r->notices,$authority,$budget,$approval,$e->policy,$e->clock,$manager,$delivery,$this->r->factor);
    }
    public function ids():array {$q=$this->e->pdo->prepare('SELECT payload_body FROM sosecurity_outbox_records WHERE namespace=:namespace ORDER BY order_no');$q->execute(['namespace'=>SoSecurity\Outbox\State::namespace('account-test','tenant','account-mailbox-recovery')]);return $q->fetchAll(PDO::FETCH_COLUMN);}
    public function begin():SoSecurity\Account\MailboxRecoveryDelivery {$this->service->request('owner@example.com',$this->newAddress,'owned-source');foreach(array_reverse($this->ids()) as $id){$d=$this->service->notification($id);if($d!==null&&$d->notice()->type()==='recover_address'){return $d;}}throw new RuntimeException('Owned new mailbox challenge missing.');}
    public function confirm(SoSecurity\Account\MailboxRecoveryDelivery $d,?string $token=null):bool {return $this->service->confirm($d->selector(),$token??$d->notice()->token(),'owned-source',['type'=>'approved','code'=>'owned-approval']);}
    public function close():void {$this->service=null;$this->onApproval=null;$this->onAuthority=null;$this->onBudget=null;$this->onDelivery=null;$this->onManager=null;$this->requests=[];$this->r->close();}
}
function mailboxCase(callable $test,bool $mfa=false,array $options=[]):void {$m=new MailboxEnvironment($mfa,$options);try{$test($m);}finally{$m->close();}}
