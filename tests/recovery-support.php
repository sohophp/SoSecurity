<?php
declare(strict_types=1);
require_once __DIR__.'/bootstrap.php';require_once __DIR__.'/address-change-support.php';
if(($argv[1] ?? '')==='mysql'){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
final class RecoveryEnvironment {
    public $t;public $e;public $service;public $factor;public $codes=[];public $onAuthority;public $onBudget;public $onStrong;public $strongCalls=[];public $allowed=true;public $managed=true;public $delivered=true;public $policyCalls=0;public $onPolicy;public $policy;public $notices;public $keys;public $queueKeys;public $budget;
    public $password='Owner replacement password 49!';
    public function __construct(bool $mfa=false,bool $approved=false,array $options=[]) {
        $this->t=new ChangeEnvironment([],$mfa);$this->e=$this->t->e;$e=$this->e;$this->policy=new SoSecurity\Account\Policy($options);
        if($mfa){$e->clock->time=(intdiv($e->clock->time,30)+1)*30;$this->codes=$this->t->factors->regenerateRecoveryCodes('tenant',$this->t->subject,(new SoSecurity\Mfa\Totp())->codeAt($this->t->factorSecret,$e->clock->time));if(!$this->codes){throw new RuntimeException('Owned recovery codes generation failed.');}$this->factor=new SoSecurity\Auth\TotpSecondFactor($this->t->factors);}
        $this->keys=new SoSecurity\Support\HmacKeys('recovery',['recovery'=>str_repeat('r',32)]);$this->queueKeys=new SoSecurity\Support\HmacKeys('outbox',['outbox'=>str_repeat('o',32)]);$this->notices=new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$e->clock);
        $policies=[];foreach(['site','source','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}$formal=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/budgets','recovery-budgets',$e->clock,5000),'account-test',str_repeat('p',32),$policies,$e->clock);
        $this->budget=function(...$args)use($formal):bool{if($this->onBudget!==null&&($this->onBudget)(...$args)!==true){return false;}return $formal(...$args);};
        $this->service=$this->build($approved);$this->service->initialize();
    }
    public function build(bool $approved=false,?SoSecurity\Auth\SecondFactor $factor=null):SoSecurity\Account\Recovery {
        $authority=function(...$args):bool{return $this->allowed&&($this->onAuthority===null||($this->onAuthority)(...$args)===true);};$manager=function():bool{return $this->managed;};$worker=function():bool{return $this->delivered;};
        $strong=$approved?function(string $phase,string $scope,string $subject,string $context,array $proof):bool{$this->strongCalls[]=[$phase,$scope,$subject,$context,$proof];return $this->onStrong!==null&&($this->onStrong)($phase,$scope,$subject,$context,$proof)===true;}:null;
        $passwords=SoSecurity\Password\PasswordPolicy::forHasher($this->e->hasher,15,null,null,function(string $password):bool{++$this->policyCalls;if($this->onPolicy!==null){return ($this->onPolicy)($password);}return false;});
        return new SoSecurity\Account\Recovery($this->e->pdo,'account-test','tenant',str_repeat('e',64),$this->keys,$this->queueKeys,$this->e->accounts,$this->notices,$this->e->hasher,$passwords,$authority,$this->budget,$this->policy,$this->e->clock,$manager,$worker,$factor ?? $this->factor,$strong);
    }
    public function ids():array {$q=$this->e->pdo->prepare('SELECT payload_body FROM sosecurity_outbox_records WHERE namespace=:namespace ORDER BY order_no');$q->execute(['namespace'=>SoSecurity\Outbox\State::namespace('account-test','tenant','account-recovery')]);return $q->fetchAll(PDO::FETCH_COLUMN);}
    public function delivery():SoSecurity\Account\RecoveryDelivery {foreach(array_reverse($this->ids()) as $id){$d=$this->service->notification($id);if($d!==null&&$d->notice()->type()==='recover_account'){return $d;}}throw new RuntimeException('Owned recovery notification not found.');}
    public function begin():SoSecurity\Account\RecoveryDelivery {$this->service->request('owner@example.com','owned-source');return $this->delivery();}
    public function confirm(SoSecurity\Account\RecoveryDelivery $delivery,array $proof=[]):bool {return $this->service->confirm($delivery->selector(),$delivery->notice()->token(),$this->password,'owned-source',$proof);}
    public function flow(string $id):array {return $this->e->flow($id);}
    public function close():void {$this->service=null;$this->budget=null;$this->factor=null;$this->onStrong=null;$this->onAuthority=null;$this->onPolicy=null;$this->onBudget=null;$this->t->close();}
}
function recoveryCase(callable $test,bool $mfa=false,bool $approved=false,array $options=[]):void {$r=new RecoveryEnvironment($mfa,$approved,$options);try{$test($r);}finally{$r->close();}}
