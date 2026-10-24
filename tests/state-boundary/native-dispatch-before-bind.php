<?php
declare(strict_types=1);
use SoSecurity\Account as A;
Check::same(false,SoSecurity\Support\SqlStateAccess::isProtected($pdo));
$oldAllow=static function():bool{return true;};$oldSource=new A\Registration($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$hasher,SoSecurity\Password\PasswordPolicy::forHasher($hasher),$oldAllow,$oldAllow,new A\Policy(),$clock,$oldAllow,$oldAllow);
$oldPolicies=[];foreach(['site','transport','target','subject'] as $dimension){$oldPolicies[$dimension]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
$oldBudgets=new A\SendBudgets(new SoSecurity\Storage\FileStore($directory.'/budget','old-send',$clock),'fresh-site',str_repeat('b',32),$oldPolicies,$clock);
$oldUrls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $action){$oldUrls[$action]='https://owned.example/'.$action;}
$oldTemplates=new A\MailTemplates('fresh-site',new A\Address('security@owned.example'),$oldUrls);
$oldTransport=new class implements A\MailTransport {
 public function name():string{throw new RuntimeException('Late-bound dispatcher must refuse before transport lookup');}
 public function send(A\MailMessage $message,int $milliseconds,callable $gate):A\MailResult{throw new RuntimeException('No transport may execute');}
};
$oldBudgetDispatcher=$oldSource->dispatcher('owned-worker',$oldBudgets,$oldTemplates,$oldTransport,$oldAllow);
