<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$directory=$argv[1];$mode=$argv[2];if(!is_dir($directory)||is_link($directory)||(fileperms($directory)&0077)!==0||!is_file($directory.'/owned-send-budget-test')){throw new RuntimeException('Use owned private send budget test state.');}
$clock=new TestClock();$policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
$budgets=new SoSecurity\Account\SendBudgets(new SoSecurity\Storage\FileStore($directory.'/state','owned-send-budget',$clock,5000),'site',str_repeat('s',32),$policies,$clock);
$notice=new SoSecurity\Account\Notice('tenant',str_repeat('a',64),'recover_account',new SoSecurity\Account\Address('owned@example.test'),str_repeat('b',64),100000,100900);$delivery=new SoSecurity\Account\DispatchNotice($notice,str_repeat('c',64),'subject');
$urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}$message=(new SoSecurity\Account\MailTemplates('site',new SoSecurity\Account\Address('security@example.test'),$urls))->render($delivery);$id=str_repeat('d',64);
if($mode==='retry'){$result=$budgets->reserve($delivery,$message,'owned',$id,2);echo json_encode(['reserved'=>$result!==null])."\n";exit;}
$until=$budgets->reserve($delivery,$message,'owned',$id,1);if($mode==='race'){echo json_encode(['reserved'=>$until!==null])."\n";exit;}
if($until===null){throw new RuntimeException('Owned crash reservation refused.');}
if(in_array($mode,['started','accepted','unknown'],true)){if(!$budgets->started($delivery,$message,$id,1)){throw new RuntimeException('Owned started transition refused.');}}
if(in_array($mode,['accepted','unknown'],true)){if(!$budgets->settle($delivery,$message,$id,1,new SoSecurity\Account\MailResult($mode,$mode==='accepted'?'smtp.accepted':'smtp.unconfirmed'))){throw new RuntimeException('Owned outcome refused.');}}
file_put_contents($directory.'/ready',$mode);while(true){usleep(10000);}
