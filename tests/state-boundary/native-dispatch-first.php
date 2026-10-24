<?php
declare(strict_types=1);
use SoSecurity\Account as A;
final class OwnedNativeFirstTransport implements A\MailTransport
{
 public $calls=0;public $delivered=0;public $messages=[];public $provider='owned-first-relay';public $before;public $after;public $result;public $failName=false;public $slowName=false;
 public function name():string{if($this->failName){throw new RuntimeException('private-relay-detail');}if($this->slowName){usleep(150000);}return $this->provider;}
 public function send(A\MailMessage $message,int $milliseconds,callable $gate):A\MailResult{++$this->calls;if($this->before!==null){($this->before)();}Check::same(true,$gate());++$this->delivered;$this->messages[]=$message;if($this->after!==null){($this->after)();}return $this->result??new A\MailResult('accepted','smtp.accepted');}
}
if(strpos($argv[4]??'','retry-')===0){require __DIR__.'/native-dispatch-rejected.php';return;}
$mode=$argv[4]??'normal';$mailTransport=new OwnedNativeFirstTransport();$workerAllowed=true;$workerCalls=0;$revokeAtGate=false;$gateReads=0;
$workerGuard=static function(string $action,string $phase)use(&$workerAllowed,&$workerCalls,&$revokeAtGate,&$gateReads,$pdo):bool{++$workerCalls;if($revokeAtGate&&$action==='current_claim'&&$phase==='return'&&++$gateReads===3){$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);}return $workerAllowed;};
$sender=$factor->dispatcher('owned-worker',$good,$templates,$mailTransport,$workerGuard,$mode==='budget'?100:10000,$mode==='budget'?50:3000);
$id=$pdo->query('SELECT message_id FROM sosecurity_outbox_records')->fetchColumn();
$makePermission=static function(string $message)use($sender,&$token):A\StatePermission{return new A\StatePermission('outbox.dispatch','tenant','fresh-user',$sender->initialTarget($message),$token,['mail-worker'],1,300,true,false,['password']);};
$permission=$makePermission($id);$before=$witness->inspect(static function():bool{return true;});$rowsBefore=$pdo->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC);
if($mode!=='budget'){Check::same(['state'=>'idle','code'=>'account.no_notification'],$sender->sendInitialFor($policy,$permission,$id));Check::same(0,$workerCalls);Check::same(0,$mailTransport->calls);Check::same($before,$witness->inspect(static function():bool{return true;}));}
$boundary->run('owned.dispatch.role',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['["mail-worker"]','fresh-user']);});$login=$auth->password('tenant','fresh-dispatch-browser','fresh@example.test',$password);Check::same('authenticated',$login->status());$token=$login->credential()->token();$permission=$makePermission($id);$before=$witness->inspect(static function():bool{return true;});
if($mode==='budget'){
 $mailTransport->slowName=true;try{$sender->sendInitialFor($policy,$permission,$id);throw new RuntimeException('Slow provider identity accepted');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.dispatch_timeout',$error->reason());}
 Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC));Check::same(0,$mailTransport->calls);echo 'PASS native first dispatch admission budget: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if($mode==='normal'){
 $workerAllowed=false;Check::same(['state'=>'idle','code'=>'account.no_notification'],$sender->sendInitialFor($policy,$permission,$id));$workerAllowed=true;
 $wrong=SoSecurity\Outbox\Message::identifier('not-the-approved-message',$clock->time);Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sender,$policy,$permission,$wrong):void{$sender->sendInitialFor($policy,$permission,$wrong);});
 $mailTransport->provider='changed-relay';Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sender,$policy,$permission,$id):void{$sender->sendInitialFor($policy,$permission,$id);});$mailTransport->provider='owned-first-relay';
 $mailTransport->failName=true;try{$sender->sendInitialFor($policy,$permission,$id);throw new RuntimeException('Private transport identity failure accepted');}catch(SoSecurity\Exception\DependencyException $error){Check::same('account.dispatch_transport',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}$mailTransport->failName=false;
 Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records')->fetchAll(PDO::FETCH_ASSOC));Check::same(0,$mailTransport->calls);
 $mailTransport->before=static function()use($sender,$policy,$permission,$id):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sender):void{$sender->sendNext();});Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sender,$policy,$permission,$id):void{$sender->sendInitialFor($policy,$permission,$id);});};
}
if($mode==='revoke-before'){$mailTransport->before=static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);};}
if($mode==='revoke-after'){$mailTransport->after=static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);};}
if($mode==='revoke-gate'){$mailTransport->before=static function()use(&$revokeAtGate):void{$revokeAtGate=true;};}
if($mode==='rejected'){$mailTransport->result=new A\MailResult('rejected','smtp.recipient_refused',false);}
if($mode==='unknown'){$mailTransport->result=new A\MailResult('unknown','smtp.unknown');}
if(in_array($mode,['revoke-before','revoke-after','revoke-gate','unknown'],true)){
 try{$sender->sendInitialFor($policy,$permission,$id);throw new RuntimeException('Uncertain delivery completion reported success');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
 Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);Check::same(in_array($mode,['revoke-after','unknown'],true)?1:0,$mailTransport->delivered);Check::same(1,$mailTransport->calls);if($mode==='revoke-gate'){Check::same(3,$gateReads);}
 echo 'PASS native first dispatch '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; original attempt retained, no continuation'.PHP_EOL;return;
}
$result=$sender->sendInitialFor($policy,$permission,$id);Check::same($mode==='rejected'?['state'=>'rejected','code'=>'smtp.recipient_refused']:['state'=>'submitted','code'=>'smtp.accepted'],$result);Check::same(1,$mailTransport->calls);Check::same(1,$mailTransport->delivered);Check::same($mode==='rejected'?'dead':'sent',$pdo->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same(1,(int)$pdo->query('SELECT attempts FROM sosecurity_outbox_records')->fetchColumn());
$current=$witness->inspect(static function():bool{return true;});Check::same('current',$current['status']);Check::same('outbox.dispatch',$current['intent']['action']);Check::same($source->digest(),$current['digest']);Check::same(false,strpos(json_encode($current),'fresh@example.test')!==false);
if($mode==='normal'){Check::same(['state'=>'idle','code'=>'account.no_notification'],$sender->sendInitialFor($policy,$permission,$id));Check::same(1,$mailTransport->calls);Check::same($current,$witness->inspect(static function():bool{return true;}));}
echo 'PASS native first dispatch '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; one local simulated original delivery'.PHP_EOL;
