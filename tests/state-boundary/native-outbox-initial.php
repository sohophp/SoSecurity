<?php
declare(strict_types=1);
use SoSecurity\Account as A;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Outbox\Message;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
$mode=$argv[4]??'normal';$options=['message_age'=>60,'recovery_age'=>120,'lease_seconds'=>10,'io_milliseconds'=>1000];if($mode==='defaults'||strpos($mode,'current')===0||strpos($mode,'ack')===0||strpos($mode,'reject')===0){unset($options['io_milliseconds']);}$queuePolicy=new SoSecurity\Outbox\Policy($options);$messages=[];if($mode==='defaults'){Check::same(10000,$queuePolicy->ioMilliseconds());}
$oldQueue=new SqlOutbox($pdo,'fresh-site',$epoch,$keys,static function():bool{return true;},$queuePolicy,$clock,static function():bool{return true;});
$boundary->run('fresh.initial.seed',static function()use($oldQueue,$pdo,$clock,&$messages):void{
 $oldQueue->initialize('tenant','initial','admin');$pdo->beginTransaction();try{foreach(['first','blocked','independent'] as $name){$messages[$name]=new Message('tenant','initial',Message::identifier('owned-'.$name,$clock->time),'owned','event',$name==='independent'?'separate':'ordered','private-owned-body-'.$name);$oldQueue->enqueue($messages[$name],'admin');}$pdo->commit();}catch(Throwable $error){if($pdo->inTransaction()){$pdo->rollBack();}throw $error;}
});
$claimAllowed=true;$claimError=false;$claimExpiry=false;$claimBudget=false;$claimLate=false;$claimCalls=0;$claimNested=null;$claimPrewrite=false;$currentPhase=false;$ackPhase=false;$rejectPhase=false;$claimReturnExpiry=false;
$claimGuard=static function(string &$action,string &$phase,string &$scope,string &$producer,string &$worker,array &$metadata)use($pdo,$clock,&$claimAllowed,&$claimError,&$claimExpiry,&$claimBudget,&$claimLate,&$claimCalls,&$claimNested,&$claimPrewrite,&$currentPhase,&$ackPhase,&$rejectPhase,&$claimReturnExpiry):bool{
 if($rejectPhase&&in_array($phase,['admission','admitted'],true)){Check::same('rejected',$metadata['outcome']);Check::same('smtp.recipient_refused',$metadata['error_code']);Check::same(false,$metadata['retryable']);}
 ++$claimCalls;if(in_array($phase,['admission','admitted'],true)){Check::same(false,$pdo->inTransaction());}
 if($claimError){throw new RuntimeException('private-worker-authority');}
 if($phase==='admission'&&$claimNested!==null){$fn=$claimNested;$claimNested=null;$fn();}
 if($phase==='admitted'&&$claimPrewrite){$clock->delayCalls=3;$clock->delayMicroseconds=1100000;}
 if($phase==='admitted'&&$claimExpiry){$clock->time+=60;}
 if($phase==='admission'&&$claimBudget){usleep(1100000);}
 if($phase==='return'&&$claimReturnExpiry){$clock->time+=60;}
 if($phase==='return'&&$claimLate){$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);}
 $allow=$claimAllowed&&$action===($rejectPhase?'fail':($ackPhase?'acknowledge':($currentPhase?'current_claim':'claim_initial')))&&$scope==='tenant'&&$producer==='initial'&&$worker==='worker';$action='mutated';$phase='mutated';$scope='mutated';$producer='mutated';$worker='mutated';$metadata=[];return $allow;
};
$queueConfig=$config;$queueConfig['outbox']=['connection'=>'db','epoch'=>$epoch,'integrity_keys'=>'keys','authority'=>'initial_allow','management_guard'=>'initial_manage','policy'=>$options];
$queueServices=$services+['initial_allow'=>$claimGuard,'initial_manage'=>static function():bool{return true;}];
$queue=SoSecurity\Security::fromArray($queueConfig,$queueServices,$clock)->outbox($accountConnection);
$permissionFor=static function(string $id)use($queue,&$token):A\StatePermission{return new A\StatePermission('outbox.claim_initial','tenant','fresh-user',$queue->initialClaimTarget('tenant','initial','worker',$id),$token,['queue-worker'],1,300,true,false,['password']);};
$id=$messages['first']->id();$permission=$permissionFor($id);$before=$witness->inspect(static function():bool{return true;});Check::same(null,$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id));Check::same(0,$claimCalls);Check::same($before,$witness->inspect(static function():bool{return true;}));
Check::throws(StorageException::class,static function()use($oldQueue,$id):void{$oldQueue->claimInitialMessage('tenant','initial','worker',$id);});
$boundary->run('fresh.initial.roles',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=?')->execute(['["queue-worker"]']);});
$login=$auth->password('tenant','fresh-initial-browser','fresh@example.test',$password);Check::same('authenticated',$login->status());$token=$login->credential()->token();$permission=$permissionFor($id);
$before=$witness->inspect(static function():bool{return true;});$rowsBefore=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);
if($mode==='expiry'||$mode==='budget'||$mode==='prewrite'){
 $claimExpiry=$mode==='expiry';$claimBudget=$mode==='budget';$claimPrewrite=$mode==='prewrite';
 if($mode==='expiry'){Check::same(null,$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id));}
 else{try{$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id);throw new RuntimeException('Worker budget overrun accepted');}catch(StorageException $error){Check::same($mode==='prewrite'?'account.operation_timeout':'outbox.timeout',$error->reason());}}
 Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
 echo 'PASS native initial claim '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
$claimAllowed=false;Check::same(null,$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id));Check::same($before,$witness->inspect(static function():bool{return true;}));$claimAllowed=true;
$claimError=true;try{$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id);throw new RuntimeException('Worker exception accepted');}catch(SoSecurity\Exception\DependencyException $error){Check::same('outbox.authority',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}$claimError=false;Check::same($before,$witness->inspect(static function():bool{return true;}));
foreach([['tenant','other','worker',$id],['tenant','initial','other',$id],['tenant','initial','worker',$messages['independent']->id()]] as $args){Check::throws(ConfigurationException::class,static function()use($queue,$policy,$permission,$args){$queue->claimInitialFor($policy,$permission,...$args);});Check::same($before,$witness->inspect(static function():bool{return true;}));}
$blocked=$messages['blocked']->id();Check::same(null,$queue->claimInitialFor($policy,$permissionFor($blocked),'tenant','initial','worker',$blocked));Check::same($before,$witness->inspect(static function():bool{return true;}));
$missing=Message::identifier('missing',$clock->time);Check::same(null,$queue->claimInitialFor($policy,$permissionFor($missing),'tenant','initial','worker',$missing));Check::same($before,$witness->inspect(static function():bool{return true;}));
$claimNested=static function()use($queue,$policy,$permission,$id):void{Check::throws(ConfigurationException::class,static function()use($queue,$policy,$permission,$id){$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id);});};
$claim=$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id);Check::same(null,$claimNested);Check::same($id,$claim->message()->id());Check::same('private-owned-body-first',$claim->message()->body());Check::same(1,$claim->status()->attempts());
$current=$witness->inspect(static function():bool{return true;});Check::same('current',$current['status']);Check::same('outbox.claim_initial',$current['intent']['action']);Check::same(false,strpos(json_encode($current),$claim->token())!==false);Check::same(false,strpos(json_encode($current),'private-owned-body')!==false);
$leased=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);Check::same(null,$queue->claimInitialFor($policy,$permission,'tenant','initial','worker',$id));Check::same($current,$witness->inspect(static function():bool{return true;}));Check::same($leased,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
if(strpos($mode,'reject')===0){require __DIR__.'/native-outbox-reject.php';return;}
if(strpos($mode,'ack')===0){require __DIR__.'/native-outbox-ack.php';return;}
if(strpos($mode,'current')===0){require __DIR__.'/native-outbox-current.php';return;}
// Only a different never-attempted message is selected. No reclaim of the first lease.
$next=$messages['independent']->id();$claimLate=true;try{$queue->claimInitialFor($policy,$permissionFor($next),'tenant','initial','worker',$next);throw new RuntimeException('Post-claim role loss returned a token');}catch(StorageException $error){Check::same('account.completion_unknown',$error->reason());}Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);
echo 'PASS native initial outbox claim: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').'; first attempts only, no delivery or continuation'.PHP_EOL;
