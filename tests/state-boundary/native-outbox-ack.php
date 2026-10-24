<?php
declare(strict_types=1);
use SoSecurity\Account as A;
$ackPhase=true;$originalToken=$claim->token();$beforeAck=$witness->inspect(static function():bool{return true;});$rowsBefore=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);
$permissionAck=static function(string $lease,string $role='queue-worker')use($queue,$token):A\StatePermission{return new A\StatePermission('outbox.acknowledge','tenant','fresh-user',$queue->acknowledgeTarget('tenant','initial','worker',$lease),$token,[$role],1,300,true,false,['password']);};
$ackPermission=$permissionAck($originalToken);$ack=static function()use($queue,$policy,$ackPermission,$originalToken):bool{return $queue->acknowledgeFor($policy,$ackPermission,'tenant','initial','worker',$originalToken);};
if($mode==='ack-expiry'){
 $claimExpiry=true;Check::same(false,$ack());Check::same($beforeAck,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
 echo 'PASS native acknowledgement admission expiry: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if($mode==='ack-late-role'||$mode==='ack-late-expiry'){
 $claimLate=$mode==='ack-late-role';$claimReturnExpiry=$mode==='ack-late-expiry';
 try{$ack();throw new RuntimeException('Uncertain completion reported success');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
 Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);$rows=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);Check::same('sent',$rows[0]['status']);Check::same(0,(int)$rows[0]['payload_present']);Check::same('',(string)$rows[0]['payload_body']);Check::same(1,(int)$rows[0]['attempts']);Check::same(0,(int)$rows[0]['lease_until']);Check::same($rowsBefore[1],$rows[1]);Check::same($rowsBefore[2],$rows[2]);
 echo 'PASS native acknowledgement '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; committed state retained, no continuation'.PHP_EOL;return;
}
$calls=$claimCalls;Check::same(false,$queue->acknowledgeFor($policy,$permissionAck($originalToken,'absent-role'),'tenant','initial','worker',$originalToken));Check::same($calls,$claimCalls);
Check::throws(SoSecurity\Storage\StorageException::class,static function()use($oldQueue,$originalToken):void{$oldQueue->acknowledge('tenant','initial','worker',$originalToken);});
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($queue):void{$queue->acknowledgeTarget('tenant','initial','worker','invalid');});
$claimAllowed=false;Check::same(false,$ack());$claimAllowed=true;$claimError=true;
try{$ack();throw new RuntimeException('Private authority failure accepted');}catch(SoSecurity\Exception\DependencyException $error){Check::same('outbox.authority',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}$claimError=false;
$wrong=substr($originalToken,0,-1).(substr($originalToken,-1)==='0'?'1':'0');
foreach([['tenant','other','worker',$originalToken],['tenant','initial','other',$originalToken],['tenant','initial','worker',$wrong]] as $args){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($queue,$policy,$ackPermission,$args){$queue->acknowledgeFor($policy,$ackPermission,...$args);});}
Check::same(false,$queue->acknowledgeFor($policy,$permissionAck($wrong),'tenant','initial','worker',$wrong));Check::same($beforeAck,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
$claimNested=static function()use($ack):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,$ack);};Check::same(true,$ack());Check::same(null,$claimNested);
$rows=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);Check::same('sent',$rows[0]['status']);Check::same(0,(int)$rows[0]['payload_present']);Check::same('',(string)$rows[0]['payload_body']);Check::same(1,(int)$rows[0]['attempts']);Check::same(1,(int)$rows[0]['generation']);Check::same(0,(int)$rows[0]['lease_until']);Check::same($clock->time,(int)$rows[0]['sent_at']);Check::same($rowsBefore[1],$rows[1]);Check::same($rowsBefore[2],$rows[2]);
$current=$witness->inspect(static function():bool{return true;});Check::same('current',$current['status']);Check::same('outbox.acknowledge',$current['intent']['action']);Check::same(false,strpos(json_encode($current),$originalToken)!==false);Check::same(false,strpos(json_encode($current),'private-owned-body')!==false);
// Only inspect the already-confirmed result: no new attempt or unknown receipt is resumed.
Check::same(false,$ack());Check::same($current,$witness->inspect(static function():bool{return true;}));Check::same($rows,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
echo 'PASS native known-success acknowledgement: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; no transport, takeover or continuation'.PHP_EOL;
