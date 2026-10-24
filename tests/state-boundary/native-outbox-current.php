<?php
declare(strict_types=1);
use SoSecurity\Account as A;
$currentPhase=true;$originalToken=$claim->token();$currentBefore=$witness->inspect(static function():bool{return true;});$rowsBefore=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);
$currentPermission=static function(string $lease,string $role='queue-worker')use($queue,$token):A\StatePermission{return new A\StatePermission('outbox.current_claim','tenant','fresh-user',$queue->currentClaimTarget('tenant','initial','worker',$lease),$token,[$role],1,300,true,false,['password']);};
$readPermission=$currentPermission($originalToken);
$read=static function()use($queue,$policy,$readPermission,$originalToken){return $queue->currentClaimFor($policy,$readPermission,'tenant','initial','worker',$originalToken);};
if($mode==='current-expiry'){
 $claimExpiry=true;Check::same(null,$read());Check::same($currentBefore,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
 echo 'PASS native current claim admission expiry: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if($mode==='current-late-expiry'){
 $claimReturnExpiry=true;try{$read();throw new RuntimeException('Expired lease returned');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
 Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
 echo 'PASS native current claim completion expiry: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
$calls=$claimCalls;Check::same(null,$queue->currentClaimFor($policy,$currentPermission($originalToken,'absent-role'),'tenant','initial','worker',$originalToken));Check::same($calls,$claimCalls);
Check::throws(SoSecurity\Storage\StorageException::class,static function()use($oldQueue,$originalToken):void{$oldQueue->currentClaim('tenant','initial','worker',$originalToken);});
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($queue):void{$queue->currentClaimTarget('tenant','initial','worker','invalid');});
$claimAllowed=false;Check::same(null,$read());$claimAllowed=true;
$claimError=true;try{$read();throw new RuntimeException('Private authority failure accepted');}catch(SoSecurity\Exception\DependencyException $error){Check::same('outbox.authority',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}$claimError=false;
$wrong=substr($originalToken,0,-1).(substr($originalToken,-1)==='0'?'1':'0');
foreach([['tenant','other','worker',$originalToken],['tenant','initial','other',$originalToken],['tenant','initial','worker',$wrong]] as $args){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($queue,$policy,$readPermission,$args){$queue->currentClaimFor($policy,$readPermission,...$args);});}
Check::same(null,$queue->currentClaimFor($policy,$currentPermission($wrong),'tenant','initial','worker',$wrong));Check::same($currentBefore,$witness->inspect(static function():bool{return true;}));Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
$claimNested=static function()use($read):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,$read);};$fresh=$read();Check::same(null,$claimNested);Check::same($claim->message()->fingerprint(),$fresh->message()->fingerprint());Check::same($originalToken,$fresh->token());Check::same($claim->status()->leaseUntil(),$fresh->status()->leaseUntil());Check::same(1,$fresh->status()->attempts());Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
$authority=$witness->inspect(static function():bool{return true;});Check::same('current',$authority['status']);Check::same('outbox.current_claim',$authority['intent']['action']);Check::same(false,strpos(json_encode($authority),$originalToken)!==false);Check::same(false,strpos(json_encode($authority),'private-owned-body')!==false);
$claimLate=true;try{$read();throw new RuntimeException('Post-read role loss returned a lease');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);Check::same($rowsBefore,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
echo 'PASS native current claim: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; no renewal, takeover or delivery'.PHP_EOL;
