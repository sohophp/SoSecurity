<?php
declare(strict_types=1);
use SoSecurity\Authorization as Z;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
Check::same(0,$customState->calls);Check::same(true,$customPolicy->matches($policy));
$foreignPolicy=new Z\SnapshotPolicy($customProvider,new SoSecurity\Account\SqlStateSnapshot($pdo,'fresh-auth-sql',$definitions,30000),hash('sha256','owned-custom-policy-v1'));
Check::same(false,$foreignPolicy->matches($policy));Check::same(null,(new Z\Authorizer($provider,$foreignPolicy))->stateSnapshotPolicy($provider,$policy));
 $rawProvider=new class implements Z\PolicyProvider{public function decide(SoSecurity\Auth\Account $actor,string $action,Z\Resource $resource,array $requestedFields=[]):?Z\Decision{return null;}};Check::same(null,(new Z\Authorizer($provider,$rawProvider))->stateSnapshotPolicy($provider,$policy));
Check::same(false,$customPolicy->fingerprint()===(new Z\SnapshotPolicy($customProvider,$sql,hash('sha256','changed-config')))->fingerprint());
Check::throws(\TypeError::class,static function()use($customPolicy,$sql):void{new Z\SnapshotPolicy($customPolicy,$sql,str_repeat('a',64));});
Check::throws(ConfigurationException::class,static function()use($customPolicy):void{serialize($customPolicy);});
foreach([$rawProvider,$foreignPolicy] as $unsupported){
 $authorizer=new Z\Authorizer($provider,$unsupported);
 Check::throws(ConfigurationException::class,static function()use($store,$sessions,$provider,$keys,$auditGuard,$services,$clock,$sdk,$authorizer,$boundary,$policy):void{new SoSecurity\Api\CredentialRegistry($store,$sessions,$provider,$keys,'fresh-site',$auditGuard,$services['api_audit_scopes'],new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['records:read','records:write']]),$clock,$sdk->managedSecondFactor(),$authorizer,$services['api_audit_actor'],$boundary,$policy);});
}
Check::same(0,$customState->calls);
if($mode==='custom-data-denied'){$boundary->run('owned.custom.policy.data',static function()use($pdo):void{$pdo->exec("UPDATE account_example SET roles='[\"blocked\"]' WHERE subject='audit-owner'");});}
if($mode==='custom-selector-write'){$customState->selectorWrite=static function()use($pdo):void{$pdo->exec("UPDATE account_example SET roles='[\"unexpected\"]' WHERE subject='audit-owner'");};}
if($mode==='custom-selector-invalid'){
 $before=$inspect();Check::throws(ConfigurationException::class,static function()use($api,$token):void{$api->issue('tenant','audit-owner',$token,'Invalid selector',['records:read']);});Check::same(0,$customState->calls);Check::same($before,$inspect());Check::same(0,$count());echo 'PASS captured policy invalid selector '.Check::$assertions.PHP_EOL;return;
}
$before=$inspect();
if($mode==='custom-before-fault'){$customState->failAt=3;}
if($mode==='custom-return-fault'){$nativeFinalHook=static function()use($customState):void{$customState->fail=true;};}
if(in_array($mode,['custom-denied','custom-denied-plain'],true)){$customState->allowed=false;}
if($mode==='custom-reentry'){$customState->write=static function()use($api,$token):void{$api->all('tenant','audit-owner',$token);};}
if($mode==='custom-fault'){$customState->fail=true;}
if($mode==='custom-write'){$customState->write=static function()use($pdo):void{$pdo->exec("UPDATE account_example SET roles='[\"unexpected\"]' WHERE subject='audit-owner'");};}
if(in_array($mode,['custom-return','custom-return-plain'],true)){$nativeFinalHook=static function()use($customState):void{$customState->allowed=false;};}
if(in_array($mode,['custom-selector-write','custom-selector-fault','custom-data-denied','custom-denied','custom-denied-plain','custom-fault','custom-before-fault','custom-return-fault','custom-reentry','custom-write','custom-return','custom-return-plain'],true)){
 try{$api->issue('tenant','audit-owner',$token,'Declared policy refusal',['records:read']);throw new RuntimeException('Expected declared policy refusal');}catch(SecurityException $error){
  $expected=$mode==='custom-before-fault'?'account.completion_unknown':(in_array($mode,['custom-selector-fault','custom-fault','custom-return-fault','custom-reentry'],true)?'authorization.unavailable':(in_array($mode,['custom-write','custom-selector-write'],true)?'account.witness_stale':'authorization.denied'));Check::same($expected,$error->reason());if($mode==='custom-before-fault'){$cause=$error->getPrevious();Check::same(true,$cause instanceof SoSecurity\Exception\DependencyException);Check::same('authorization.unavailable',$cause->reason());Check::same(null,$cause->getPrevious());Check::same(false,strpos($cause->getMessage(),'PRIVATE')!==false);}else{Check::same(null,$error->getPrevious());}Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);
 }
 Check::same($customAudit&&in_array($mode,['custom-data-denied','custom-denied','custom-return','custom-return-fault'],true)?1:0,$count());Check::same($mode==='custom-before-fault'?'pending':'current',$inspect()['status']);
 if(in_array($mode,['custom-selector-write','custom-selector-fault','custom-denied-plain','custom-fault','custom-reentry','custom-write'],true)){Check::same($before,$inspect());}
 if($mode==='custom-write'){Check::same('["unexpected"]',$pdo->query("SELECT roles FROM account_example WHERE subject='audit-owner'")->fetchColumn());}
}else{
 $key=$api->issue('tenant','audit-owner',$token,'Declared policy',['records:read']);Check::same(1,count($api->all('tenant','audit-owner',$token)));
 $key=$api->rotate('tenant','audit-owner',$token,$key->metadata()->id(),1);Check::same(2,$key->metadata()->generation());
 $key=$api->replace('tenant','audit-owner',$token,$key->metadata()->id(),2,'Changed',['records:write']);Check::same(3,$key->metadata()->generation());
 Check::same(true,$api->revoke('tenant','audit-owner',$token,$key->metadata()->id()));Check::same(0,$api->revokeAll('tenant','audit-owner',$token));
 Check::same($customAudit?6:0,$count());Check::same(true,$customState->calls>=24);Check::same('current',$inspect()['status']);
 $phases=[];foreach($auditCalls as $call){if($call[0]===($customAudit?'audit_current':'management_current')){$phases[]=$call[1];}}foreach(['admission','before','return'] as $phase){Check::same(true,in_array($phase,$phases,true));}
}
if(in_array($mode,['custom-before-fault','custom-return-fault'],true)){echo 'POLICY_FAULT_STATE '.json_encode(['mode'=>$mode,'witness'=>$inspect()['status'],'audit_rows'=>$count()]).PHP_EOL;}
echo 'PASS native declared policy '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
