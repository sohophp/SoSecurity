<?php
declare(strict_types=1);
list($feature,$case)=explode('-',substr($mode,strlen('captured-permission-')),2);
$boundary->run('owned.captured.policy.seed',static function()use($pdo,$case):void{$q=$pdo->prepare('INSERT INTO owned_policy_business VALUES (?,?,?,?)');$q->execute(['tenant','policy','fresh-user',$case==='deny'?0:1]);$q->execute(['tenant','owned','fresh-user',1]);});
$before=$inspect();$calls=0;
echo 'CAPTURED_PERMISSION_CONSTRUCTION '.$feature.' '.$case.PHP_EOL;
$service=$feature==='grants'?$sdk->operations($policy):$sdk->signedLinks($policy);
Check::same(0,$capturedEvaluator->selections);Check::same(0,$capturedEvaluator->decisions);Check::same($before,$inspect());
Check::same($capturedPolicy,$sessions->operationSnapshotPolicy($sdk->authorization(),$policy));
$rejectedAuditCalls=0;$rejectedAudit=new SoSecurity\Audit\AuditLogger(static function()use(&$rejectedAuditCalls):void{++$rejectedAuditCalls;},str_repeat('z',32));
$plainPolicy=new class implements SoSecurity\Authorization\PolicyProvider {public function decide(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $fields=[]):?SoSecurity\Authorization\Decision{throw new RuntimeException('PRIVATE-CAPTURED-PLAIN');}};
foreach([
 new SoSecurity\Authorization\Authorizer(clone $provider,$capturedPolicy),
 new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\SnapshotPolicy($capturedEvaluator,clone $sql,hash('sha256','other-source'))),
 new SoSecurity\Authorization\Authorizer($provider,$plainPolicy),
 new SoSecurity\Authorization\Authorizer($provider,$capturedPolicy,$rejectedAudit)
] as $unsupported){
 Check::same(null,$sessions->operationSnapshotPolicy($unsupported,$policy));
 Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($feature,$store,$sessions,$unsupported,$clock,$boundary,$policy,$keys,$service):void{
  if($feature==='grants'){new SoSecurity\Operation\Grants($store,$sessions,$unsupported,static function():bool{return true;},null,$clock,$boundary,$policy);}
  else{new SoSecurity\Link\Links($store,$keys,'fresh-site',$service->policy(),static function():bool{return true;},$clock,$boundary,$policy,$sessions,$unsupported);}
 });
}
Check::same(0,$rejectedAuditCalls);Check::same(0,$capturedEvaluator->selections);Check::same(0,$capturedEvaluator->decisions);Check::same($before,$inspect());
if($case==='construct'){echo 'PASS captured permission factory '.$feature.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;return;}
$tables=['owned_policy_business'=>['columns'=>['scope'=>'bytes:256','id'=>'bytes:64','owner'=>'bytes:256','amount'=>'int'],'primary'=>['scope','id']]];
$resource=new SoSecurity\Authorization\Resource('tenant','record','owned','1',['owner'=>'fresh-user']);
$intent=new SoSecurity\Operation\Intent('records.write',$resource,['amount'=>2],['amount']);$target=new SoSecurity\Link\Target('record',$resource,'/records/owned');
$prepare=static function()use($target){return $target;};
$run=static function()use($feature,$service,&$token,$pdo,$tables,$prepare,$intent){return $feature==='grants'?$service->begin('tenant','fresh-user',$token,$intent):$service->issueFor('tenant','fresh-user',$token,$pdo,$tables,$prepare,true,60);};
if($case==='reentry'){$capturedEvaluator->reenter=$run;}
$rejected=false;$errorReason=null;
try{
 $first=$run();Check::same(true,$feature==='grants'?$first instanceof SoSecurity\Operation\Confirmation:$first instanceof SoSecurity\Link\IssuedLink);
 if($feature==='links'){
  Check::same(1,count($service->allFor('tenant','fresh-user',$token,$pdo,$tables,$prepare)));Check::same(true,$service->revokeFor('tenant','fresh-user',$token,$pdo,$tables,$prepare,$first->id()));
  Check::same(null,$service->verifyFor('tenant',$pdo,$tables,$prepare,$first->url()));
 }else{
  $clock->time+=30;$login=$auth->password('tenant','owned-captured-reauth','fresh@example.test',$password,'',$token);Check::same('mfa_required',$login->status());$login=$auth->secondFactor('tenant','owned-captured-reauth',$login->challenge(),['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($capturedOperationSecret,$clock->time)]);Check::same('authenticated',$login->status());$token=$login->credential()->token();
  $grant=$service->confirm('tenant','fresh-user',$token,$intent,$first->token());Check::same(true,$grant instanceof SoSecurity\Operation\Grant);$before=$inspect();
  $value=$service->execute('tenant','fresh-user',$token,$grant->token(),$pdo,$tables,static function()use($intent){return $intent;},static function(PDO $db)use(&$calls,$case):int{++$calls;$q=$db->prepare('UPDATE owned_policy_business SET amount=2 WHERE scope=? AND id=? AND amount=1');$q->execute(['tenant','owned']);Check::same(1,$q->rowCount());if($case==='changed'){$db->exec("UPDATE owned_policy_business SET amount=0 WHERE id='policy'");}return 17;});Check::same(17,$value);
 }
}catch(SoSecurity\Exception\SecurityException $error){$rejected=true;$errorReason=$error->reason();if(in_array($case,['effect-deny','budget-effect'],true)){Check::same('account.completion_unknown',$errorReason);Check::same($case==='effect-deny'?'authorization.denied':'account.operation_timeout',$error->getPrevious()->reason());}else{Check::same(null,$error->getPrevious());}Check::same(false,strpos((string)$error,'PRIVATE-CAPTURED')!==false);}
if($rejected){Check::same(in_array($case,['effect-deny','budget-effect'],true)?'account.completion_unknown':(strpos($case,'budget-')===0?'account.operation_timeout':(in_array($case,['fault','selectors-fault','reentry'],true)?'authorization.unavailable':'authorization.denied')),$errorReason);}
Check::same(in_array($case,['deny','fields','fault','selectors-fault','reentry','effect-deny','return-deny','changed','budget-before','budget-effect','budget-return'],true),$rejected);
if(in_array($case,['deny','fields','fault','selectors-fault','reentry','budget-before'],true)){Check::same($before,$inspect());Check::same(0,$calls);}
elseif(in_array($case,['effect-deny','budget-effect'],true)){Check::same('pending',$inspect()['status']);Check::same(0,$calls);Check::same($before['digest'],$source->digest());}
else{Check::same('current',$inspect()['status']);Check::same($feature==='grants'&&in_array($case,['normal','changed'],true)?1:0,$calls);}
if($case==='return-deny'){Check::same(false,hash_equals($before['digest'],$source->digest()));}
if($case==='normal'){Check::same(true,$capturedEvaluator->decisions>=3);}
Check::same($feature==='grants'&&in_array($case,['normal','changed'],true)?2:1,(int)$pdo->query("SELECT amount FROM owned_policy_business WHERE id='owned'")->fetchColumn());
echo 'PASS captured native permissions '.$feature.' '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
