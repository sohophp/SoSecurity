<?php
declare(strict_types=1);
use SoSecurity\Authorization as Z;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
$case=substr($mode,strlen('policy-business-'));
$credential=$api->issue('tenant','fresh-user',$token,'Owned captured business',['records:write']);
$boundary->run('owned.policy.business.seed',static function()use($pdo,$case):void{$pdo->prepare('INSERT INTO owned_policy_business VALUES (?,?,?,?)')->execute(['tenant','owned',$case==='denied'?'other':'fresh-user',1]);});
$state=(object)['calls'=>0,'failAt'=>$case==='before-fault'?2:($case==='return-fault'?3:0),'fields'=>$case!=='fields','hook'=>null];
$evaluator=new class($state) implements Z\SnapshotEvaluator{
 private $state;public function __construct($state){$this->state=$state;}
 public function selectors(SoSecurity\Auth\Account $actor,string $action,Z\Resource $resource,array $requestedFields):array{return ['object'=>['table'=>'owned_policy_business','key'=>['scope'=>$resource->scope(),'id'=>$resource->id()],'columns'=>['owner','amount']]];}
 public function decide(SoSecurity\Auth\Account $actor,string $action,Z\Resource $resource,array $requestedFields,array $facts):?Z\Decision{
  ++$this->state->calls;if($this->state->calls===$this->state->failAt){throw new RuntimeException('PRIVATE-BUSINESS-POLICY');}
  if($this->state->hook!==null){$hook=$this->state->hook;$this->state->hook=null;$hook();}
  return $action==='records.write'&&in_array('operator',$actor->roles(),true)&&isset($facts['object'])&&$facts['object']['owner']===$actor->subject()?Z\Decision::allow($this->state->fields?['amount']:[]):Z\Decision::deny();
 }
};
$declared=new Z\SnapshotPolicy($evaluator,$sql,hash('sha256','owned-captured-business-v1'));
$tables=['owned_policy_business'=>['columns'=>['scope'=>'bytes:256','id'=>'bytes:64','owner'=>'bytes:256','amount'=>'int'],'primary'=>['scope','id']]];
$prepare=static function(PDO $db,SoSecurity\Api\VerifiedCredential $proof):SoSecurity\Operation\Intent{return new SoSecurity\Operation\Intent('records.write',new Z\Resource('tenant','record','owned','1',['owner'=>'fresh-user']),['amount'=>2],['amount']);};
$calls=0;$work=static function(PDO $db)use(&$calls,$case):int{++$calls;$db->prepare('UPDATE owned_policy_business SET amount=2,owner=? WHERE scope=? AND id=?')->execute([$case==='return-denied'?'other':'fresh-user','tenant','owned']);return 2;};
$before=$inspect();
if($case==='foreign'){
 $foreign=new Z\SnapshotPolicy($evaluator,new SoSecurity\Account\SqlStateSnapshot($pdo,'fresh-auth-sql',$definitions,30000),hash('sha256','owned-captured-business-v1'));
 Check::throws(ConfigurationException::class,static function()use($api,$credential,$pdo,$tables,$foreign,$prepare,$work):void{$api->withSnapshotAuthorization('tenant','Bearer '.$credential->token(),'records:write',$pdo,$tables,$foreign,$prepare,$work);});Check::same(0,$state->calls);Check::same(0,$calls);Check::same($before,$inspect());
}else{
 $rejected=false;
 try{$result=$api->withSnapshotAuthorization('tenant','Bearer '.$credential->token(),'records:write',$pdo,$tables,$declared,$prepare,$work);Check::same(2,$result);}
 catch(SecurityException $error){$rejected=true;Check::same($case==='before-fault'?'account.completion_unknown':($case==='return-fault'?'authorization.unavailable':'authorization.denied'),$error->reason());if($case==='before-fault'){Check::same('authorization.unavailable',$error->getPrevious()->reason());Check::same(null,$error->getPrevious()->getPrevious());}else{Check::same(null,$error->getPrevious());}Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}
 Check::same($case!=='normal',$rejected);$early=in_array($case,['denied','fields','before-fault'],true);Check::same($early?0:1,$calls);Check::same($early?1:2,(int)$pdo->query('SELECT amount FROM owned_policy_business')->fetchColumn());Check::same($case==='before-fault'?'pending':'current',$inspect()['status']);
 if(in_array($case,['denied','fields'],true)){Check::same($before,$inspect());}
 if($case==='normal'){Check::same(3,$state->calls);Check::same($before['revision']+1,$inspect()['revision']);}
}
Check::same(0,$count());
echo 'PASS native captured business '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
