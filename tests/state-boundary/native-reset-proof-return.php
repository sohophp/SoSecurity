<?php
declare(strict_types=1);
list($entry,$case)=explode('-',substr($mode,strlen('reset-proof-return-')),2);$allowed=true;$fault=false;$calls=0;$guardCalls=0;$budgetArmed=false;
$proofs=new SoSecurity\Password\ResetTokens($store,60,$clock,$boundary,$policy,$sessions,static function()use(&$allowed,&$fault,&$guardCalls,&$budgetArmed,$case):bool{++$guardCalls;if($budgetArmed&&$case==='shared-budget'&&$guardCalls===2){usleep(11000000);}if($fault){throw new RuntimeException('PRIVATE-RESET-PROOF-GUARD');}return $allowed;},'fresh-site');
$boundary->run('owned.reset.proof.seed',static function()use($pdo):void{$pdo->prepare('INSERT INTO owned_policy_business VALUES (?,?,?,?)')->execute(['tenant','owned','fresh-user',1]);});
$proof=$entry==='issue'?null:$proofs->issueFor('tenant','fresh-user');$guardCalls=0;$budgetArmed=true;$before=$inspect();$accountDigest=hash('sha256',json_encode($pdo->query('SELECT * FROM account_example ORDER BY subject')->fetchAll(PDO::FETCH_ASSOC)));
$nativeFinalHook=static function()use(&$allowed,&$fault,$clock,$case):void{if($case==='guard'){$allowed=false;}elseif($case==='fault'){$fault=true;}elseif($case==='expiry'){$clock->time+=61;}elseif($case==='clock'){$clock->fail=true;}};
$rejected=false;
try{
 if($entry==='issue'){$result=$proofs->issueFor('tenant','fresh-user');Check::same(true,is_string($result)&&strlen($result)===64);}
 elseif($entry==='consume'){Check::same(true,$proofs->consumeFor('tenant','fresh-user',$proof));}
 elseif($entry==='revoke'){$proofs->revokeFor('tenant','fresh-user');}
 else{$tables=['owned_policy_business'=>['columns'=>['scope'=>'bytes:256','id'=>'bytes:64','owner'=>'bytes:256','amount'=>'int'],'primary'=>['scope','id']]];$result=$proofs->withConsumption('tenant','fresh-user',$pdo,$tables,$proof,static function(PDO $db)use(&$calls,$case):int{++$calls;if($case==='shared-budget'){usleep(20000000);}$db->exec('UPDATE owned_policy_business SET amount=2');return 2;});Check::same(2,$result);}
}catch(SoSecurity\Exception\SecurityException $error){$rejected=true;Check::same($case==='guard'?'reset.request_denied':($case==='fault'?'reset.request_unavailable':($case==='clock'?'reset.clock':($case==='shared-budget'?'account.operation_timeout':'reset.expired'))),$error->reason());Check::same(null,$error->getPrevious());}
Check::same($case!=='normal',$rejected);Check::same('current',$inspect()['status']);Check::same($before['revision']+1,$inspect()['revision']);Check::same($entry==='execute'?1:0,$calls);Check::same($entry==='execute'?2:1,(int)$pdo->query('SELECT amount FROM owned_policy_business')->fetchColumn());
if($entry!=='issue'&&in_array($case,['normal','guard','fault'],true)){$allowed=true;$fault=false;$stable=$inspect();Check::same(false,$proofs->consumeFor('tenant','fresh-user',$proof));Check::same($stable,$inspect());}
Check::same($accountDigest,hash('sha256',json_encode($pdo->query('SELECT * FROM account_example ORDER BY subject')->fetchAll(PDO::FETCH_ASSOC))));
echo 'PASS native reset proof return '.$entry.' '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
