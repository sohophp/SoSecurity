<?php
declare(strict_types=1);
$parts=explode('-',substr($mode,strlen('operation-return-')),2);$entry=count($parts)===2?$parts[0]:'begin';$case=count($parts)===2?$parts[1]:$parts[0];$allowed=true;$guardFault=false;
$operationPolicy=new SoSecurity\Authorization\RolePolicy(['records.write'=>['type'=>'record','roles'=>['operator'],'fields'=>['amount']]]);
$operationAuthorizer=new SoSecurity\Authorization\Authorizer($provider,$operationPolicy);
$operation=new SoSecurity\Operation\Grants($store,$sessions,$operationAuthorizer,static function()use(&$allowed,&$guardFault):bool{if($guardFault){throw new RuntimeException('PRIVATE-OPERATION-GUARD');}return $allowed;},null,$clock,$boundary,$policy);
$intent=new SoSecurity\Operation\Intent('records.write',new SoSecurity\Authorization\Resource('tenant','record','owned','1'),['amount'=>2],['amount']);
$boundary->run('owned.operation.seed',static function()use($pdo):void{$pdo->prepare('INSERT INTO owned_policy_business VALUES (?,?,?,?)')->execute(['tenant','owned','fresh-user',1]);});
$confirmation=null;$grant=null;
if($entry!=='begin'){
 $confirmation=$operation->begin('tenant','fresh-user',$token,$intent);$clock->time+=30;
 $login=$auth->password('tenant','owned-operation-reauth','fresh@example.test',$password,'',$token);Check::same('mfa_required',$login->status());$login=$auth->secondFactor('tenant','owned-operation-reauth',$login->challenge(),['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($operationSecret,$clock->time)]);Check::same('authenticated',$login->status());$token=$login->credential()->token();
 if($entry!=='confirm'){$grant=$operation->confirm('tenant','fresh-user',$token,$intent,$confirmation->token());Check::same(true,$grant instanceof SoSecurity\Operation\Grant);}
}
unset($operationSecret);$before=$inspect();$calls=0;
$nativeFinalHook=static function()use(&$allowed,&$guardFault,$clock,$case,$pdo):void{if($case==='guard'){$allowed=false;}elseif($case==='fault'){$guardFault=true;}elseif($case==='expiry'){$clock->time+=121;}elseif($case==='source-change'){$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['["member"]','fresh-user']);}};
$rejected=false;
try{
 if($entry==='begin'){$result=$operation->begin('tenant','fresh-user',$token,$intent);Check::same(true,$result instanceof SoSecurity\Operation\Confirmation);}
 elseif($entry==='confirm'){$result=$operation->confirm('tenant','fresh-user',$token,$intent,$confirmation->token());Check::same(true,$result instanceof SoSecurity\Operation\Grant);}
 elseif($entry==='consume'){$result=$operation->consume('tenant','fresh-user',$token,$intent,$grant->token());Check::same(true,$result instanceof SoSecurity\Operation\Permit);}
 else{$tables=['owned_policy_business'=>['columns'=>['scope'=>'bytes:256','id'=>'bytes:64','owner'=>'bytes:256','amount'=>'int'],'primary'=>['scope','id']]];$result=$operation->execute('tenant','fresh-user',$token,$grant->token(),$pdo,$tables,static function()use($intent){return $intent;},static function(PDO $db)use(&$calls):int{++$calls;$db->exec('UPDATE owned_policy_business SET amount=2');return 2;});Check::same(2,$result);}
}catch(SoSecurity\Exception\SecurityException $error){$rejected=true;Check::same($case==='guard'?'operation.request_denied':($case==='fault'?'operation.request_unavailable':($case==='source-change'?'account.completion_unknown':'operation.expired')),$error->reason());if($case==='source-change'){Check::same('account.witness_changed',$error->getPrevious()->reason());}else{Check::same(null,$error->getPrevious());}Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}
Check::same($case!=='normal',$rejected);Check::same($case==='source-change'?'pending':'current',$inspect()['status']);Check::same($before['revision']+1,$inspect()['revision']);Check::same($entry==='execute'?1:0,$calls);Check::same($entry==='execute'?2:1,(int)$pdo->query('SELECT amount FROM owned_policy_business')->fetchColumn());
echo 'PASS native operation return '.$entry.' '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
