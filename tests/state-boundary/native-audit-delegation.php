<?php
declare(strict_types=1);
use SoSecurity\Account as A;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
$mode=$argv[4]??'normal';
$worker=$raw->managedRegistered('fresh-site','tenant',$epoch,$keys,$fence,new A\FactorWorkerAuthority($pdo,'fresh-site','tenant',$epoch,$keys,$fence,static function(string $action,string $phase,string $scope,string $subject):bool{return $scope==='tenant'&&(($subject==='fresh-user'&&in_array($action,['begin','confirm'],true))||($subject==='audit-owner'&&$action==='adoptManaged'));},new A\Policy(),$clock));
$secret=$boundary->run('owned.audit.first_enrollment',static function()use($worker,$registry,$pdo,$clock):string{
 $pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['["operator"]','fresh-user']);
 $enrollment=$worker->begin('tenant','fresh-user','Owned audit operator');parse_str(parse_url($enrollment->provisioningUri(),PHP_URL_QUERY),$params);$secret=$params['secret'];Check::same(10,count($worker->confirm('tenant','fresh-user',$enrollment->id(),(new SoSecurity\Mfa\Totp())->codeAt($secret,$clock->time))));Check::same(true,$registry->adopt('fresh-user'));return $secret;
});
$boundary->run('owned.audit.owner',static function()use($accounts,$hasher,$password,$registry,$worker):void{$pending=$accounts->createPending('tenant','audit-owner',new A\Address('audit-owner@example.test'));Check::same(true,$accounts->activate($pending,$hasher->hash($password))!==null);Check::same(false,$worker->adoptManaged('tenant','audit-owner',null)['enabled']);Check::same(true,$registry->initialize('audit-owner'));});
$clock->time+=30;$login=$auth->password('tenant','audit-browser','fresh@example.test',$password);Check::same('mfa_required',$login->status());$login=$auth->secondFactor('tenant','audit-browser',$login->challenge(),['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($secret,$clock->time)]);Check::same('authenticated',$login->status());$token=$login->credential()->token();if(strpos($mode,'operation-return-')===0){$operationSecret=$secret;}if(strpos($mode,'captured-permission-')===0){$capturedOperationSecret=$secret;}if(strpos($mode,'auth-return-')===0){$authReturnSecret=$secret;}unset($secret);
if(($mode??'')==='read-factor-locations'){require __DIR__.'/native-factor-locations.php';return;}
if(($mode??'')==='read-pair'){require __DIR__.'/native-credential-pair.php';return;}
if(($mode??'')==='read-cold'){require __DIR__.'/native-credential-cold.php';return;}
$api=$sdk->apiCredentials($policy);$inspect=static function()use($witness):array{return $witness->inspect(static function():bool{return true;});};$count=static function()use($pdo):int{return (int)$pdo->query('SELECT COUNT(*) FROM sosecurity_audit_records')->fetchColumn();};
if(strpos($mode,'captured-permission-')===0){require __DIR__.'/native-captured-permissions.php';return;}
if(strpos($mode,'remember-return-')===0){require __DIR__.'/native-remember-return.php';return;}
if(strpos($mode,'auth-return-')===0){require __DIR__.'/native-auth-return.php';return;}
if(strpos($mode,'reset-proof-return-')===0){require __DIR__.'/native-reset-proof-return.php';return;}
if(strpos($mode,'link-return-')===0){require __DIR__.'/native-link-return.php';return;}
if(strpos($mode,'hmac-return-')===0){require __DIR__.'/native-hmac-return.php';return;}
if(strpos($mode,'operation-return-')===0){require __DIR__.'/native-operation-return.php';return;}
if(strpos($mode,'policy-business-')===0){require __DIR__.'/native-business-policy.php';return;}
if(strpos($mode,'bearer-')===0){require __DIR__.'/native-bearer-return.php';return;}
if(strpos($mode,'business-')===0){require __DIR__.'/native-business-return.php';return;}
if(strpos($mode,'custom-')===0){require __DIR__.'/native-custom-policy.php';return;}
if($mode==='profile-defaults'){require __DIR__.'/native-audit-profile.php';return;}
if($mode==='audit-admission-timeout'){
 $before=$inspect();$auditAdmissionHook=static function():void{usleep(1100000);};
 try{$api->issue('tenant','audit-owner',$token,'Expired audit admission',['records:read']);throw new RuntimeException('Expired audit admitted');}catch(SecurityException $error){Check::same('account.operation_timeout',$error->reason());}
 Check::same(0,$count());Check::same($before,$inspect());echo 'PASS audited delegation '.$mode.' '.Check::$assertions.PHP_EOL;return;
}
if(in_array($mode,['post-audit-delay','post-audit-denial','post-audit-timeout'],true)){
 $nativeFinalHook=static function()use($mode,&$auditReturnAllowed):void{usleep($mode==='post-audit-timeout'?5100000:1100000);if($mode==='post-audit-denial'){$auditReturnAllowed=false;}};
 if($mode==='post-audit-delay'){$issued=$api->issue('tenant','audit-owner',$token,'Completed audit',['records:read']);Check::same(1,$issued->metadata()->generation());}
 else{try{$api->issue('tenant','audit-owner',$token,'Completed audit denied',['records:read']);throw new RuntimeException('Expired caller or revoked permission accepted');}catch(SecurityException $error){Check::same(null,$error->getPrevious());Check::same($mode==='post-audit-timeout'?'account.operation_timeout':'api_credentials.denied',$error->reason());}}
 Check::same(1,$count());Check::same('current',$inspect()['status']);echo 'PASS audited delegation '.$mode.' '.Check::$assertions.PHP_EOL;return;
}
$unsupportedCalls=0;$unsupportedAudit=new SoSecurity\Audit\AuditLogger(static function()use(&$unsupportedCalls):void{++$unsupportedCalls;},str_repeat('a',32));$unsupportedAuthorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy($auditRoleRules),$unsupportedAudit);
Check::throws(ConfigurationException::class,static function()use($store,$sessions,$provider,$keys,$auditGuard,$services,$clock,$sdk,$unsupportedAuthorizer,$boundary,$policy):void{new SoSecurity\Api\CredentialRegistry($store,$sessions,$provider,$keys,'fresh-site',$auditGuard,$services['api_audit_scopes'],new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['records:read','records:write']]),$clock,$sdk->managedSecondFactor(),$unsupportedAuthorizer,$services['api_audit_actor'],$boundary,$policy);});Check::same(0,$unsupportedCalls);
$before=$inspect();$auditCurrentAllowed=false;Check::throws(SecurityException::class,static function()use($api,$token):void{$api->issue('tenant','audit-owner',$token,'Denied before audit',['records:read']);});$auditCurrentAllowed=true;Check::same($before,$inspect());Check::same(0,$count());
if(in_array($mode,['return-denial','return-expiry','return-scope','return-fault','return-clock'],true)){
 $nativeFinalHook=static function()use($mode,&$auditReturnAllowed,&$auditScopes,&$auditGuardFault,$clock):void{if($mode==='return-denial'){$auditReturnAllowed=false;}elseif($mode==='return-expiry'){$clock->time+=301;}elseif($mode==='return-scope'){$auditScopes=[];}elseif($mode==='return-clock'){$clock->fail=true;}else{$auditGuardFault=true;}};
 try{$api->issue('tenant','audit-owner',$token,'Late return denied',['records:read']);throw new RuntimeException('Late authority accepted');}catch(SecurityException $error){Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}
 Check::same(1,$count());Check::same('current',$inspect()['status']);echo 'PASS audited delegation '.$mode.' '.Check::$assertions.PHP_EOL;return;
}
$key=$api->issue('tenant','audit-owner',$token,'Owned audited key',['records:read']);Check::same(1,$count());Check::same(1,count($api->all('tenant','audit-owner',$token)));
$rotated=$api->rotate('tenant','audit-owner',$token,$key->metadata()->id(),1);Check::same(2,$rotated->metadata()->generation());$replaced=$api->replace('tenant','audit-owner',$token,$key->metadata()->id(),2,'Changed audited key',['records:write'],600);Check::same(3,$replaced->metadata()->generation());Check::same(true,$api->revoke('tenant','audit-owner',$token,$key->metadata()->id()));$last=$api->issue('tenant','audit-owner',$token,'Another audited key',['records:read']);Check::same(1,$api->revokeAll('tenant','audit-owner',$token));Check::same(7,$count());
$deniedRules=$auditRoleRules;$deniedRules['api.credentials.issue']['roles']=['absent'];$deniedAuthorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy($deniedRules),$auditLogger);
$denied=new SoSecurity\Api\CredentialRegistry($store,$sessions,$provider,$keys,'fresh-site',$auditGuard,$services['api_audit_scopes'],new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['records:read','records:write'],'io_milliseconds'=>30000]),$clock,$sdk->managedSecondFactor(),$deniedAuthorizer,$services['api_audit_actor'],$boundary,$policy);
try{$denied->issue('tenant','audit-owner',$token,'Object denied',['records:read']);throw new RuntimeException('Object denial accepted');}catch(SecurityException $error){Check::same('authorization.denied',$error->reason());}Check::same(8,$count());Check::same('current',$inspect()['status']);
$rows=$pdo->query('SELECT record FROM sosecurity_audit_records ORDER BY sequence_no')->fetchAll(PDO::FETCH_COLUMN);foreach($rows as $index=>$json){$event=json_decode($json,true);Check::same($index===7?'authorization.denied':'authorization.allowed',$event['event']);Check::same(hash_hmac('sha256','fresh-user',str_repeat('a',32)),$event['subject']);Check::same(['allowed'=>$index!==7],$event['context']);Check::same(false,strpos($json,'audit-owner')!==false);}
$boundary->run('owned.audit.fill_capacity',static function()use($auditLogger):void{for($i=0;$i<8;++$i){$auditLogger->record('owned.capacity','tenant',null);}});$before=$inspect();Check::throws(SecurityException::class,static function()use($api,$token):void{$api->all('tenant','audit-owner',$token);});Check::same(16,$count());Check::same($before,$inspect());
Check::same($source->digest(),$inspect()['digest']);echo 'PASS audited delegation workflow '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
