<?php
declare(strict_types=1);
list($entry,$case)=explode('-',substr($mode,strlen('remember-return-')),2);$allowed=true;$risk='allow';
$remember=new SoSecurity\Auth\RememberedLogin($store,$provider,$sessions,$keys,$requests,$sdk->managedSecondFactor(),$clock,60,8,300,5,static function()use(&$risk){if($risk==='fault'){throw new RuntimeException('PRIVATE-REMEMBER-RISK');}if($risk==='invalid-reason'||$risk==='invalid-action'){$raw=serialize(new SoSecurity\Auth\DeviceRiskDecision('allow','none'));$raw=str_replace($risk==='invalid-reason'?'s:4:"none";':'s:5:"allow";',serialize($risk==='invalid-reason'?'compromised':'unexpected'),$raw);return unserialize($raw,['allowed_classes'=>[SoSecurity\Auth\DeviceRiskDecision::class]]);}return new SoSecurity\Auth\DeviceRiskDecision($risk,$risk==='allow'?'none':($risk==='deny'?'compromised':'changed'));},$boundary);
$credential=$entry==='issue'?null:$remember->issue('tenant','fresh-user',$token,'Owned return test');
$before=$inspect();$nativeFinalHook=static function()use(&$allowed,$clock,$case,&$authenticationCurrentHook,&$risk):void{if($case==='shared-budget'){usleep(20000000);$authenticationCurrentHook=static function():void{usleep(11000000);};}elseif(strpos($case,'risk-')===0){$risk=substr($case,5);}elseif($case==='guard'){$allowed=false;}elseif($case==='expiry'){$clock->time+=61;}elseif($case==='clock'){$clock->fail=true;}elseif($case==='fault'){$authenticationCurrentHook=static function():void{throw new RuntimeException('PRIVATE-REMEMBER-GUARD');};}};
$rejected=false;
try{
 if($entry==='issue'){Check::same(true,$remember->issue('tenant','fresh-user',$token)!==null);}
 elseif($entry==='resume'){Check::same('authenticated',$remember->resume('tenant',$credential->token())->status());}
 elseif($entry==='revoke'){Check::same(true,$remember->revoke('tenant','fresh-user',$credential->id()));}
 elseif($entry==='forget'){Check::same(true,$remember->forget('tenant',$credential->token()));}
 else{Check::same(1,count($remember->all('tenant','fresh-user')));}
}catch(SoSecurity\Exception\SecurityException $error){$rejected=true;Check::same($case==='guard'?'auth.request_denied':($case==='fault'?'auth.request_unavailable':($case==='clock'?'auth.clock':($case==='shared-budget'?'account.operation_timeout':(strpos($case,'risk-')===0?($case==='risk-fault'?'auth.device_risk_unavailable':'auth.device_risk_denied'):'auth.expired')))),$error->reason());Check::same(null,$error->getPrevious());}
Check::same($case!=='normal',$rejected);Check::same('current',$inspect()['status']);Check::same($before['revision']+1,$inspect()['revision']);
echo 'PASS native persistent login return '.$entry.' '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
