<?php
declare(strict_types=1);
list($entry,$case)=explode('-',substr($mode,strlen('auth-return-')),2);
$allowed=true;$clock->time+=30;
if($entry!=='password'){$pending=$auth->password('tenant','return-browser','fresh@example.test',$password);Check::same('mfa_required',$pending->status());}
$before=$inspect();
$nativeFinalHook=static function()use(&$allowed,$clock,$case,&$authenticationCurrentHook,&$auth):void{if($case==='fault'){$authenticationCurrentHook=static function():void{throw new RuntimeException('PRIVATE-AUTH-GUARD');};}elseif($case==='reentry'){$authenticationCurrentHook=static function()use($auth):void{$auth->cancel('tenant','return-browser');};}elseif($case==='shared-budget'){usleep(20000000);$authenticationCurrentHook=static function():void{usleep(11000000);};}elseif($case==='guard'){$allowed=false;}elseif($case==='expiry'){$clock->time+=31536001;}elseif($case==='clock'){$clock->fail=true;}};
$rejected=false;
try{
 if($entry==='password'){$result=$auth->password('tenant','return-browser','fresh@example.test',$password);Check::same('mfa_required',$result->status());}
 elseif($entry==='cancel'){$auth->cancel('tenant','return-browser');}
 else{$result=$auth->secondFactor('tenant','return-browser',$pending->challenge(),['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($authReturnSecret,$clock->time)]);Check::same('authenticated',$result->status());}
}catch(SoSecurity\Exception\SecurityException $error){$rejected=true;Check::same($case==='guard'?'auth.request_denied':($case==='clock'?'auth.clock':(in_array($case,['fault','reentry'],true)?'auth.request_unavailable':($case==='shared-budget'?'account.operation_timeout':'auth.expired'))),$error->reason());Check::same(null,$error->getPrevious());}
Check::same($case!=='normal',$rejected);Check::same('current',$inspect()['status']);Check::same($before['revision']+1,$inspect()['revision']);
echo 'PASS native authentication return '.$entry.' '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
