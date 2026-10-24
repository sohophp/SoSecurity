<?php
declare(strict_types=1);
use SoSecurity\Exception\SecurityException;
$case=explode('-',$mode,3)[2];
$credential=$api->issue('tenant','fresh-user',$token,'Owned bearer return',['records:read','records:write']);
if($case==='grow'){$auditScopes=['records:write'];}
$before=$inspect();
$nativeFinalHook=static function()use($case,&$auditRequestAllowed,&$auditScopes,$clock,$credential,&$bearerRequestFault,&$bearerScopeFault,&$bearerScopeReentry,$api):void{
 if($case==='narrow'){$auditScopes=['records:write'];}
 if($case==='grow'){$auditScopes=['records:read','records:write'];}
 if($case==='guard'){$auditRequestAllowed=false;}
 if($case==='scope'){$auditScopes=[];}
 if($case==='expiry'){$clock->time=$credential->metadata()->expiresAt();}
 if($case==='guard-fault'){$bearerRequestFault=true;}
 if($case==='scope-fault'){$bearerScopeFault=true;}
 if($case==='reentry'){$bearerScopeReentry=static function()use($api,$credential):void{$api->authenticate('tenant',$credential->token(),'records:write');};}
 if($case==='budget'){usleep(5100000);}
};
$rejected=false;$secret=$case==='invalid'?'invalid':$credential->token();
try{
 if(in_array($case,['extra-scalar','extra-object'],true)){
  $extra=$case==='extra-scalar'?'undeclared':new class implements JsonSerializable{public function jsonSerialize():array{throw new RuntimeException('PRIVATE-UNDECLARED-ARGUMENT');}};
  $entry=strpos($mode,'bearer-auth-')===0?'authenticate':'fromAuthorization';$input=$entry==='authenticate'?$secret:'Bearer '.$secret;$proof=$api->$entry('tenant',$input,'records:write',$extra);
  Check::same(true,$proof instanceof SoSecurity\Api\VerifiedCredential);Check::same(['records:read','records:write'],$proof->scopes());
 }else{
 $proof=strpos($mode,'bearer-auth-')===0?$api->authenticate('tenant',$secret,'records:write'):$api->fromAuthorization('tenant','Bearer '.$secret,'records:write');
 }

 if(in_array($case,['narrow','grow'],true)){Check::same(['records:write'],$proof->scopes());}
 if($case==='normal'){Check::same(true,$proof instanceof SoSecurity\Api\VerifiedCredential);Check::same('fresh-user',$proof->account()->subject());Check::same(['records:read','records:write'],$proof->scopes());}
 if($case==='invalid'){Check::same(null,$proof);Check::same($before,$inspect());}
}catch(SecurityException $error){
 $rejected=true;$reason=$case==='budget'?'account.operation_timeout':($case==='guard-fault'?'api_credentials.request_unavailable':(in_array($case,['scope-fault','reentry'],true)?'api_credentials.scopes_unavailable':'api_credentials.denied'));
 Check::same($reason,$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);
}
Check::same(!in_array($case,['normal','narrow','grow','invalid','extra-scalar','extra-object'],true),$rejected);$after=$inspect();Check::same('current',$after['status']);Check::same($before['revision']+($case==='invalid'?0:1),$after['revision']);Check::same(0,$count());
echo 'PASS native bearer return '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
