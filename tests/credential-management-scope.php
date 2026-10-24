<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/credential-support.php';
$modes=($argv[1]??'')==='management-expiry'?[]:(isset($argv[1])?[$argv[1]]:['scope','offline','late-logout','late-identity','late-expiry','late-return-time']);
foreach(['issue','rotate','replace'] as $operation){foreach($modes as $mode){credentialCase(static function(CredentialEnvironment $e)use($mode,$operation):void{
 $original=$operation==='issue'?null:$e->issue();$generation=$original===null?0:$original->metadata()->generation();
 $remaining=0;$armed=false;$issued=false;$marked=false;$e->onScope=static function()use(&$remaining,&$armed,&$issued,&$marked,$e,$mode):void{if($issued&&!$marked){$armed=true;$marked=true;}elseif($issued&&$marked){if($mode==='late-logout'){$e->sessions->revokeAll('tenant','alice');}elseif($mode==='late-identity'){$e->accounts['alice']=new SoSecurity\Auth\Account('tenant','alice','changed',true,['editor']);}elseif($mode==='late-expiry'){$e->clock->time+=301;}elseif($mode==='late-return-time'){$remaining=2;}}};
 $watch=null;$watch=static function()use($e,&$watch,&$issued,$generation):void{foreach($e->store->states as $state){foreach($state['entries'] as $row){if($row['generation']>$generation){$issued=true;return;}}}$e->store->after=$watch;};$e->store->after=$watch;
 $e->onFind=static function()use(&$remaining,&$armed,$e,$mode):void{if($remaining>0&&--$remaining===0){$e->clock->time+=301;}if($armed){$armed=false;if($mode==='scope'){$e->allowed=[];}elseif($mode==='offline'){$e->scopesOffline=true;}}};
 try{if($operation==='issue'){$e->issue();}elseif($operation==='rotate'){$e->registry->rotate('tenant','alice',$e->session(),$original->metadata()->id(),1);}else{$e->registry->replace('tenant','alice',$e->session(),$original->metadata()->id(),1,'Updated key',['documents:read']);}throw new RuntimeException('Stale management permission returned a credential');}catch(SoSecurity\Exception\SecurityException $error){Check::same($mode==='scope'?'api_credentials.scope_denied':($mode==='offline'?'api_credentials.scopes_unavailable':'api_credentials.denied'),$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}
 $e->onScope=null;$e->onFind=null;$e->scopesOffline=false;
 foreach($e->store->states as $state){Check::same([],$state['entries']);}
});}}
if(!isset($argv[1])||$argv[1]==='management-expiry'){foreach(['all','revoke','revokeAll'] as $operation){credentialCase(static function(CredentialEnvironment $e)use($operation):void{
 $original=$e->issue();$effect=false;$observations=0;$remaining=0;
 $e->store->after=static function()use(&$effect):void{$effect=true;};
 $e->onScope=static function()use(&$effect,&$observations,&$remaining):void{if($effect&&++$observations===2){$remaining=2;}};
 $e->onFind=static function()use(&$remaining,$e):void{if($remaining>0&&--$remaining===0){$e->clock->time+=3601;}};
 try{if($operation==='all'){$e->rows();}elseif($operation==='revoke'){$e->registry->revoke('tenant','alice',$e->session(),$original->metadata()->id());}else{$e->registry->revokeAll('tenant','alice',$e->session());}throw new RuntimeException('Expired management session returned a result');}catch(SoSecurity\Exception\SecurityException $error){Check::same('api_credentials.denied',$error->reason());}
 Check::same($operation==='all'?1:0,count($e->store->states[$e->key()]['entries']));
});}}
echo 'PASS management scope completion '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
