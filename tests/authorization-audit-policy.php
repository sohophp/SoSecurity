<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\CallbackPolicy;
use SoSecurity\Authorization\Decision;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\DependencyException;

$actor=new Account('tenant','alice','1',true,['reader']);
$source=new CallbackIdentityProvider(static function(){return null;},static function()use($actor){return $actor;});
$mode=$argv[1]??'revoked';$after=false;$events=0;$calls=0;
$original=new Resource('tenant','document','original','1');$slot=$original;$resources=[&$slot];if($mode==='batch'){$resources[]=new Resource('tenant','document','second','1');}
$policy=new CallbackPolicy(static function(Account $account,string $action,Resource $resource,array $fields)use(&$after,&$calls,$mode):?Decision{
 ++$calls;
 if(!$after){return $mode==='denied'?Decision::deny():Decision::allow(['title','body']);}
 if($mode==='batch'&&$resource->id()==='second'){return Decision::deny();}
 if($mode==='revoked'){return Decision::deny();}
 if($mode==='unsupported'){return null;}
 if($mode==='fault'){throw new RuntimeException('private-policy-detail');}
 if($mode==='fields'){return Decision::allow(['body']);}
 if($mode==='expanded'){return Decision::allow(['title','body','secret']);}
 if($mode==='resource'){return $resource->id()==='original'?Decision::allow(['title']):Decision::deny();}
 return Decision::allow(['title','body']);
});
$audit=new AuditLogger(static function()use(&$after,&$events,&$slot,$mode):void{++$events;$after=true;if($mode==='resource'){$slot=new Resource('tenant','document','replacement','1');}},str_repeat('K',32));
$auth=new Authorizer($source,$policy,$audit);
try{
 $decision=$auth->decideBatch('tenant',$actor,'read',$resources,$mode==='fields'?['title']:[]);
 if($mode==='fault'){throw new LogicException('Policy failure accepted');}
 Check::same(!in_array($mode,['revoked','unsupported','fields','denied','batch'],true),$decision->allowed());
 if($mode==='expanded'){Check::same(['title','body'],$decision->fields());}
 if($mode==='resource'){Check::same('replacement',$slot->id());Check::same(['title'],$decision->fields());}
}catch(DependencyException $error){
 if($mode!=='fault'){throw $error;}
 Check::same('authorization.unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);
}
Check::same(1,$events);Check::same($mode==='denied'?1:($mode==='batch'?4:2),$calls);
echo 'PASS authorization audit policy '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
