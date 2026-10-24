<?php
declare(strict_types=1);
list($entry,$case)=explode('-',substr($mode,strlen('link-return-')),2);$allowed=true;$fault=false;$calls=0;$guardCalls=0;
$rules=[];foreach(['issue','all','revoke','revoke_all'] as $action){$rules['links.'.$action]=['type'=>'record','roles'=>['operator'],'fields'=>$action==='issue'?['target','one_time','ttl','binding']:($action==='revoke'?['id']:[])];}
$authorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy($rules));
$links=new SoSecurity\Link\Links($store,$keys,'fresh-site',new SoSecurity\Link\Policy('https://links.example.test',60),static function()use(&$allowed,&$fault,&$guardCalls,$case):bool{++$guardCalls;if($case==='shared-budget'&&$guardCalls===2){usleep(11000000);}if($fault){throw new RuntimeException('PRIVATE-LINK-GUARD');}return $allowed;},$clock,$boundary,$policy,$sessions,$authorizer);
$boundary->run('owned.link.seed',static function()use($pdo):void{$pdo->prepare('INSERT INTO owned_policy_business VALUES (?,?,?,?)')->execute(['tenant','owned','fresh-user',1]);});
$target=new SoSecurity\Link\Target('record',new SoSecurity\Authorization\Resource('tenant','record','owned','1'),'/records/owned');$prepare=static function()use($target){return $target;};
$tables=['owned_policy_business'=>['columns'=>['scope'=>'bytes:256','id'=>'bytes:64','owner'=>'bytes:256','amount'=>'int'],'primary'=>['scope','id']]];
$issued=null;if($entry!=='issue'){$issued=$links->issueFor('tenant','fresh-user',$token,$pdo,$tables,$prepare,true,60);}
$guardCalls=0;$before=$inspect();$nativeFinalHook=static function()use(&$allowed,&$fault,$clock,$case):void{if($case==='guard'){$allowed=false;}elseif($case==='fault'){$fault=true;}elseif($case==='expiry'){$clock->time+=61;}elseif($case==='clock'){$clock->fail=true;}elseif($case==='session'){$clock->time+=86400;}};
$rejected=false;
try{
 if($entry==='issue'){$result=$links->issueFor('tenant','fresh-user',$token,$pdo,$tables,$prepare,true,60);Check::same(true,$result instanceof SoSecurity\Link\IssuedLink);}
 elseif($entry==='verify'){$result=$links->verifyFor('tenant',$pdo,$tables,$prepare,$issued->url());Check::same(true,$result instanceof SoSecurity\Link\VerifiedLink);}
 elseif($entry==='all'){$result=$links->allFor('tenant','fresh-user',$token,$pdo,$tables,$prepare);Check::same(1,count($result));}
 elseif($entry==='revoke'){Check::same(true,$links->revokeFor('tenant','fresh-user',$token,$pdo,$tables,$prepare,$issued->id()));}
 elseif($entry==='revoke_all'){$links->revokeAllFor('tenant','fresh-user',$token,$pdo,$tables,$prepare);}
 else{$result=$links->withVerification('tenant',$pdo,$tables,$prepare,$issued->url(),static function(PDO $db)use(&$calls,$case):int{++$calls;if($case==='shared-budget'){usleep(20000000);}$db->exec('UPDATE owned_policy_business SET amount=2');return 2;});Check::same(2,$result);}
}catch(SoSecurity\Exception\SecurityException $error){$rejected=true;Check::same($case==='guard'?'link.request_denied':($case==='fault'?'link.request_unavailable':($case==='clock'?'link.clock':($case==='session'?'link.authentication':($case==='shared-budget'?'account.operation_timeout':'link.expired')))),$error->reason());Check::same(null,$error->getPrevious());}
Check::same($case!=='normal',$rejected);Check::same('current',$inspect()['status']);Check::same($before['revision']+1,$inspect()['revision']);Check::same($entry==='execute'?1:0,$calls);Check::same($entry==='execute'?2:1,(int)$pdo->query('SELECT amount FROM owned_policy_business')->fetchColumn());
if(in_array($entry,['verify','execute','revoke','revoke_all'],true)&&in_array($case,['normal','guard','fault'],true)){$allowed=true;$fault=false;$stable=$inspect();Check::same(null,$links->verifyFor('tenant',$pdo,$tables,$prepare,$issued->url()));Check::same($stable,$inspect());}
echo 'PASS native link return '.$entry.' '.$case.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
