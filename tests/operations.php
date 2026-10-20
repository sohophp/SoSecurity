<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/operation-support.php';
use SoSecurity\Operation\Intent;
use SoSecurity\Operation\Policy;
use SoSecurity\Operation\Grants;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

$e=new OperationEnvironment();$intent=$e->intent();$key=SoSecurity\Support\Guard::key('operations','site','alice');
$pending=$e->begin();Check::same(1,$e->guards);Check::same(101,strlen($pending->token()));Check::same($intent->fingerprint(),$pending->intent()->fingerprint());
Check::throws(SecurityException::class,function () use ($e,$pending) { $e->confirm($pending); }); // Ordinary password login cannot approve the default policy.
$old=$e->credential->token();$e->reauthenticate();Check::same(null,$e->sessions->verify('site','alice',$old));
$grant=$e->confirm($pending);Check::same(true,$grant instanceof SoSecurity\Operation\Grant);Check::same($pending->id(),$grant->id());Check::same($pending->expiresAt(),$grant->expiresAt());
Check::same(null,$e->confirm($pending));Check::same(null,$e->grants->consume('site','alice',$e->credential->token(),$intent,$pending->token()));
$permit=$e->consume($grant);Check::same($grant->id(),$permit->id());Check::same('totp',$permit->method());Check::same('alice',$permit->account()->subject());Check::same($intent->fingerprint(),$permit->intent()->fingerprint());
Check::same(null,$e->consume($grant));Check::same(null,$e->store->states[$key]);
// Even a recent strong login must rotate its secret after preparing this particular operation.
$pending=$e->begin();Check::same(null,$e->confirm($pending));$e->reauthenticate();$grant=$e->confirm($pending);Check::same(true,$grant!==null);$e->consume($grant);
// Correct owner/context with modified data invalidates the pending challenge or approved grant.
foreach (['pending','granted'] as $phase) {
    $e=new OperationEnvironment();$pending=$e->begin();$e->reauthenticate();$changed=$e->intent(['title'=>'Changed']);
    if ($phase==='pending') { Check::same(null,$e->confirm($pending,$changed));Check::same(null,$e->confirm($pending)); }
    else { $grant=$e->confirm($pending);Check::same(null,$e->consume($grant,$changed));Check::same(null,$e->consume($grant)); }
}
$e=new OperationEnvironment();$grant=$e->approved();Check::same(null,$e->consume($grant,$e->intent(['title'=>'PRIVATE-APPROVED-TITLE'],'2')));Check::same(null,$e->consume($grant));
// Another fully authenticated session cannot confirm, consume or cancel the bound session's operation.
$e=new OperationEnvironment();$pending=$e->begin();$other=$e->newSession('totp');
Check::same(null,$e->grants->confirm('site','alice',$other->token(),$e->intent(),$pending->token()));
Check::same(false,$e->grants->revoke('site','alice',$other->token(),$pending->id()));
$e->reauthenticate();$grant=$e->confirm($pending);Check::same(null,$e->grants->consume('site','alice',$other->token(),$e->intent(),$grant->token()));Check::same(true,$e->consume($grant)!==null);
// A subsequent reauthentication rotates the secret and invalidates an earlier approved grant.
$e=new OperationEnvironment();$grant=$e->approved();$e->reauthenticate();Check::same(null,$e->consume($grant));
$e->grants->revokeAll('site','alice',$e->credential->token());Check::same(null,$e->store->states[$key]);
$pending=$e->begin();Check::same(true,$e->grants->revoke('site','alice',$e->credential->token(),$pending->id()));$e->reauthenticate();Check::same(null,$e->confirm($pending));
$grant=$e->approved();$e->sessions->revokeAll('site','alice');Check::throws(SecurityException::class,function () use ($e,$grant) { $e->consume($grant); });
foreach ([new SoSecurity\Auth\Account('site','alice','2',true,['editor']),new SoSecurity\Auth\Account('site','alice','1',false,['editor']),new SoSecurity\Auth\Account('site','alice','1',true,['reader'])] as $changed) {
    $e=new OperationEnvironment();$grant=$e->approved();$e->current=$changed;Check::throws(SecurityException::class,function () use ($e,$grant) { $e->consume($grant); });
}
// Recovery, remembered/resumed and old proofs are not silently upgraded to the default MFA policy.
$e=new OperationEnvironment();$pending=$e->begin();$e->reauthenticate('recovery');Check::throws(SecurityException::class,function () use ($e,$pending) { $e->confirm($pending); });
$policy=new Policy();$session=new SoSecurity\Auth\VerifiedSession($e->current,str_repeat('a',32),'totp',100000,100000,100300,true);Check::same(false,$policy->accepts($session,100000));
$e=new OperationEnvironment(new Policy(10,8,2,1,['password']));$pending=$e->begin();$e->reauthenticate('password');$grant=$e->confirm($pending);Check::same(100002,$grant->expiresAt());$e->clock->time+=2;
Check::throws(SecurityException::class,function () use ($e,$grant) { $e->consume($grant); });
$e=new OperationEnvironment();$pending=$e->begin();$e->reauthenticate();$e->clock->time+=120;Check::same(null,$e->confirm($pending));
// Scope/subject and policy failures occur before operation storage mutation.
$e=new OperationEnvironment();$grant=$e->approved();$before=$e->store->states;
Check::throws(SecurityException::class,function () use ($e,$grant) { $e->grants->consume('site','other',$e->credential->token(),$e->intent(),$grant->token()); });Check::same($before,$e->store->states);
$foreign=new Intent('document.update',new SoSecurity\Authorization\Resource('other','document','a','1',['owner'=>'alice']),['title'=>'PRIVATE-APPROVED-TITLE'],['title']);
Check::throws(SecurityException::class,function () use ($e,$grant,$foreign) { $e->consume($grant,$foreign); });Check::same($before,$e->store->states);
$e->guard=false;Check::throws(SecurityException::class,function () use ($e,$grant) { $e->consume($grant); });Check::same($before,$e->store->states);$e->guard=true;
$failingGuard=new Grants($e->store,$e->sessions,$e->authorizer,static function () { throw new RuntimeException('PRIVATE-REQUEST-GUARD'); },null,$e->clock);
try { $failingGuard->begin('site','alice',$e->credential->token(),$e->intent());throw new LogicException('Expected guard outage.'); }
catch (DependencyException $error) { Check::same('operation.request_unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false); }
$e->offline=true;Check::throws(SecurityException::class,function () use ($e,$grant) { $e->consume($grant); });Check::same($before,$e->store->states);$e->offline=false;
$e->consume($grant);
// Bound capacity rejects new work, expiry releases it, and complete metadata fits the shared record budget.
$e=new OperationEnvironment(new Policy(120,16));$pending=[];for ($i=0;$i<16;++$i) { $pending[]=$e->begin(); }
Check::throws(SecurityException::class,function () use ($e) { $e->begin(); });
Check::same(true,strlen(SoSecurity\Storage\Codec::encode(new SoSecurity\Storage\Change($e->store->states[$key],$e->store->expires[$key],null)))<65536);
$json=json_encode($e->store->states);Check::same(false,strpos($json,$pending[0]->token())!==false);Check::same(false,strpos($json,'PRIVATE-APPROVED-TITLE')!==false);Check::same(false,strpos($json,'alice')!==false);
$e->clock->time+=121;$new=$e->begin();Check::same(1,count($e->store->states[$key]['entries']));
// Active policy drift and malformed records refuse; explicit canonical state does not silently reset.
$valid=$e->store->states[$key];$changedPolicy=new Grants($e->store,$e->sessions,$e->authorizer,static function ():bool{return true;},new Policy(60,16),$e->clock);
Check::throws(StorageException::class,function () use ($e,$changedPolicy) { $changedPolicy->begin('site','alice',$e->credential->token(),$e->intent()); });
foreach ([['v'=>2],['seen'=>-1],['extra'=>true],['entries'=>['bad'=>[]]]] as $bad) { $e->store->states[$key]=array_merge($valid,$bad);Check::throws(StorageException::class,function () use ($e) { $e->begin(); }); }
foreach (['phase'=>'unknown','digest'=>'bad','session'=>'bad','issued'=>-1,'expires'=>1000000000,'authenticated'=>PHP_INT_MAX,'method'=>'unknown'] as $name=>$value) {
    $e->store->states[$key]=$valid;$e->store->states[$key]['entries'][$new->id()][$name]=$value;Check::throws(StorageException::class,function () use ($e) { $e->begin(); });
}
$e->store->states[$key]=$valid;
// Dependency/authority changes after commit burn or remove the exact operation and never return authorization.
foreach (['begin','confirm','consume'] as $operation) {
    $e=new OperationEnvironment();$pending=null;$grant=null;
    if ($operation!=='begin') { $pending=$e->begin();$e->reauthenticate();if ($operation==='consume') { $grant=$e->confirm($pending); } }
    $e->store->after=function () use ($e) { $e->current=new SoSecurity\Auth\Account('site','alice','2',true,['editor']); };
    Check::throws(SecurityException::class,function () use ($e,$operation,$pending,$grant) { if ($operation==='begin') {$e->begin();}elseif($operation==='confirm'){$e->confirm($pending);}else{$e->consume($grant);} });
    Check::same(null,$e->store->states[$key]);
}
foreach (['begin','confirm','consume'] as $operation) {
    $e=new OperationEnvironment();$pending=null;$grant=null;
    if ($operation!=='begin') { $pending=$e->begin();$e->reauthenticate();if ($operation==='consume') { $grant=$e->confirm($pending); } }
    $e->store->after=function () use ($e) { $e->clock->time+=121; };
    Check::throws(SecurityException::class,function () use ($e,$operation,$pending,$grant) { if ($operation==='begin') {$e->begin();}elseif($operation==='confirm'){$e->confirm($pending);}else{$e->consume($grant);} });
    Check::same(null,$e->store->states[$key]);
}
$e=new OperationEnvironment();$e->store->before=static function () {throw new StorageException('Fixed operation-store outage.');};Check::throws(StorageException::class,function () use ($e) {$e->begin();});
// Canonical maps are order-insensitive, lists are ordered, scalar types stay distinct, and references are detached.
$e=new OperationEnvironment();$title='Original';$parameters=['title'=>&$title,'options'=>['second'=>2,'first'=>1]];$a=$e->intent($parameters);$title='Changed';
Check::same('Original',$a->parameters()['title']);$b=$e->intent(['options'=>['first'=>1,'second'=>2],'title'=>'Original']);Check::same($a->fingerprint(),$b->fingerprint());
$fingerprints=[];foreach ([0,'0',false,null,[1,2],[2,1]] as $value) {$fingerprints[]=$e->intent(['title'=>$value])->fingerprint();}Check::same(6,count(array_unique($fingerprints)));
$cycle=[];$cycle['loop']=&$cycle;
foreach ([[1],['bad-key'=>1],['title'=>new stdClass()],['title'=>1.1],['title'=>NAN],['title'=>"\xff"],['title'=>str_repeat('x',4097)],array_fill_keys(range('a','z'),str_repeat('x',1024)),['title'=>range(1,65)],['title'=>$cycle]] as $bad) { Check::throws(ValidationException::class,function () use ($e,$bad) {$e->intent($bad);}); }
foreach ([[0],[301],[120,17],[120,8,901],[120,8,300,0],[120,8,300,2,['password']],[120,8,300,2,['totp','totp']],[120,8,300,1,['remembered']]] as $bad) { Check::throws(ConfigurationException::class,function () use ($bad) {new Policy(...$bad);}); }
$pending=$e->begin();$e->reauthenticate();$grant=$e->confirm($pending);$permit=$e->consume($grant);
foreach ([$a,$pending,$grant,$permit,$e->grants] as $object) {Check::throws(ConfigurationException::class,function () use ($object) {serialize($object);});Check::same('{}',json_encode($object));}
ob_start();var_dump($pending,$grant,$permit,$a);$debug=ob_get_clean();Check::same(false,strpos($debug,$grant->token())!==false);Check::same(false,strpos($debug,'PRIVATE')!==false);
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
$directory=privateDirectory();
try {
    $e=new OperationEnvironment();$rules=new SoSecurity\Authorization\RolePolicy(['document.update'=>['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner']]);
    $config=['site'=>'operation-factory','storage'=>['driver'=>'file','directory'=>$directory],
        'authentication'=>['identity_provider'=>'identity','request_guard'=>'guard'], 'authorization'=>['policy'=>'policy'],'operations'=>[]];
    $services=['identity'=>$e->source,'guard'=>static function ():bool{return true;},'policy'=>$rules];
    $factory=SoSecurity\Security::fromArray($config,$services,$e->clock);$sessions=$factory->sessions();
    $identity=(new SoSecurity\Auth\IdentityState($e->source,null))->load('site','alice');$epoch=$sessions->epoch('site','alice');$credential=$sessions->register('site','alice',$identity['fingerprint'],$epoch,'password');
    $pending=$factory->operations()->begin('site','alice',$credential->token(),$e->intent());$reference=SoSecurity\Auth\SessionRegistry::reference($credential->token());
    $credential=$sessions->replace('site','alice',$identity['fingerprint'],$epoch,'totp',$reference['id'],$reference['digest']);
    $grant=$factory->operations()->confirm('site','alice',$credential->token(),$e->intent(),$pending->token());
    Check::same(true,$factory->operations()->consume('site','alice',$credential->token(),$e->intent(),$grant->token())!==null);
    Check::same('manual',array_column($factory->diagnose(),null,'check')['operations.request_guard']['status']);
    $withoutGuard=$services;unset($withoutGuard['guard']);Check::throws(ConfigurationException::class,function () use ($config,$withoutGuard) {SoSecurity\Security::fromArray($config,$withoutGuard)->operations();});
    foreach (['memory','session'] as $driver) {$bad=$config;$bad['storage']=['driver'=>$driver];Check::throws(ConfigurationException::class,function () use ($bad,$services) {SoSecurity\Security::fromArray($bad,$services)->operations();});}
    foreach ([null,['ttl'=>'30'],['minimum_strength'=>0],['methods'=>['password']],['unknown'=>true]] as $options) {$bad=$config;$bad['operations']=$options;Check::throws(ConfigurationException::class,function () use ($bad,$services) {SoSecurity\Security::fromArray($bad,$services);});}
    foreach (['authentication','authorization'] as $missing) {$bad=$config;unset($bad[$missing]);Check::throws(ConfigurationException::class,function () use ($bad,$services) {SoSecurity\Security::fromArray($bad,$services);});}
    Check::throws(ConfigurationException::class,function () {SoSecurity\Security::fromArray(['site'=>'a'])->operations();});
} finally {cleanDirectory($directory);}
echo 'PASS operation grants: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; exact intents, new proof, one-use transitions, current session/permissions, bounded canonical data and fail-closed I/O\n";
