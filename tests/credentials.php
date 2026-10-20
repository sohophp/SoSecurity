<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/credential-support.php';
use SoSecurity\Api\CredentialEncoding;
use SoSecurity\Api\CredentialPolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

$referenced=['allowed_scopes'=>['documents:write','documents:read'],'ttl'=>60,'maximum_ttl'=>600,'capacity'=>2,'fresh_age'=>120,'minimum_strength'=>1,'delegated_minimum_strength'=>2,'methods'=>['totp','password'],'io_milliseconds'=>1000];$aliases=[];
foreach($referenced as $name=>&$value){$aliases[$name]=&$value;}unset($value);
$unchanged=json_decode(json_encode($referenced),true);$stable=new CredentialPolicy($aliases);Check::same($unchanged,$referenced);$options=$stable->options();$fingerprint=$stable->fingerprint();
foreach($referenced as $name=>&$value){$value=is_array($value)?['invalid']:-1;}unset($value);
Check::same($options,$stable->options());Check::same($fingerprint,$stable->fingerprint());
$returned=$stable->options();$returned['allowed_scopes'][]='injected';$returned['ttl']=-1;Check::same($options,$stable->options());

foreach([['extra'=>true],['ttl'=>'60'],['ttl'=>0],['maximum_ttl'=>31536001],['ttl'=>60,'maximum_ttl'=>59],['capacity'=>17],['capacity'=>0],['fresh_age'=>0],['fresh_age'=>3601],['minimum_strength'=>0],['minimum_strength'=>2,'methods'=>['password']],['methods'=>[]],['methods'=>['password','password']],['methods'=>['remembered']],['io_milliseconds'=>30001],['allowed_scopes'=>['*']],['allowed_scopes'=>['x','x']],['allowed_scopes'=>['x'=>'x']]] as $options){Check::throws(InvalidArgumentException::class,static function()use($options){new CredentialPolicy($options);});}
Check::same((new CredentialPolicy(['capacity'=>2,'allowed_scopes'=>['documents:write','documents:read']]))->fingerprint(),(new CredentialPolicy(['allowed_scopes'=>['documents:read','documents:write'],'capacity'=>2]))->fingerprint());
foreach(['',' bad','bad ',"bad\r\n",str_repeat('x',129),"bad\xe2\x80\xae"] as $name){Check::throws(ValidationException::class,static function()use($name){CredentialEncoding::name($name);});}
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue(['documents:write','documents:read'],60,'工具 <script>alert(1)</script>');$info=$issued->metadata();Check::same(1,$info->generation());Check::same(100060,$info->expiresAt());Check::same(null,$info->lastUsedAt());Check::same(['documents:read','documents:write'],$info->scopes());Check::same(true,strlen($issued->token())<=512);
    $proof=$e->auth($issued->token());Check::same('alice',$proof->account()->subject());Check::same(true,$proof->allows('documents:read'));Check::same(false,$proof->allows('*'));Check::same(100000,$proof->metadata()->lastUsedAt());Check::same($info->id(),$proof->id());Check::same(100060,$proof->expiresAt());
    $rows=$e->rows();Check::same(1,count($rows));Check::same($info->id(),$rows[0]->id());Check::same('old',$rows[0]->keyId());Check::same(false,strpos(json_encode($rows[0]->toArray()),$issued->token())!==false);Check::same(false,strpos(json_encode($e->store->states),$issued->token())!==false);
    foreach([$issued,$proof,$e->registry] as $object){Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object){serialize($object);});Check::same(false,strpos(print_r($object,true),$issued->token())!==false);}
    Check::same('{}',json_encode($info));Check::throws(ConfigurationException::class,static function()use($info){$info->name='changed';});Check::same(0,$e->store->states[$e->key()]['v']-1);
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$before=$e->store->calls;
    foreach([null,[],1,'',str_repeat('x',513),'Bearer '.$issued->token(),strtoupper($issued->token()),substr($issued->token(),0,-1).'!'] as $token){Check::same(null,$e->auth($token));}
    Check::same($before,$e->store->calls);Check::same(null,$e->registry->authenticate('other',$issued->token(),'documents:read'));Check::same($before,$e->store->calls);
    foreach([$issued->token(),'Basic '.$issued->token(),'Bearer  '.$issued->token(),'Bearer '.$issued->token().', another',"Bearer ".$issued->token()."\r\nInjected: yes",['Bearer '.$issued->token()]] as $header){Check::same(null,$e->registry->fromAuthorization('tenant',$header,'documents:read'));}
    Check::same('alice',$e->registry->fromAuthorization('tenant','bEaReR '.$issued->token(),'documents:read')->account()->subject());
    Check::throws(ConfigurationException::class,static function()use($e,$issued){$e->auth($issued->token(),'unconfigured:read');});
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue(['documents:read','documents:write'],60);$e->clock->time+=10;$next=$e->registry->rotate('tenant','alice',$e->session(),$issued->metadata()->id(),1);Check::same(2,$next->metadata()->generation());Check::same(100000,$next->metadata()->createdAt());Check::same(100010,$next->metadata()->issuedAt());Check::same(100060,$next->metadata()->expiresAt());Check::same(null,$e->auth($issued->token()));Check::same(true,$e->auth($next->token())!==null);
    Check::same(null,$e->registry->rotate('tenant','alice',$e->session(),$issued->metadata()->id(),1));Check::same(true,$e->auth($next->token())!==null);
    $e->clock->time+=5;$replacement=$e->registry->replace('tenant','alice',$e->session(),$next->metadata()->id(),2,'New name',['documents:read'],10);Check::same(3,$replacement->metadata()->generation());Check::same(100025,$replacement->metadata()->expiresAt());Check::same('New name',$replacement->metadata()->name());Check::same(null,$e->auth($next->token()));Check::same(null,$e->auth($replacement->token(),'documents:write'));Check::same(true,$e->auth($replacement->token())!==null);
    $longer=$e->registry->replace('tenant','alice',$e->session(),$replacement->metadata()->id(),3,'Same expiry',['documents:read'],86400);Check::same(100025,$longer->metadata()->expiresAt());
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$other=$e->registry->issue('tenant','bob',$e->otherLogin->credential()->token(),'Other',['documents:read']);Check::same(false,$e->registry->revoke('tenant','bob',$e->otherLogin->credential()->token(),$issued->metadata()->id()));Check::same(null,$e->registry->rotate('tenant','bob',$e->otherLogin->credential()->token(),$issued->metadata()->id(),1));
    Check::throws(SecurityException::class,static function()use($e){$e->registry->all('tenant','bob',$e->session());});Check::same(true,$e->auth($issued->token())!==null);
    Check::same(true,$e->registry->revoke('tenant','alice',$e->session(),$issued->metadata()->id()));Check::same(false,$e->registry->revoke('tenant','alice',$e->session(),$issued->metadata()->id()));Check::same(null,$e->auth($issued->token()));Check::same(true,$e->auth($other->token())!==null);
    $a=$e->issue();$b=$e->issue();Check::same(2,$e->registry->revokeAll('tenant','alice',$e->session()));Check::same(null,$e->auth($a->token()));Check::same(null,$e->auth($b->token()));Check::same(true,$e->auth($other->token())!==null);Check::same([], $e->rows());Check::same(true,isset($e->store->states[$e->key()]));
});
foreach([false,1,null,'true'] as $guard){credentialCase(static function(CredentialEnvironment $e)use($guard){$e->guard=$guard;Check::throws(SecurityException::class,static function()use($e){$e->issue();});Check::same([],array_values(array_filter($e->store->states,static function($s){return !empty($s['entries']);})));});}
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$before=$e->store->states;$e->guard=false;Check::throws(SecurityException::class,static function()use($e,$issued){$e->registry->revoke('tenant','alice',$e->session(),$issued->metadata()->id());});Check::same($before,$e->store->states);$e->guard=true;Check::same(true,$e->auth($issued->token())!==null);
    $e->allowed=['documents:read'];Check::throws(SecurityException::class,static function()use($e){$e->issue(['documents:write']);});Check::throws(ValidationException::class,static function()use($e){$e->issue([]);});
});
credentialCase(static function(CredentialEnvironment $e){$e->issue();$e->issue();Check::throws(SecurityException::class,static function()use($e){$e->issue();});Check::same(2,count($e->rows()));},new CredentialPolicy(['allowed_scopes'=>['documents:read'],'capacity'=>2]));
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue(['documents:read','documents:write']);$e->allowed=['documents:read'];Check::same(null,$e->auth($issued->token(),'documents:write'));$proof=$e->auth($issued->token());Check::same(['documents:read'],$proof->scopes());Check::same(['documents:read','documents:write'],$proof->metadata()->scopes());
    $e->scopesOffline=true;try{$e->auth($issued->token());throw new LogicException('Expected scope outage.');}catch(DependencyException $error){Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}$e->scopesOffline=false;Check::same(true,$e->auth($issued->token())!==null);
    $e->offline=true;Check::throws(DependencyException::class,static function()use($e,$issued){$e->auth($issued->token());});$e->offline=false;Check::same(true,$e->auth($issued->token())!==null);
});
foreach(['version','roles','disabled','deleted'] as $change){credentialCase(static function(CredentialEnvironment $e)use($change){
    $issued=$e->issue();if($change==='deleted'){unset($e->accounts['alice']);}else{$e->accounts['alice']=new SoSecurity\Auth\Account('tenant','alice',$change==='version'?'2':'1',$change!=='disabled',$change==='roles'?['reader']:['editor']);}
    Check::same(null,$e->auth($issued->token()));Check::same([],$e->store->states[$e->key()]['entries']);$e->accounts['alice']=new SoSecurity\Auth\Account('tenant','alice','1',true,['editor']);Check::same(null,$e->auth($issued->token()));
});}
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$e->sessions->revokeAll('tenant','alice');Check::same(true,$e->auth($issued->token())!==null);Check::throws(SecurityException::class,static function()use($e){$e->rows();});
});
credentialCase(static function(CredentialEnvironment $e){$e->clock->time+=300;Check::throws(SecurityException::class,static function()use($e){$e->issue();});Check::same([],$e->rows());});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue(['documents:read'],2);$e->clock->time+=2;Check::same(null,$e->auth($issued->token()));Check::same([],$e->store->states[$e->key()]['entries']);$e->clock->time=100000;Check::throws(StorageException::class,static function()use($e,$issued){$e->auth($issued->token());});
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$nextKeys=new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32),'old'=>str_repeat('k',32)]);$next=$e->service(null,$nextKeys);Check::same(true,$next->authenticate('tenant',$issued->token(),'documents:read')!==null);$rotated=$next->rotate('tenant','alice',$e->session(),$issued->metadata()->id(),1);Check::same('new',$rotated->metadata()->keyId());
    $oldOnly=$e->service();Check::same(null,$oldOnly->authenticate('tenant',$rotated->token(),'documents:read'));$newOnly=$e->service(null,new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('n',32)]));Check::same(true,$newOnly->authenticate('tenant',$rotated->token(),'documents:read')!==null);
    $site=$e->service(null,$nextKeys,'other-site');$calls=$e->store->calls;Check::same(null,$site->authenticate('tenant',$rotated->token(),'documents:read'));Check::same($calls,$e->store->calls);
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$policy=new CredentialPolicy(['allowed_scopes'=>['documents:read'],'capacity'=>8]);$changed=$e->service($policy);Check::throws(StorageException::class,static function()use($changed,$issued){$changed->authenticate('tenant',$issued->token(),'documents:read');});Check::same(1,$changed->revokeAll('tenant','alice',$e->session()));Check::same(null,$changed->authenticate('tenant',$issued->token(),'documents:read'));Check::same(1,$changed->issue('tenant','alice',$e->session(),'Migrated',['documents:read'])->metadata()->generation());
});
credentialCase(static function(CredentialEnvironment $e){
    $first=$e->issue();$e->onGuard=function(string $operation)use($e){if($operation==='issue'){$e->onGuard=null;$e->registry->revokeAll('tenant','alice',$e->session());}};Check::throws(SecurityException::class,static function()use($e){$e->issue();});Check::same(null,$e->auth($first->token()));Check::same([],$e->rows());
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$at=$e->scopeCalls+2;$e->onScope=function(int $count)use($e,$at,$issued){if($count===$at){$e->onScope=null;$e->registry->revoke('tenant','alice',$e->session(),$issued->metadata()->id());}};Check::same(null,$e->auth($issued->token()));
});
credentialCase(static function(CredentialEnvironment $e){
    // A late capability denial still observes expiry; restoring permissions and time must not revive it.
    $issued=$e->issue(['documents:read'],2);$at=$e->scopeCalls+2;
    $e->onScope=function(int $count)use($e,$at){if($count===$at){$e->onScope=null;$e->allowed=[];$e->clock->time+=2;}};
    Check::same(null,$e->auth($issued->token()));Check::same([],$e->store->states[$e->key()]['entries']);
    $e->allowed=['documents:read','documents:write'];$e->clock->time=100000;
    Check::throws(StorageException::class,static function()use($e,$issued){$e->auth($issued->token());});
});
credentialCase(static function(CredentialEnvironment $e){
    $e->onScope=function()use($e){$e->onScope=null;$e->sessions->revokeAll('tenant','alice');};Check::throws(SecurityException::class,static function()use($e){$e->issue();});Check::same([],$e->store->states);
});
foreach([-1,PHP_INT_MAX,99999] as $invalid){credentialCase(static function(CredentialEnvironment $e)use($invalid){
    $issued=$e->issue();$e->store->after=function()use($e,$invalid){$e->clock->time=$invalid;};Check::throws(SecurityException::class,static function()use($e,$issued){$e->auth($issued->token());});$e->clock->time=100000;Check::same(null,$e->auth($issued->token()));
});}
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$original=$e->store->states[$e->key()];$id=$issued->metadata()->id();
    foreach(['scopes','expires','identity','claims','epoch','subject','extra'] as $field){$state=$original;
        if($field==='scopes'){$state['entries'][$id]['scopes']=['documents:write'];}elseif($field==='expires'){$state['entries'][$id]['expires']+=1;}elseif($field==='identity'){$state['identity']=str_repeat('a',64);}elseif($field==='claims'){$state['entries'][$id]['claims']=str_repeat('b',64);}elseif($field==='epoch'){$state['epoch']=str_repeat('c',32);}elseif($field==='subject'){$state['subject']='bob';}else{$state['extra']=true;}
        $e->store->states[$e->key()]=$state;Check::throws(StorageException::class,static function()use($e,$issued){$e->auth($issued->token());});
    }$e->store->states[$e->key()]=$original;Check::same(true,$e->auth($issued->token())!==null);
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$parts=CredentialEncoding::parse($issued->token());$state=$e->store->states[$e->key()];$state['entries'][$parts['id']]['scopes']=['documents:write'];$state['entries'][$parts['id']]['claims']=SoSecurity\Api\CredentialState::claims('credential-test','tenant','alice',$parts['root'],$state['epoch'],$parts['id'],$state['entries'][$parts['id']]);$e->store->states[$e->key()]=$state;Check::same(null,$e->auth($issued->token(),'documents:write'));
});
credentialCase(static function(CredentialEnvironment $e){$issued=$e->issue();unset($e->store->states[$e->key()]);Check::same(null,$e->auth($issued->token()));Check::same([],$e->store->states);Check::same([], $e->rows());$next=$e->issue();Check::same(null,$e->auth($issued->token()));Check::same(true,$e->auth($next->token())!==null);});
credentialCase(static function(CredentialEnvironment $e){
    $e->onGuard=function(string $operation)use($e){if($operation==='issue'){$e->clock->time+=300;}};Check::throws(SecurityException::class,static function()use($e){$e->issue();});Check::same([],$e->store->states[$e->key()]['entries']);
});
credentialCase(static function(CredentialEnvironment $e){
    $at=$e->store->calls+2;$e->store->after=function(string $key,int $count)use($e,$at){if($count===$at){$e->clock->time+=3;}else{$e->store->after=function()use($e){$e->clock->time+=3;};}};
    Check::throws(SecurityException::class,static function()use($e){$e->issue(['documents:read'],1);});Check::same([],$e->store->states[$e->key()]['entries']);
});
credentialCase(static function(CredentialEnvironment $e){
    $issued=$e->issue();$e->store->failure=true;Check::throws(StorageException::class,static function()use($e,$issued){$e->auth($issued->token());});Check::throws(StorageException::class,static function()use($e){$e->issue();});$e->store->failure=false;Check::same(true,$e->auth($issued->token())!==null);
});
$longScopes=[];for($i=0;$i<32;++$i){$longScopes[]=str_pad('scope:'.str_pad((string)$i,2,'0',STR_PAD_LEFT),64,'x');}
credentialCase(static function(CredentialEnvironment $e)use($longScopes){
    $e->allowed=$longScopes;for($i=0;$i<16;++$i){$e->issue($longScopes,null,str_repeat('名',42).'a');}Check::same(16,count($e->rows()));$encoded=SoSecurity\Storage\Codec::encode(new SoSecurity\Storage\Change($e->store->states[$e->key()],0,null));Check::same(true,strlen($encoded)<65536);Check::throws(SecurityException::class,static function()use($e,$longScopes){$e->issue($longScopes);});
},new CredentialPolicy(['allowed_scopes'=>$longScopes]));
credentialCase(static function(CredentialEnvironment $e){
    Check::throws(ConfigurationException::class,static function(){SoSecurity\Security::fromArray(['site'=>'credential-factory','api_credentials'=>[]]);});
    Check::throws(ConfigurationException::class,static function(){SoSecurity\Security::fromArray(['site'=>'credential-factory'])->apiCredentials();});
    $directory=privateDirectory();
    try {
        $config=['site'=>'credential-factory','storage'=>['driver'=>'file','directory'=>$directory],'authentication'=>['identity_provider'=>'identity','request_guard'=>'auth_guard'],'api_credentials'=>['keys'=>'keys','request_guard'=>'credential_guard','scope_provider'=>'scopes','policy'=>['allowed_scopes'=>['documents:read']]]];
        $services=['identity'=>$e->provider,'keys'=>$e->keys,'auth_guard'=>static function(){return true;},'credential_guard'=>static function(){return true;},'scopes'=>static function(){return ['documents:read'];}];
        $factory=SoSecurity\Security::fromArray($config,$services,$e->clock);Check::same([],array_values(array_diff(scandir($directory),['.','..'])));Check::same(['documents:read'],$factory->config()->apiCredentials()['policy']['allowed_scopes']);$registry=$factory->apiCredentials();Check::same([],array_values(array_diff(scandir($directory),['.','..'])));
        $login=$factory->authentication()->password('tenant','factory-browser','alice','test-password');$token=$registry->issue('tenant','alice',$login->credential()->token(),'Factory',['documents:read']);Check::same(true,$registry->authenticate('tenant',$token->token(),'documents:read')!==null);
        $diagnostic=json_encode($factory->diagnose());Check::same(true,strpos($diagnostic,'api_credentials.current_scopes_unverified')!==false);Check::same(false,strpos($diagnostic,$token->token())!==false);Check::same(false,strpos($diagnostic,str_repeat('k',32))!==false);
        $bad=$services;$bad['scopes']=new stdClass();Check::throws(ConfigurationException::class,static function()use($config,$bad,$e){SoSecurity\Security::fromArray($config,$bad,$e->clock)->apiCredentials();});
    } finally {cleanDirectory($directory);}
});
credentialCase(static function(CredentialEnvironment $e){
    // Synthetic trusted proof only: tests current factor-version binding, not a real TOTP/WebAuthn protocol.
    $factor=new class implements SoSecurity\Auth\SecondFactor {
        public $generation='factor-v1';
        public function binding(string $scope,string $subject):?string {return $this->generation;}
        public function verify(string $scope,string $subject,string $expectedBinding,$proof):?string {return null;}
    };
    $sessionStore=new SoSecurity\Storage\MemoryStore($e->clock);$sessions=new SoSecurity\Auth\SessionRegistry($sessionStore,$e->provider,$factor,$e->clock);
    $identity=(new SoSecurity\Auth\IdentityState($e->provider,$factor))->load('tenant','alice');$epoch=$sessions->epoch('tenant','alice');$session=$sessions->register('tenant','alice',$identity['fingerprint'],$epoch,'totp');
    $registry=new SoSecurity\Api\CredentialRegistry($e->store,$sessions,$e->provider,$e->keys,'factor-api',static function(){return true;},static function(){return ['documents:read'];},new CredentialPolicy(['allowed_scopes'=>['documents:read'],'minimum_strength'=>2,'methods'=>['totp']]),$e->clock,$factor);
    $issued=$registry->issue('tenant','alice',$session->token(),'MFA bound',['documents:read']);Check::same(true,$registry->authenticate('tenant',$issued->token(),'documents:read')!==null);$factor->generation='factor-v2';Check::same(null,$registry->authenticate('tenant',$issued->token(),'documents:read'));$factor->generation='factor-v1';Check::same(null,$registry->authenticate('tenant',$issued->token(),'documents:read'));
});
credentialCase(static function(CredentialEnvironment $e){
    $identity=(new SoSecurity\Auth\IdentityState($e->provider,null))->load('tenant','alice');$epoch=$e->sessions->epoch('tenant','alice');$recovery=$e->sessions->register('tenant','alice',$identity['fingerprint'],$epoch,'recovery');
    Check::throws(SecurityException::class,static function()use($e,$recovery){$e->registry->issue('tenant','alice',$recovery->token(),'Recovery denied',['documents:read']);});
    $explicit=$e->service(new CredentialPolicy(['allowed_scopes'=>['documents:read'],'methods'=>['recovery']]));Check::same(1,$explicit->issue('tenant','alice',$recovery->token(),'Explicit recovery policy',['documents:read'])->metadata()->generation());
});
credentialCase(static function(CredentialEnvironment $e){
    $e->accounts['alice']=new SoSecurity\Auth\Account('tenant','alice','2',true,['admin']);$e->login=$e->flow->password('tenant','admin-browser','alice','test-password');$e->sessions->revokeAll('tenant','bob');
    $rules=[];foreach(['issue','all','rotate','replace','revoke','revoke_all'] as $operation){$rules['api.credentials.'.$operation]=['type'=>'api_credential_owner','roles'=>['admin'],'fields'=>[]];}
    $authority=new SoSecurity\Authorization\Authorizer($e->provider,new SoSecurity\Authorization\RolePolicy($rules));$manager='alice';$seenActors=[];
    $scopeProvider=static function(SoSecurity\Auth\Account $owner):array{return $owner->subject()==='bob'?['documents:read']:['documents:read','documents:write'];};
    $guard=static function(string $operation,?SoSecurity\Auth\Account $actor,array $metadata)use(&$seenActors):bool{$seenActors[]=[$operation,$actor===null?null:$actor->subject(),$metadata['owner'] ?? null];return true;};
    $resolver=static function(string $scope)use(&$manager):string{return $manager;};
    $delegated=new SoSecurity\Api\CredentialRegistry($e->store,$e->sessions,$e->provider,$e->keys,'credential-test',$guard,$scopeProvider,$e->policy,$e->clock,null,$authority,$resolver);
    Check::throws(SecurityException::class,static function()use($e){$e->registry->issue('tenant','bob',$e->session(),'Not delegated',['documents:read']);});
    Check::throws(SecurityException::class,static function()use($e,$delegated){$delegated->issue('tenant','bob',$e->session(),'Weak operator',['documents:read']);});
    // Explicit synthetic trusted strong proof; real password/TOTP is separately required in native HTTP tests.
    $identity=(new SoSecurity\Auth\IdentityState($e->provider,null))->load('tenant','alice');$strong=$e->sessions->register('tenant','alice',$identity['fingerprint'],$e->sessions->epoch('tenant','alice'),'totp');
    Check::throws(SecurityException::class,static function()use($delegated,$strong){$delegated->issue('tenant','bob',$strong->token(),'Excess target scope',['documents:write']);});
    $issued=$delegated->issue('tenant','bob',$strong->token(),'Service key',['documents:read']);Check::same('bob',$delegated->authenticate('tenant',$issued->token(),'documents:read')->account()->subject());Check::same(0,count($e->sessions->all('tenant','bob')));Check::same(['issue','alice','bob'],$seenActors[0]);
    $creator=SoSecurity\Api\CredentialState::root('credential-test','tenant','alice');Check::same($creator,$issued->metadata()->creatorReference());Check::same($creator,$issued->metadata()->issuerReference());Check::same(1,count($delegated->all('tenant','bob',$strong->token())));
    $e->accounts['carol']=new SoSecurity\Auth\Account('tenant','carol','1',true,['admin']);$identity=(new SoSecurity\Auth\IdentityState($e->provider,null))->load('tenant','carol');$second=$e->sessions->register('tenant','carol',$identity['fingerprint'],$e->sessions->epoch('tenant','carol'),'totp');$manager='carol';
    $rotated=$delegated->rotate('tenant','bob',$second->token(),$issued->metadata()->id(),1);Check::same($creator,$rotated->metadata()->creatorReference());Check::same(SoSecurity\Api\CredentialState::root('credential-test','tenant','carol'),$rotated->metadata()->issuerReference());Check::same(null,$delegated->authenticate('tenant',$issued->token(),'documents:read'));Check::same(true,$delegated->authenticate('tenant',$rotated->token(),'documents:read')!==null);
    $e->onFind=null;$manager='alice';$deniedAuthority=new SoSecurity\Authorization\Authorizer($e->provider);$denied=new SoSecurity\Api\CredentialRegistry($e->store,$e->sessions,$e->provider,$e->keys,'credential-test',$guard,$scopeProvider,$e->policy,$e->clock,null,$deniedAuthority,$resolver);Check::throws(SecurityException::class,static function()use($denied,$strong){$denied->all('tenant','bob',$strong->token());});
    Check::same(true,$delegated->revoke('tenant','bob',$strong->token(),$rotated->metadata()->id()));Check::same(null,$delegated->authenticate('tenant',$rotated->token(),'documents:read'));
});
credentialCase(static function(CredentialEnvironment $e){
    $authority=new SoSecurity\Authorization\Authorizer($e->provider,new SoSecurity\Authorization\CallbackPolicy(static function(){return SoSecurity\Authorization\Decision::allow();}));
    Check::throws(ConfigurationException::class,static function()use($e,$authority){new SoSecurity\Api\CredentialRegistry($e->store,$e->sessions,$e->provider,$e->keys,'credential-test',static function(){return true;},static function(){return ['documents:read'];},$e->policy,$e->clock,null,$authority);});
    $registry=new SoSecurity\Api\CredentialRegistry($e->store,$e->sessions,$e->provider,$e->keys,'credential-test',function(string $op)use($e){if($op==='issue'){$e->accounts['bob']=new SoSecurity\Auth\Account('tenant','bob','2',false,['editor']);}return true;},static function(){return ['documents:read'];},new CredentialPolicy(['allowed_scopes'=>['documents:read'],'delegated_minimum_strength'=>1]),$e->clock,null,$authority,static function(){return 'alice';});
    Check::throws(SecurityException::class,static function()use($e,$registry){$registry->issue('tenant','bob',$e->session(),'Owner changed',['documents:read']);});$root=SoSecurity\Api\CredentialState::root('credential-test','tenant','bob');Check::same([],$e->store->states[SoSecurity\Api\CredentialState::key('credential-test',$root)]['entries']);
});
foreach(['logout','demotion','operator_switch'] as $change){credentialCase(static function(CredentialEnvironment $e)use($change){
    $e->accounts['alice']=new SoSecurity\Auth\Account('tenant','alice','2',true,['admin']);$e->login=$e->flow->password('tenant','admin-browser','alice','test-password');
    $authority=new SoSecurity\Authorization\Authorizer($e->provider,new SoSecurity\Authorization\RolePolicy(['api.credentials.issue'=>['type'=>'api_credential_owner','roles'=>['admin'],'fields'=>[]]]));
    $operator='alice';$changed=false;
    $registry=new SoSecurity\Api\CredentialRegistry($e->store,$e->sessions,$e->provider,$e->keys,'credential-test',static function(){return true;},function()use($e,$change,&$operator,&$changed):array{
        if(!$changed){$changed=true;if($change==='logout'){$e->sessions->revokeAll('tenant','alice');}elseif($change==='demotion'){$e->accounts['alice']=new SoSecurity\Auth\Account('tenant','alice','3',true,['reader']);}else{$operator='bob';}}
        return ['documents:read'];
    },new CredentialPolicy(['allowed_scopes'=>['documents:read'],'delegated_minimum_strength'=>1]),$e->clock,null,$authority,static function()use(&$operator):string{return $operator;});
    Check::throws(SecurityException::class,static function()use($e,$registry){$registry->issue('tenant','bob',$e->session(),'Revoked delegation',['documents:read']);});
    foreach($e->store->states as $state){Check::same([],$state['entries']);}
});}
foreach([null,1,['documents:read','documents:read'],['key'=>'documents:read'],['*']] as $invalid){credentialCase(static function(CredentialEnvironment $e)use($invalid){
    $issued=$e->issue();$registry=new SoSecurity\Api\CredentialRegistry($e->store,$e->sessions,$e->provider,$e->keys,'credential-test',static function(){return true;},static function()use($invalid){return $invalid;},$e->policy,$e->clock);
    Check::throws(DependencyException::class,static function()use($registry,$issued){$registry->authenticate('tenant',$issued->token(),'documents:read');});
    Check::same(true,$e->auth($issued->token())!==null);
});}
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
echo 'PASS account API credentials: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; live Session management, effective scopes, digest/signed claims, atomic generation/epoch, isolation, expiry, provider failures and retry-pure state\n";
