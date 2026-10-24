<?php
declare(strict_types=1);
require_once __DIR__.'/api-retirement-support.php';
function managedApi(EntryEnvironment $x,?callable $guard=null,?callable $scopes=null,?SoSecurity\Api\CredentialPolicy $policy=null):SoSecurity\Api\CredentialRegistry
{
    return new SoSecurity\Api\CredentialRegistry($x->store,$x->sessions,$x->provider,$x->e->keys,'managed-test',$guard??static function():bool{return true;},$scopes??static function():array{return ['records:read','records:write'];},$policy??new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['records:read','records:write'],'minimum_strength'=>2,'methods'=>['totp'],'io_milliseconds'=>30000]),$x->e->clock,$x->factorAdapter,null,null,$x->boundary);
}
function managedApiSeed(EntryEnvironment $x):array
{
    $session=$x->login()->credential()->token();$api=managedApi($x);$tokens=$x->boundary->run('owned.managed.seed',static function()use($api,$session):array{return [$api->issue('tenant','user',$session,'Owned key one',['records:read'])->token(),$api->issue('tenant','user',$session,'Owned key two',['records:write'])->token(),$api->issue('tenant','user',$session,'Owned expiring key',['records:read'],1)->token()];});$authority=$x->boundary->run('owned.managed.authority',static function()use($x):array{return [$x->provider->find('tenant','user'),$x->factorAdapter->binding('tenant','user')];});$x->e->clock->time+=2;return [$api,$tokens,$session,$authority];
}
function managedApiSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,?callable $persist=null):array
{
    list($api,$tokens,$session,$authority)=managedApiSeed($x);list($next,$token)=containmentStage($x,$op,$control);$plan=SoSecurity\Account\StateApiKeyRetirement::prepareCredentials(...array_merge(apiRetirementArgs($x,$next,$api,$persist),['tenant','user','witnessBudget']));return [$api,$tokens,$session,$authority,$next,$plan,$token];
}
/** Same native HMAC/session/credential code, deliberately unchanged valid identity/factor on copied bytes. */
function managedApiProbe(EntryEnvironment $x,array $tokens,string $session,array $authority,bool $retired):void
{
    $dir=privateDirectory();try{
        foreach(glob($x->e->directory.'/factors/*.json') as $file){copy($file,$dir.'/'.basename($file));chmod($dir.'/'.basename($file),0600);}$provider=new class($authority[0]) implements SoSecurity\Auth\IdentityProvider{private $a;public function __construct($a){$this->a=$a;}public function authenticate(string $s,string $i,string $p):?SoSecurity\Auth\Account{return $this->a;}public function find(string $s,string $u):?SoSecurity\Auth\Account{return $this->a;}};$factor=new class($authority[1]) implements SoSecurity\Auth\SecondFactor{private $b;public function __construct($b){$this->b=$b;}public function binding(string $s,string $u):?string{return $this->b;}public function verify(string $s,string $u,string $b,$p):?string{return 'totp';}};
        $store=new SoSecurity\Storage\FileStore($dir,'entry-sessions',$x->e->clock);$sessions=new SoSecurity\Auth\SessionRegistry($store,$provider,$factor,$x->e->clock,1800,28800,16);$api=new SoSecurity\Api\CredentialRegistry($store,$sessions,$provider,$x->e->keys,'managed-test',static function():bool{return true;},static function():array{return ['records:read','records:write'];},new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['records:read','records:write'],'minimum_strength'=>2,'methods'=>['totp'],'io_milliseconds'=>30000]),$x->e->clock,$factor);
        foreach($tokens as $i=>$t){Check::same(!$retired&&$i<2,$api->authenticate('tenant',$t,$i===1?'records:write':'records:read') instanceof SoSecurity\Api\VerifiedCredential);}
        if($retired){$fresh=$api->issue('tenant','user',$session,'Owned renewed key',['records:read']);Check::same(true,$api->authenticate('tenant',$fresh->token(),'records:read') instanceof SoSecurity\Api\VerifiedCredential);$rotated=$api->rotate('tenant','user',$session,$fresh->metadata()->id(),1);Check::same(true,$rotated instanceof SoSecurity\Api\IssuedCredential);Check::same(null,$api->authenticate('tenant',$fresh->token(),'records:read'));Check::same(true,$api->authenticate('tenant',$rotated->token(),'records:read') instanceof SoSecurity\Api\VerifiedCredential);}
    }finally{cleanDirectory($dir);}
}
function managedApiAssertions(EntryEnvironment $x,array $tokens,string $session,array $authority,SoSecurity\Account\StateApiKeyRetirement $plan,array $before,array $done):void
{
    Check::same('quarantined',$done['status']);Check::same('complete',$done['remediation']['phase']);Check::same($before['digest'],$done['digest']);Check::same(2,$plan->manifest()['format']);Check::same('account_credentials',$plan->manifest()['kind']);$m=$plan->manifest();$raw=file_get_contents($x->e->directory.'/factors/'.$m['reference']['file']);Check::same($m['after'],$raw);Check::same([],json_decode($raw,true)['value']['entries']);Check::same(32,strlen(json_decode($raw,true)['value']['epoch']));managedApiProbe($x,$tokens,$session,$authority,true);foreach($tokens as $t){Check::same(false,strpos(json_encode($done),$t)!==false);}
}
