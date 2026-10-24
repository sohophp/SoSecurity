<?php
declare(strict_types=1);
require_once __DIR__.'/recovery-audit-support.php';
function apiRetirementSeed(EntryEnvironment $x):array
{
    $api=new SoSecurity\Api\ApiKeys($x->store,$x->e->clock);$otherStore=new SoSecurity\Storage\FileStore($x->e->directory.'/factors','other-api',$x->e->clock);$other=new SoSecurity\Api\ApiKeys($otherStore,$x->e->clock);$tokens=$x->boundary->run('owned.api.seed',static function()use($api,$other):array{return [$api->issue('user',['read'])->token(),$api->issue('user',['write'])->token(),$api->issue('user',['read'],1)->token(),$api->issue('foreign',['read'])->token(),$other->issue('user',['read'])->token()];});$x->e->clock->time+=2;return [$api,$tokens];
}
function apiRetirementArgs(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $w,$api,?callable $persist=null):array{return [$w,$x->source,$x->sources['files'],'sessions-and-factors',$api,$x->store,$x->e->clock,$persist??static function($h)use($x):bool{return witnessPersist($h,$x->e->directory.'/factors');}];}
function apiRetirementSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,?callable $persist=null):array
{
    list($api,$tokens)=apiRetirementSeed($x);list($next,$token)=containmentStage($x,$op,$control);$plan=SoSecurity\Account\StateApiKeyRetirement::prepare(...array_merge(apiRetirementArgs($x,$next,$api,$persist),['user','witnessBudget']));return [$api,$tokens,$next,$plan,$token];
}
function apiRetirementApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateApiKeyReview $review,string $token):array
{
    $c=$control->beginApiKeys($review,'user',$token);Check::same(null,$control->confirmApiKeys($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmApiKeys($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
/** Actual API token code on private copied bytes, clock zero proves retirement is independent of expiry. */
function apiRetirementProbe(EntryEnvironment $x,array $tokens,bool $retired,?SoSecurity\Account\StateApiKeyRetirement $plan=null):void
{
    $dir=privateDirectory();try{
        foreach(glob($x->e->directory.'/factors/*.json') as $file){copy($file,$dir.'/'.basename($file));chmod($dir.'/'.basename($file),0600);}$clock=new TestClock();$clock->time=0;$store=new SoSecurity\Storage\FileStore($dir,'entry-sessions',$clock);$api=new SoSecurity\Api\ApiKeys($store,$clock);$other=new SoSecurity\Api\ApiKeys(new SoSecurity\Storage\FileStore($dir,'other-api',$clock),$clock);
        foreach(array_slice($tokens,0,3) as $token){Check::same(!$retired,$api->authenticate($token) instanceof SoSecurity\Api\Identity);if($retired){Check::same(null,$api->rotate(explode('.',substr($token,5))[0]));}}
        Check::same('foreign',$api->authenticate($tokens[3])->subject());Check::same('user',$other->authenticate($tokens[4])->subject());
        if($retired){$fresh=$api->issue('user',['read']);Check::same('user',$api->authenticate($fresh->token(),'read')->subject());$rotated=$api->rotate($fresh->identity()->id());Check::same(true,$rotated instanceof SoSecurity\Api\Credential);Check::same(null,$api->authenticate($fresh->token()));Check::same('user',$api->authenticate($rotated->token())->subject());$state=json_decode(file_get_contents($dir.'/'.$store->snapshotFile('api-key:'.hash('sha256',$fresh->identity()->id()))),true)['value'];Check::same(2,$state['v']);
            if($plan!==null){unlink($dir.'/'.$plan->manifest()['reference']['file']);Check::same(null,$api->authenticate($rotated->token()));Check::same(true,$api->authenticate($tokens[0]) instanceof SoSecurity\Api\Identity);}
        }
    }finally{cleanDirectory($dir);}
}
function apiRetirementAssertions(EntryEnvironment $x,array $tokens,SoSecurity\Account\LocalStateWitness $next,SoSecurity\Account\StateApiKeyRetirement $plan,array $before,array $done):void
{
    Check::same('quarantined',$done['status']);Check::same('complete',$done['remediation']['phase']);Check::same($before['digest'],$done['digest']);Check::same($plan->manifest(),$done['remediation']['manifest']);Check::same($plan->manifest()['after'],file_get_contents($x->e->directory.'/factors/'.$plan->manifest()['reference']['file']));apiRetirementProbe($x,$tokens,true,$plan);$dump=json_encode($done);foreach($tokens as $t){Check::same(false,strpos($dump,$t)!==false);}
}
