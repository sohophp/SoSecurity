<?php
declare(strict_types=1);
require __DIR__.'/api-intent-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $token=$x->login()->credential()->token();$api=nativeApi($x);$identity=apiIntentIdentity($x,'user',$token);$fp=$identity['fingerprint'];$ref=SoSecurity\Auth\SessionRegistry::reference($token);$id=null;$bearer=null;
    foreach(['issue','all','rotate','replace','authenticate','fromAuthorization','revoke','revokeAll'] as $entry){
        $parameters=['owner'=>'user'];$credential=$ref;$args=['tenant','user',$token];
        if($entry==='issue'){$parameters+=['name'=>'Receipt owned','scopes'=>['records:read','records:write'],'ttl'=>600];$args=array_merge($args,['Receipt owned',['records:write','records:read'],600]);}
        elseif($entry==='rotate'){$parameters+=['id'=>$id,'generation'=>1,'name'=>null,'scopes'=>null,'ttl'=>null];$args=array_merge($args,[$id,1]);}
        elseif($entry==='replace'){$parameters+=['id'=>$id,'generation'=>2,'name'=>'Receipt replaced','scopes'=>['records:read'],'ttl'=>300];$args=array_merge($args,[$id,2,'Receipt replaced',['records:read'],300]);}
        elseif(in_array($entry,['authenticate','fromAuthorization'],true)){$parameters=['required_scope'=>'records:read'];$credential=['digest'=>hash('sha256',$bearer)];$args=['tenant',$entry==='authenticate'?$bearer:'Bearer '.$bearer,'records:read'];}
        elseif($entry==='revoke'){$parameters['id']=$id;$args[]=$id;}
        $expected=apiIntentExpected($x,$api,$entry,'user','user',$fp,$fp,$credential,$parameters,['records:read','records:write'],$x->source->digest());$writes=[];apiIntentObserve($x,$writes);$result=$api->$entry(...$args);$x->persistHook=null;Check::same(2,count($writes));Check::same('pending',$writes[0]['status']);Check::same('current',$writes[1]['status']);apiIntentCheck($expected,$writes[0]);apiIntentCheck($expected,$writes[1]);apiIntentCheck($expected,$x->inspect());
        if(in_array($entry,['issue','rotate','replace'],true)){$id=$result->metadata()->id();$bearer=$result->token();Check::same(false,strpos(json_encode($x->inspect()),$bearer)!==false);}elseif(in_array($entry,['authenticate','fromAuthorization'],true)){Check::same('user',$result->account()->subject());}
        Check::same(false,strpos(json_encode($x->inspect()),$token)!==false);
    }
    $observed=$x->source->digest();$expected=apiIntentExpected($x,$api,'issue','user','user',$fp,$fp,$ref,['owner'=>'user','name'=>'Unknown exact','scopes'=>['records:read'],'ttl'=>86400],['records:read','records:write'],$observed);$writes=[];apiIntentObserve($x,$writes);$x->finalAllowed=false;witnessReason('account.completion_unknown',static function()use($api,$token):void{$api->issue('tenant','user',$token,'Unknown exact',['records:read']);});$x->finalAllowed=true;$x->persistHook=null;Check::same(1,count($writes));$pending=$x->inspect();Check::same('pending',$pending['status']);apiIntentCheck($expected,$pending);Check::same($observed,$pending['digest']);nativeApiNoEffect($x,static function()use($api,$token):void{$api->issue('tenant','user',$token,'Do not replay',['records:read']);},'account.witness_pending');apiIntentCheck($expected,$x->inspect());
});
echo 'PASS exact native API intent receipts: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; all eight entries bind actual identity, credential digest, normalized parameters, current scopes, source and policy; pending/current identical, committed unknown preserved without secrets or replay\n";
