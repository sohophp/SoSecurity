<?php
declare(strict_types=1);
// Test-only process bridge. Every key/account below is synthetic; no application secrets are loaded.
require __DIR__.'/bootstrap.php';require __DIR__.'/credential-support.php';
$request=json_decode(stream_get_contents(STDIN),true);
if(!is_array($request)){throw new RuntimeException('Expected test vectors.');}
$results=[];
foreach($request as $case){
    $e=new CredentialEnvironment();
    if($case['operation']==='issue'){
        $issued=$e->issue($case['scopes'],$case['ttl'],$case['name']);
        $results[]=['token'=>$issued->token(),'state'=>$e->store->states[$e->key()],'metadata'=>$issued->metadata()->toArray(),'policy'=>$e->policy->options()];
    }elseif($case['operation']==='verify'){
        if($case['state']!==null){$e->store->states[$e->key()]=$case['state'];}
        $before=$e->store->calls;
        try{$proof=$e->registry->authenticate($case['scope'],$case['token'],$case['required']);$results[]=['result'=>$proof===null?'denied':'allowed','calls'=>$e->store->calls-$before];}
        catch(SoSecurity\Storage\StorageException $error){$results[]=['result'=>'corrupt','calls'=>$e->store->calls-$before];}
    }else{throw new RuntimeException('Unknown test operation.');}
}
echo json_encode($results,JSON_UNESCAPED_SLASHES)."\n";
