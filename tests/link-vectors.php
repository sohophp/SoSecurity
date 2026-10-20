<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$input=json_decode(stream_get_contents(STDIN),true);$clock=new TestClock();$clock->time=$input['now'];
$r=$input['resource'];$resource=new SoSecurity\Authorization\Resource($r['scope'],$r['type'],$r['id'],$r['version'],$r['attributes']);
$target=new SoSecurity\Link\Target($input['purpose'],$resource,$input['path'],$input['parameters'],$input['method']);
$policy=new SoSecurity\Link\Policy($input['origin']);$keys=new SoSecurity\Support\HmacKeys($input['kid'],[$input['kid']=>hex2bin($input['key'])]);$store=new SoSecurity\Storage\MemoryStore($clock);
$links=new SoSecurity\Link\Links($store,$keys,$input['site'],$policy,static function(){return true;},$clock);
if($input['operation']==='issue'){
    $link=$links->issue($target,$input['once'],$input['ttl'],$input['binding']);echo json_encode(['url'=>$link->url(),'id'=>$link->id(),'issued'=>$link->issuedAt(),'expires'=>$link->expiresAt(),'target'=>$target->fingerprint(),'resource'=>$resource->fingerprint()]);
}else{
    $parts=$input['record'];$token=substr($parts['url'],strrpos($parts['url'],'_ss=')+4);
    $state=['v'=>1,'policy'=>$policy->fingerprint(),'seen'=>$parts['issued'],'entries'=>[$parts['id']=>['digest'=>hash('sha256',$token),'target'=>$target->fingerprint(),'issued'=>$parts['issued'],'expires'=>$parts['expires'],'one_time'=>$parts['once'],'key_id'=>$input['kid']]]];
    $store->transact(SoSecurity\Link\State::key($input['site'],$target),static function()use($state,$parts){return new SoSecurity\Storage\Change($state,$parts['expires'],null);});
    $first=$links->verify($target,$input['url'],$input['request_method'],$input['binding'])!==null;$second=$links->verify($target,$input['url'],$input['request_method'],$input['binding'])!==null;echo json_encode([$first,$second]);
}
