<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$cases=json_decode(stream_get_contents(STDIN),true);$results=[];
foreach($cases as $case){
    $endpoint=new SoSecurity\Webhook\Endpoint('endpoint','tenant','provider-account','https://hooks.example/events',$case['protocol'],$case['options']);$clock=new TestClock();$clock->time=$case['now'];$keys=new SoSecurity\Webhook\KeySet($endpoint,['test'=>base64_decode($case['key'],true)]);$calls=0;
    $service=new SoSecurity\Webhook\Verifier($endpoint,static function()use($keys,&$calls){++$calls;return $keys;},static function(){return true;},$clock);
    try{$proof=$service->verify(new SoSecurity\Webhook\Request($case['method'],$case['url'],base64_decode($case['body'],true),$case['headers']));$result=$proof===null?['result'=>'denied']:['result'=>'allowed','digest'=>$proof->bodyDigest(),'id'=>$proof->messageId(),'timestamp'=>$proof->timestamp(),'expires'=>$proof->expiresAt()];}
    catch(SoSecurity\Exception\ValidationException $error){$result=['result'=>'denied'];}
    catch(SoSecurity\Storage\StorageException $error){$result=['result'=>'clock'];}
    $result['calls']=$calls;$results[]=$result;
}
echo json_encode($results)."\n";
