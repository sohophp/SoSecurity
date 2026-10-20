<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$driver=$argv[1];$target=$argv[2];$operation=$argv[3];$index=(int)$argv[4];$channel=$argv[5] ?? '';
$pdo=$driver==='mysql'?new InboxTestConnection('mysql:unix_socket='.$target.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]):new InboxTestConnection('sqlite:'.$target,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>2]);
$clock=new TestClock();$endpoint=new SoSecurity\Webhook\Endpoint('inbox','tenant','provider-account','https://hooks.example/events','standard-hmac',['io_milliseconds'=>10000]);$keys=new SoSecurity\Webhook\KeySet($endpoint,['test'=>str_repeat('k',32)]);
$event=strpos($operation,'before')!==false?'msg_crash_before':(strpos($operation,'after')!==false?'msg_crash_after':($operation==='conflict'?'msg_conflict':'msg_race'));
$body=json_encode(['id'=>$event,'type'=>'document.changed','resource'=>'a','account'=>'provider-account','version'=>'1','variant'=>$operation==='conflict'?(string)($index%2):'same']);
$wait=static function()use($channel):void{$handle=fopen($channel,'x');if($handle===false){throw new RuntimeException('Cannot create private process checkpoint.');}chmod($channel,0600);fwrite($handle,'ready');fclose($handle);while(true){usleep(100000);}};
$keyCalls=0;$verifier=new SoSecurity\Webhook\Verifier($endpoint,static function()use($keys,$operation,$wait,&$keyCalls){++$keyCalls;if($operation==='crash-before'&&$keyCalls===5){$wait();}return $keys;},static function(){return true;},$clock);
if($operation==='crash-after'){$pdo->afterCommit=$wait;}
$site=$operation==='sites'?'worker-site-'.($index%2):'inbox-test-site';
$inbox=new SoSecurity\Webhook\SqlInbox($pdo,$site,$verifier,new SoSecurity\Support\HmacKeys('seal',['seal'=>str_repeat('s',32)]),static function(SoSecurity\Webhook\Endpoint $endpoint,SoSecurity\Webhook\Message $message)use($pdo,$driver):bool{
    $query=$pdo->prepare('SELECT account,enabled,version FROM webhook_test_resources WHERE tenant=:tenant AND id=:id'.($driver==='mysql'&&$pdo->inTransaction()?' FOR UPDATE':''));$query->execute(['tenant'=>$endpoint->scope(),'id'=>$message->resource()]);$row=$query->fetch(PDO::FETCH_ASSOC);return is_array($row)&&$row['account']===$endpoint->account()&&(int)$row['enabled']===1&&$row['version']==='1';
},$clock);
$signature=base64_encode(hash_hmac('sha256',$event.'.100000.'.$body,str_repeat('k',32),true));if($operation==='invalid'){$signature=base64_encode(str_repeat('x',32));}
$request=new SoSecurity\Webhook\Request('POST',$endpoint->url(),$body,['Webhook-Id'=>$event,'Webhook-Timestamp'=>'100000','Webhook-Signature'=>'v1,'.$signature]);
try{
    $receipt=$inbox->accept($request,static function(SoSecurity\Webhook\VerifiedWebhook $proof):SoSecurity\Webhook\Message{$value=json_decode($proof->body(),true);return new SoSecurity\Webhook\Message($value['id'],$value['type'],$value['resource'],['version'=>'1','variant'=>$value['variant']]);});
    echo json_encode($receipt===null?['status'=>'denied']:['status'=>$receipt->duplicate()?'duplicate':'created','id'=>$receipt->id()]);
}catch(SoSecurity\Exception\SecurityException $error){if($error->reason()!=='webhook.inbox_conflict'){throw $error;}echo json_encode(['status'=>'conflict']);}
