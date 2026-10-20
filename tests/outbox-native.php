<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$headers=headers_list();$session=function_exists('session_status')?session_status():null;ob_start();
foreach(['outbox-business','outbox-producer','outbox-worker','outbox-admin','outbox-receiver','outbox-receiver-admin'] as $name){require dirname(__DIR__).'/examples/'.$name.'.php';}
Check::same('',ob_get_clean());Check::same($headers,headers_list());Check::same($session,function_exists('session_status')?session_status():null);
use SoSecurity\Examples\Outbox as Adapter;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
$directory=privateDirectory();$previous=getenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');
function nativePrivate(string $path,array $data):string {file_put_contents($path,json_encode($data));chmod($path,0600);return $path;}
function nativeRequest(string $body,string $id,string $file,?int $stamp=null):SoSecurity\Webhook\Request
{
    $data=Adapter\keyData($file);$time=(string)($stamp ?? time());$signature=base64_encode(hash_hmac('sha256',$id.'.'.$time.'.'.$body,$data['keys'][$data['current']],true));
    return new SoSecurity\Webhook\Request('POST','https://receiver.example.com/outbox-receiver.php',$body,['Webhook-Id'=>$id,'Webhook-Timestamp'=>$time,'Webhook-Signature'=>'v1,'.$signature]);
}
try{
    mkdir($directory.'/web',0700);mkdir($directory.'/sender-state',0700);mkdir($directory.'/receiver-state',0700);
    $sender=new PDO('sqlite:'.$directory.'/sender.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$receiver=new PDO('sqlite:'.$directory.'/receiver.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($directory.'/sender.sqlite',0600);chmod($directory.'/receiver.sqlite',0600);
    foreach(['outbox-sqlite','idempotency-sqlite','outbox-example-sender-sqlite'] as $name){$sender->exec(file_get_contents(dirname(__DIR__).'/resources/sql/'.$name.'.sql'));}
    foreach(['webhook-sqlite','webhook-processing-sqlite','outbox-example-receiver-sqlite'] as $name){$receiver->exec(file_get_contents(dirname(__DIR__).'/resources/sql/'.$name.'.sql'));}
    $sender->exec("INSERT INTO outbox_example_actors VALUES('alice','1',1,'[\"orders_writer\",\"outbox_worker\",\"outbox_admin\"]')");$receiver->exec("INSERT INTO outbox_example_actors VALUES('receiver','1',1,'[\"receiver_worker\",\"receiver_admin\"]')");$receiver->exec("INSERT INTO outbox_example_routes VALUES('outbox-publisher','outbox-example',1)");$receiver->exec("INSERT INTO outbox_example_owners VALUES('alice',1)");
    $checkpoint=new PDO('sqlite:'.$directory.'/checkpoint.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($directory.'/checkpoint.sqlite',0600);$checkpoint->exec(file_get_contents(dirname(__DIR__).'/resources/sql/outbox-example-checkpoint-sqlite.sql'));file_put_contents($directory.'/checkpoint.lock','');chmod($directory.'/checkpoint.lock',0600);
    foreach(['sender-seals'=>'s','receiver-seals'=>'r','idempotency'=>'i','wire'=>'w'] as $name=>$byte){nativePrivate($directory.'/'.$name.'.json',['current'=>'old','keys'=>['old'=>base64_encode(str_repeat($byte,32))]]);}
    $base=['document_root'=>$directory.'/web','actor'=>'alice','version'=>'1','epoch'=>str_repeat('e',64),'url'=>'https://receiver.example.com/outbox-receiver.php'];
    $senderConfig=$base+['role'=>'sender','database'=>$directory.'/sender.sqlite','storage'=>$directory.'/sender-state','seals'=>$directory.'/sender-seals.json','wire_keys'=>$directory.'/wire.json','idempotency_keys'=>$directory.'/idempotency.json'];
    $receiverConfig=array_replace($base,['actor'=>'receiver'])+['role'=>'receiver','database'=>$directory.'/receiver.sqlite','storage'=>$directory.'/receiver-state','seals'=>$directory.'/receiver-seals.json','wire_keys'=>$directory.'/wire.json','checkpoint_database'=>$directory.'/checkpoint.sqlite','checkpoint_lock'=>$directory.'/checkpoint.lock'];
    $senderFile=nativePrivate($directory.'/sender.json',$senderConfig);$receiverFile=nativePrivate($directory.'/receiver.json',$receiverConfig);
    putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$senderFile);$s=Adapter\settings('sender');Check::same(8192,$s['policy']['maximum_payload_bytes']);Check::same(1000,$s['transport_budget_ms']);Check::same(true,Adapter\principal($s,'orders_writer'));
    Check::throws(SecurityException::class,static function()use($s):void{Adapter\produce($s,'native-before-init-001','initial',500);});Check::same(0,(int)$sender->query('SELECT COUNT(*) FROM outbox_example_orders')->fetchColumn());
    Check::same(true,Adapter\outbox($s)->initialize(Adapter\SCOPE,Adapter\PRODUCER,'alice'));Check::same(true,Adapter\idempotency($s)->initialize(Adapter\SCOPE,'alice','orders.create'));
    $result=Adapter\produce($s,'native-request-key-001','one',500);Check::same(false,$result['replayed']);$repeated=Adapter\produce($s,'native-request-key-001','one',500);Check::same(true,$repeated['replayed']);Check::same($result['result'],$repeated['result']);Check::same($result['result'],Adapter\produce($s,'native-request-key-002','one',500)['result']);
    Check::same(1,(int)$sender->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());Check::same(1,(int)$sender->query('SELECT COUNT(*) FROM outbox_example_orders')->fetchColumn());
    Check::throws(SecurityException::class,static function()use($s):void{Adapter\produce($s,'native-request-key-003','one',501);});Check::same(1,(int)$sender->query('SELECT COUNT(*) FROM outbox_example_orders')->fetchColumn());
    $event=$result['result']['event_id'];$row=$sender->query('SELECT delivery_id,payload_body FROM sosecurity_outbox_records')->fetch(PDO::FETCH_ASSOC);$body=$row['payload_body'];$delivery=$row['delivery_id'];
    Check::same($event,Adapter\event($body)['event_id']);
    foreach([str_replace('"amount":500','"amount":500,"amount":500',$body),str_repeat('x',8193),"\0".$body] as $bad){Check::throws(ValidationException::class,static function()use($bad):void{Adapter\event($bad);});}
    putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$receiverFile);$r=Adapter\settings('receiver',$directory.'/web');Check::same(true,Adapter\receiverInitialize($r));$request=nativeRequest($body,$delivery,$directory.'/wire.json');
    Check::throws(SecurityException::class,static function()use($r,$request):void{Adapter\receive($r,$request,static function():bool{return false;});});Check::same(0,(int)$receiver->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn());
    $guard=static function():bool{return true;};$confirmation=Adapter\receive($r,$request,$guard);Check::same(['committed'=>true,'delivery_id'=>$delivery,'body_digest'=>hash('sha256',$body)],$confirmation);Check::same($confirmation,Adapter\receive($r,$request,$guard));Check::same(1,(int)$receiver->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn());
    $receiver->exec('DELETE FROM sosecurity_webhook_processing');$receiver->exec('DELETE FROM sosecurity_webhook_inbox');Check::same($confirmation,Adapter\receive($r,$request,$guard));Check::same(1,(int)$receiver->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn());
    Check::throws(SecurityException::class,static function()use($r,$body,$directory,$guard):void{Adapter\receive($r,nativeRequest($body,str_repeat('a',64),$directory.'/wire.json'),$guard);});Check::same(1,(int)$receiver->query('SELECT COUNT(*) FROM outbox_example_effects')->fetchColumn());
    Check::throws(SecurityException::class,static function()use($r,$body,$delivery,$directory,$guard):void{Adapter\receive($r,nativeRequest($body,$delivery,$directory.'/wire.json',time()-1000),$guard);});
    $receiver->exec('UPDATE outbox_example_owners SET enabled=0');Check::throws(SecurityException::class,static function()use($r,$request,$guard):void{Adapter\receive($r,$request,$guard);});$receiver->exec('UPDATE outbox_example_owners SET enabled=1');
    $receiver->exec("UPDATE outbox_example_routes SET tenant='other'");Check::throws(SecurityException::class,static function()use($r,$request,$guard):void{Adapter\receive($r,$request,$guard);});$receiver->exec("UPDATE outbox_example_routes SET tenant='outbox-example'");
    $receiver->exec('UPDATE outbox_example_actors SET enabled=0');Check::throws(SecurityException::class,static function()use($r,$request,$guard):void{Adapter\receive($r,$request,$guard);});$receiver->exec('UPDATE outbox_example_actors SET enabled=1');
    $newKeys=['current'=>'new','keys'=>['old'=>base64_encode(str_repeat('w',32)),'new'=>base64_encode(str_repeat('n',32))]];nativePrivate($directory.'/wire.json',$newKeys);Check::same($confirmation,Adapter\receive($r,nativeRequest($body,$delivery,$directory.'/wire.json'),$guard));
    unset($newKeys['keys']['old']);nativePrivate($directory.'/wire.json',$newKeys);Check::throws(SecurityException::class,static function()use($r,$request,$guard):void{Adapter\receive($r,$request,$guard);});Check::same(1,(int)$receiver->query('SELECT COUNT(*) FROM outbox_example_effects')->fetchColumn());
    // Current business fields must match the immutable event, rather than trusting just a stored body blob.
    $sender->exec('UPDATE outbox_example_orders SET amount=999');Check::same(null,Adapter\order($s,$event));Check::throws(SecurityException::class,static function()use($s):void{Adapter\outbox($s)->claim(Adapter\SCOPE,Adapter\PRODUCER,'alice');});$sender->exec('UPDATE outbox_example_orders SET amount=500');
    foreach(["version='2'","enabled=0","roles='[\"reader\"]'","roles='[\"orders_writer\",{}]'", "roles=CAST(zeroblob(16777216) AS TEXT)"] as $change){$sender->exec('UPDATE outbox_example_actors SET '.$change);Check::same(false,Adapter\principal($s,'orders_writer'));}
    $sender->exec("UPDATE outbox_example_actors SET version='1',enabled=1,roles='[\"orders_writer\",\"outbox_worker\",\"outbox_admin\"]'");
    foreach([['epoch'=>'wrong'],['url'=>'http://receiver.example.com/outbox-receiver.php'],['url'=>'https://127.0.0.1/outbox-receiver.php'],['url'=>'https://receiver.example.com/outbox-receiver.php#fragment'],['database'=>$directory.'/missing.sqlite'],['document_root'=>$directory.'/missing'],['unknown'=>true],['policy'=>['maximum_payload_bytes'=>8193]],['seals'=>$directory.'/wire.json'],['transport_budget_ms'=>99],['transport_budget_ms'=>10001],['transport_budget_ms'=>'3000'],['transport_budget_ms'=>null]] as $change){
        nativePrivate($senderFile,array_replace($senderConfig,$change));putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$senderFile);Check::throws(Throwable::class,static function():void{Adapter\settings('sender');});
    }
    foreach([100,3000,10000] as $budget){nativePrivate($senderFile,array_replace($senderConfig,['transport_budget_ms'=>$budget]));putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$senderFile);Check::same($budget,Adapter\settings('sender')['transport_budget_ms']);}
    nativePrivate($senderFile,$senderConfig);putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$senderFile);chmod($senderFile,0644);Check::throws(Throwable::class,static function():void{Adapter\settings('sender');});chmod($senderFile,0600);
    nativePrivate($directory.'/different-path-same-key.json',json_decode(file_get_contents($directory.'/wire.json'),true));nativePrivate($senderFile,array_replace($senderConfig,['seals'=>$directory.'/different-path-same-key.json']));Check::throws(Throwable::class,static function():void{Adapter\settings('sender');});
    Check::same(false,is_file($directory.'/missing.sqlite'));Check::same(1,(int)$receiver->query('SELECT SUM(deliveries) FROM outbox_example_projection')->fetchColumn());
}finally{
    if($previous===false){putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');}else{putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$previous);}
    $sender=null;$receiver=null;foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $path){if($path->isDir()){rmdir($path->getPathname());}else{unlink($path->getPathname());}}rmdir($directory);
}
echo 'PASS native Outbox adapters: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; inert imports, private configuration, transactional produce, current authority and independent receiver deduplication\n";
