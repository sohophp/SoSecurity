<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
use SoSecurity\Webhook as W;
$c=json_decode(stream_get_contents(STDIN),true);
if(!is_array($c)||!is_string($c['directory']??null)||strpos($c['directory'],'/tmp/sosecurity-')!==0||!is_dir($c['directory'])||is_link($c['directory'])){throw new RuntimeException('Private native processing test required.');}
$mysql=$c['mysql']===true;
if($mysql){$socket=$c['socket'];if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
elseif(!is_string($c['database'])||strpos($c['database'],'/tmp/sosecurity-')!==0||!is_file($c['database'])){throw new RuntimeException('Private SQLite test required.');}
$pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$c['database'],$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$clock=new TestClock();$endpoint=new W\Endpoint('inbox','tenant','provider-account','https://hooks.example/events','standard-hmac');$keys=new W\KeySet($endpoint,['test'=>str_repeat('k',32)]);$seals=new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('s',32)]);$policy=new W\ProcessingPolicy();
$sql=new A\SqlStateSnapshot($pdo,'owned-webhook-sql',$c['definitions'],30000);$configuration=new A\WebhookStateSnapshot($pdo,'owned-config',$endpoint,$keys,$seals,$policy);$source=new A\CompositeStateSnapshot($pdo,['sql'=>$sql,'configuration'=>$configuration]);
$witnessKeys=new SoSecurity\Support\HmacKeys('witness',['witness'=>str_repeat('w',32)]);$witness=new A\LocalStateWitness($pdo,$c['directory'],'inbox-test-site','tenant',str_repeat('e',64),$witnessKeys,$source,new A\LocalStatePersistence($c['directory'],30000),30000,2);$boundary=new A\StateBoundary($witness,static function():bool{return true;});
$state=new A\StateWebhookConnection($boundary,$witness,$source,$sql,'sql',$configuration,'configuration','inbox-test-site',str_repeat('e',64),$endpoint,$keys,$seals,$policy);
$mapper=static function(string $body):W\Message{$v=json_decode($body,true);return new W\Message($v['id'],$v['type'],$v['resource'],['version'=>$v['version']]);};$allow=static function():bool{return true;};
$processor=new W\SqlProcessor($pdo,'inbox-test-site',$endpoint,$seals,$mapper,$allow,$allow,$policy,$clock,$allow,$state);$claim=$processor->claim($c['receipt'],'worker');$done=null;
if($claim!==null){$done=$processor->execute('worker',$claim->token(),static function(PDO $connection)use($c):bool{$q=$connection->prepare('INSERT INTO webhook_owned_effects VALUES(?)');$q->execute([$c['receipt']]);return true;});}
echo json_encode(['claimed'=>$claim!==null,'status'=>$done===null?null:$done->status()]),PHP_EOL;
