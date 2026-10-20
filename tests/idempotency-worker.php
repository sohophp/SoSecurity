<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
$config=json_decode(stream_get_contents(STDIN),true);$mysql=$config['driver']==='mysql';$clock=new TestClock();$clock->time=$config['time'];
$pdo=new InboxTestConnection($mysql?'mysql:unix_socket='.$config['target'].';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$config['target'],$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>10]);if($mysql){$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
$service=new SoSecurity\Idempotency\SqlExecutor($pdo,'idem-test',str_repeat('e',64),new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('i',32)]),static function():bool{return true;},new SoSecurity\Idempotency\Policy($config['policy']),$clock);
$request=new SoSecurity\Idempotency\Request($config['scope'],$config['subject'],'orders.create',$config['key'],'POST','/orders',json_encode(['reference'=>$config['reference'],'amount'=>5]),['content_type'=>'application/json']);
$checkpoint=static function()use($config):void{if(file_put_contents($config['checkpoint'],'ready')!==5||!chmod($config['checkpoint'],0600)){throw new RuntimeException('Checkpoint failed.');}while(true){usleep(100000);}};
if($config['operation']==='crash-before'){$pdo->beforeCommit=$checkpoint;}elseif($config['operation']==='crash-after'){$pdo->afterCommit=$checkpoint;}
try{
    $result=$service->execute($request,static function(PDO $pdo,SoSecurity\Idempotency\Request $request,string $execution):SoSecurity\Idempotency\Response{$body=json_decode($request->body(),true);$q=$pdo->prepare('INSERT INTO idempotency_test_business VALUES(:tenant,:subject,:reference,:execution,:amount)');$q->execute(['tenant'=>$request->scope(),'subject'=>$request->subject(),'reference'=>$body['reference'],'execution'=>$execution,'amount'=>5]);return new SoSecurity\Idempotency\Response(201,json_encode(['execution'=>$execution,'reference'=>$body['reference']]));});
    echo json_encode(['status'=>$result->replayed()?'replayed':'executed','execution'=>$result->executionId(),'body'=>$result->response()->body()]);
}catch(SoSecurity\Exception\SecurityException $error){echo json_encode(['status'=>$error->reason()]);}
