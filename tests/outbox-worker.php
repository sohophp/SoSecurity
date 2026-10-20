<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';

$config=json_decode(stream_get_contents(STDIN,65536),true,16);
if(!is_array($config)){throw new RuntimeException('Invalid private worker configuration.');}
if(isset($config['body_base64'])){$body=base64_decode($config['body_base64'],true);if(!is_string($body)||base64_encode($body)!==$config['body_base64']){throw new RuntimeException('Invalid private binary body.');}$config['body']=$body;}
if(isset($config['start'])){
    $until=microtime(true)+15;while(!is_file($config['start'])&&microtime(true)<$until){usleep(10000);}
    if(!is_file($config['start'])){throw new RuntimeException('Private worker start barrier timed out.');}
}
$mysql=$config['driver']==='mysql';$clock=new TestClock();$clock->time=$config['time'];
$pdo=new InboxTestConnection($mysql?'mysql:unix_socket='.$config['target'].';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$config['target'],$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>30]);
if($mysql){$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
$service=new SoSecurity\Outbox\SqlOutbox($pdo,'outbox-test',str_repeat('e',64),new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('o',32)]),static function():bool{return true;},new SoSecurity\Outbox\Policy($config['policy']),$clock,static function():bool{return true;});
$messageId=SoSecurity\Outbox\Message::identifier($config['reference'],$config['created']);
$checkpoint=static function(array $data)use($config):void{
    $data['ready']=true;$json=json_encode($data);$temporary=$config['checkpoint'].'.writing';
    if(!is_string($json)||file_put_contents($temporary,$json)!==strlen($json)||!chmod($temporary,0600)||!rename($temporary,$config['checkpoint'])){throw new RuntimeException('Private checkpoint failed.');}
    // The parent owns this child and must kill it. A missing parent cannot leave an infinite test process.
    $until=microtime(true)+30;while(microtime(true)<$until){usleep(100000);}throw new RuntimeException('Private checkpoint was not terminated.');
};
if(isset($config['pause'])&&in_array($config['pause'],['before','after'],true)){
    $hook=static function()use($pdo,$checkpoint,$messageId,$config):void{
        $query=$pdo->prepare('SELECT delivery_id,order_no,status,attempts FROM sosecurity_outbox_records WHERE namespace=:namespace AND message_id=:id');$query->execute(['namespace'=>SoSecurity\Outbox\State::namespace('outbox-test',$config['scope'],$config['producer']),'id'=>$messageId]);$row=$query->fetch(PDO::FETCH_ASSOC);$query->closeCursor();
        $checkpoint(['row'=>$row]);
    };
    if($config['pause']==='before'){$pdo->beforeCommit=$hook;}else{$pdo->afterCommit=$hook;}
}
try{
    if($config['operation']==='append'){
        $message=new SoSecurity\Outbox\Message($config['scope'],$config['producer'],$messageId,'receiver','order.changed',$config['aggregate'],$config['body']);
        $pdo->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
        try{
            $query=$pdo->prepare($mysql?'INSERT INTO outbox_test_business(id) VALUES(:id) ON DUPLICATE KEY UPDATE id=id':'INSERT INTO outbox_test_business(id) VALUES(:id) ON CONFLICT(id) DO NOTHING');
            $query->execute(['id'=>$config['business']]);$query->closeCursor();
            $status=$service->enqueue($message,'alice');$pdo->exec('COMMIT');
        }catch(Throwable $error){try{$pdo->exec('ROLLBACK');}catch(Throwable $ignored){}throw $error;}
        echo json_encode(['status'=>'appended','metadata'=>$status->metadata()]);
    }elseif($config['operation']==='reconcile'){
        $message=new SoSecurity\Outbox\Message($config['scope'],$config['producer'],$messageId,'receiver','order.changed',$config['aggregate'],$config['body']);$outcome=$config['outcome'];$evidence=$config['evidence'];
        $pdo->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
        try{
            $query=$pdo->prepare($mysql?'INSERT INTO outbox_test_decisions VALUES(:id,:fingerprint,:digest,:outcome,:evidence) ON DUPLICATE KEY UPDATE event_id=event_id':'INSERT INTO outbox_test_decisions VALUES(:id,:fingerprint,:digest,:outcome,:evidence) ON CONFLICT(event_id) DO NOTHING');
            $query->execute(['id'=>$messageId,'fingerprint'=>$message->fingerprint(),'digest'=>hash('sha256',$message->body()),'outcome'=>$outcome,'evidence'=>$evidence]);$query->closeCursor();
            $guard=static function(string $phase,array $metadata)use($pdo):bool{
                $query=$pdo->prepare('SELECT 1 FROM outbox_test_decisions WHERE event_id=:id AND fingerprint=:fingerprint AND body_digest=:digest AND outcome=:outcome AND evidence=:evidence');$query->execute(['id'=>$metadata['id'],'fingerprint'=>$metadata['fingerprint'],'digest'=>$metadata['payload_digest'],'outcome'=>$metadata['outcome'],'evidence'=>$metadata['evidence_digest']]);$found=$query->fetchColumn()!==false;$query->closeCursor();return $found;
            };
            $changed=$service->reconcile($message,'admin',$outcome,$evidence,$guard);$pdo->exec('COMMIT');
        }catch(Throwable $error){try{$pdo->exec('ROLLBACK');}catch(Throwable $ignored){}throw $error;}
        echo json_encode(['status'=>$changed?'resolved':'already_resolved','outcome'=>$outcome]);
    }elseif($config['operation']==='claim'){
        $claim=isset($config['targeted'])?$service->claimMessage($config['scope'],$config['producer'],$config['worker'],$messageId):$service->claim($config['scope'],$config['producer'],$config['worker']);
        $result=$claim===null?['status'=>'empty']:['status'=>'claimed','worker'=>$config['worker'],'token'=>$claim->token(),'metadata'=>$claim->status()->metadata(),'body_digest'=>hash('sha256',$claim->message()->body())];
        if(($config['pause'] ?? '')==='held'){$checkpoint($result);}echo json_encode($result);
    }elseif($config['operation']==='acknowledge'||$config['operation']==='fail'){
        $accepted=$config['operation']==='acknowledge'?$service->acknowledge($config['scope'],$config['producer'],$config['worker'],$config['token']):$service->fail($config['scope'],$config['producer'],$config['worker'],$config['token'],'transport.timeout');
        echo json_encode(['status'=>$accepted?'accepted':'denied']);
    }elseif($config['operation']==='maintain'){
        echo json_encode(['status'=>'maintained','result'=>$service->maintain($config['scope'],$config['producer'],'admin',1)]);
    }else{throw new RuntimeException('Unknown private Outbox operation.');}
}catch(SoSecurity\Exception\SecurityException $error){echo json_encode(['status'=>$error->reason()]);}
