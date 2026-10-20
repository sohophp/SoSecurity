<?php
declare(strict_types=1);
// Owned concurrency test writer. Each committed state intentionally lacks one required permission.
if(count($argv)!==4||!in_array($argv[2],['sender','receiver','association'],true)||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$argv[3])){exit(2);}
$pdo=new PDO('sqlite:'.$argv[1],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);$mode=$argv[2];$actor=$argv[3];$q=$pdo->prepare('UPDATE outbox_example_actors SET roles=:roles WHERE subject=:actor');$ready=false;stream_set_blocking(STDIN,false);
while(true){
    $stop=fgets(STDIN);if($stop!==false||feof(STDIN)){break;}
    foreach([0,1] as $step){
        $roles=$mode==='sender'?[$step===0?'outbox_admin':'outbox_reconciler']:($mode==='receiver'?[$step===0?'receiver_admin':'receiver_reconciler']:($step===0?['receiver_worker']:[]));
        $pdo->beginTransaction();try{$q->execute(['roles'=>json_encode($roles),'actor'=>$actor]);$q->closeCursor();if($mode==='association'){$pdo->exec('UPDATE outbox_example_routes SET enabled='.$step);}$pdo->exec('UPDATE authority_test_progress SET revision=revision+1');$pdo->commit();}catch(Throwable $failure){if($pdo->inTransaction()){$pdo->rollBack();}throw $failure;}
        usleep(500);
    }
    if(!$ready){echo json_encode(['pid'=>getmypid(),'mode'=>$mode]),PHP_EOL;flush();$ready=true;}
}
