<?php
declare(strict_types=1);
// Only standalone read-only scans of this test's ordinary receipt records. No claims or continuations.
function pendingProcessor(InboxEnvironment $e,?callable $guard=null):SoSecurity\Webhook\SqlProcessor
{
 $e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');foreach(explode(';',file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($e->mysql?'mysql':'sqlite').'.sql')) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
 return new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(){throw new RuntimeException('Pending must not map business data');},static function(){throw new RuntimeException('Pending must not invoke business association');},$guard??static function(){return true;},null,$e->clock);
}
function pendingSeed(InboxEnvironment $e,string $status='ready',?int $due=null):array
{
 $source=$e->snapshot()[0];$row=['endpoint_key'=>$source['endpoint_key'],'receipt_id'=>$source['receipt_id'],'event_key'=>$source['event_key'],'body_digest'=>$source['body_digest'],'descriptor'=>$source['descriptor'],'policy'=>(new SoSecurity\Webhook\ProcessingPolicy())->fingerprint(),'status'=>$status,'attempt'=>0,'total_attempts'=>0,'manual_retries'=>0,'revision'=>1,'due_at'=>$due??$e->clock->time,'lease_until'=>0,'claim_digest'=>'','worker_digest'=>'','error_code'=>'','created_at'=>$e->clock->time,'updated_at'=>$e->clock->time,'seal_key'=>'old','seal'=>''];$row=SoSecurity\Webhook\ProcessingState::seal($row,$e->seals);
 $q=$e->pdo->prepare('INSERT INTO sosecurity_webhook_processing('.implode(',',array_keys($row)).') VALUES(:'.implode(',:',array_keys($row)).')');foreach($row as $name=>$value){$q->bindValue(':'.$name,$value,is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR);}$q->execute();$q->closeCursor();return $row;
}
function pendingClone(InboxEnvironment $e,string $id):void
{
 $row=$e->snapshot()[0];$row['event_id']='inert-'.$id;$row['event_key']=hash('sha256',$row['event_id']);$row['receipt_id']=$id;$row['bytes']=strlen($row['payload']);$row=SoSecurity\Webhook\InboxState::seal($row,$e->seals);unset($row['bytes']);
 $q=$e->pdo->prepare('INSERT INTO sosecurity_webhook_inbox('.implode(',',array_keys($row)).') VALUES(:'.implode(',:',array_keys($row)).')');foreach($row as $name=>$value){$q->bindValue(':'.$name,$value,$value===null?PDO::PARAM_NULL:($name==='payload'?PDO::PARAM_LOB:(is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR)));}$q->execute();$q->closeCursor();
}
function pendingClose(InboxEnvironment $e):void{$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');$e->close();}
