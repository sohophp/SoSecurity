<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';require __DIR__.'/outbox-concurrency-support.php';
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy;
use SoSecurity\Outbox\State;

function outboxProducerCount(PDO $pdo,string $scope,string $producer,?string $status=null):int
{
    $query=$pdo->prepare('SELECT COUNT(*) FROM sosecurity_outbox_records WHERE namespace=:namespace'.($status===null?'':' AND status=:status'));
    $values=['namespace'=>State::namespace('outbox-test',$scope,$producer)];if($status!==null){$values['status']=$status;}
    $query->execute($values);$count=(int)$query->fetchColumn();$query->closeCursor();return $count;
}
function outboxBusinessCount(PDO $pdo,int $id):int
{
    $query=$pdo->prepare('SELECT COUNT(*) FROM outbox_test_business WHERE id=:id');$query->execute(['id'=>$id]);$count=(int)$query->fetchColumn();$query->closeCursor();return $count;
}
function outboxStored(PDO $pdo,array $config):?array
{
    $query=$pdo->prepare('SELECT delivery_id,order_no,status,attempts,length(payload_body) AS bytes FROM sosecurity_outbox_records WHERE namespace=:namespace AND message_id=:id');
    $query->execute(['namespace'=>State::namespace('outbox-test',$config['scope'],$config['producer']),'id'=>Message::identifier($config['reference'],$config['created'])]);$row=$query->fetch(PDO::FETCH_ASSOC);$query->closeCursor();
    if($row===false){return null;}foreach(['order_no','attempts','bytes'] as $field){$row[$field]=(int)$row[$field];}return $row;
}
function outboxOutcomes(array $results,string $status,int $count):void
{
    $counts=array_count_values(array_column($results,'status'));Check::same($count,$counts[$status] ?? 0);
}

$mysql=($argv[1] ?? '')==='mysql';$policy=new Policy(['maximum_entries'=>24,'lease_seconds'=>2,'io_milliseconds'=>30000]);
$e=new OutboxEnvironment($mysql,$policy);$directory=privateDirectory();
try{
    $service=$e->service();$service->initialize('tenant','orders','admin');
    $base=['driver'=>$mysql?'mysql':'sqlite','target'=>$mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):$e->database,'time'=>$e->clock->time,'created'=>100000,'scope'=>'tenant','producer'=>'orders','reference'=>'event','aggregate'=>'aggregate','body'=>"order\0payload",'business'=>1,'worker'=>'worker','operation'=>'append','policy'=>$policy->options()];
    $distinct=static function(array $config,int $i):array{return array_replace($config,['reference'=>'event-'.$i,'aggregate'=>'aggregate-'.$i,'business'=>$i+1]);};
    // Distinct business rows and intents commit together; repeated work cannot allocate a second event order.
    $appended=outboxParallel($base,$directory,$distinct);outboxOutcomes($appended,'appended',24);
    $orders=array_column(array_column($appended,'metadata'),'order');sort($orders);Check::same(range(1,24),$orders);
    $deliveries=array_column(array_column($appended,'metadata'),'delivery_id');Check::same(24,count(array_unique($deliveries)));Check::same(24,$e->business(true));Check::same(24,$e->count(true));
    $duplicates=outboxParallel($base,$directory,$distinct);outboxOutcomes($duplicates,'appended',24);
    Check::same(array_column($appended,'metadata'),array_column($duplicates,'metadata'));Check::same(24,$e->business(true));Check::same(24,$e->count(true));
    $conflicts=outboxParallel(array_replace($base,['body'=>'conflicting payload']),$directory,$distinct);outboxOutcomes($conflicts,'outbox.conflict',24);Check::same(24,$e->business(true));Check::same(24,$e->count(true));

    // Twenty-four workers get distinct claims. Acknowledgements remain bound to the actual claiming worker.
    $claimConfig=array_replace($base,['operation'=>'claim']);
    $claims=outboxParallel($claimConfig,$directory,static function(array $config,int $i):array{return array_replace($config,['worker'=>'worker-'.$i]);});
    outboxOutcomes($claims,'claimed',24);Check::same(24,count(array_unique(array_column($claims,'token'))));
    $claimedDeliveries=array_column(array_column($claims,'metadata'),'delivery_id');sort($claimedDeliveries);sort($deliveries);Check::same($deliveries,$claimedDeliveries);
    Check::same([1],array_values(array_unique(array_column(array_column($claims,'metadata'),'attempts'))));
    Check::same([hash('sha256',$base['body'])],array_values(array_unique(array_column($claims,'body_digest'))));Check::same(24,outboxProducerCount($e->observer,'tenant','orders','leased'));
    $wrong=outboxParallel(array_replace($base,['operation'=>'acknowledge']),$directory,static function(array $config,int $i)use($claims):array{return array_replace($config,['token'=>$claims[$i]['token'],'worker'=>'wrong-worker']);});outboxOutcomes($wrong,'denied',24);Check::same(24,outboxProducerCount($e->observer,'tenant','orders','leased'));
    $acknowledge=static function(array $config,int $i)use($claims):array{return array_replace($config,['token'=>$claims[$i]['token'],'worker'=>$claims[$i]['worker']]);};
    $done=outboxParallel(array_replace($base,['operation'=>'acknowledge']),$directory,$acknowledge);outboxOutcomes($done,'accepted',24);Check::same(24,outboxProducerCount($e->observer,'tenant','orders','sent'));
    $again=outboxParallel(array_replace($base,['operation'=>'acknowledge']),$directory,$acknowledge);outboxOutcomes($again,'accepted',24);
    Check::same(null,$service->claim('tenant','orders','idle-worker'));Check::same(0,(int)$e->observer->query("SELECT COALESCE(SUM(length(payload_body)),0) FROM sosecurity_outbox_records WHERE status='sent'")->fetchColumn());

    // Same event races are serialized by business uniqueness and the Outbox namespace root.
    $service->initialize('tenant','single','admin');$single=array_replace($base,['producer'=>'single','reference'=>'shared-event','business'=>1001]);
    $results=outboxParallel($single,$directory);outboxOutcomes($results,'appended',24);Check::same(1,count(array_unique(array_column(array_column($results,'metadata'),'delivery_id'))));Check::same(1,outboxProducerCount($e->observer,'tenant','single'));Check::same(1,outboxBusinessCount($e->observer,1001));
    $contenders=outboxParallel(array_replace($single,['operation'=>'claim','targeted'=>true]),$directory,static function(array $config,int $i):array{return array_replace($config,['worker'=>'contender-'.$i]);});outboxOutcomes($contenders,'claimed',1);outboxOutcomes($contenders,'empty',23);
    $singleClaim=array_values(array_filter($contenders,static function(array $value):bool{return $value['status']==='claimed';}))[0];
    Check::same($results[0]['metadata']['delivery_id'],$singleClaim['metadata']['delivery_id']);
    $service->initialize('other','single','admin');$other=outboxWorkerResult(array_replace($single,['scope'=>'other','business'=>1002]));Check::same('appended',$other['status']);Check::same(false,$other['metadata']['delivery_id']===$singleClaim['metadata']['delivery_id']);

    // One aggregate permits only its earliest unsent event, despite 24 eligible rows and workers.
    $service->initialize('tenant','sequence','admin');$sequence=array_replace($base,['producer'=>'sequence','aggregate'=>'same-aggregate']);
    outboxOutcomes(outboxParallel($sequence,$directory,static function(array $config,int $i):array{return array_replace($config,['reference'=>'sequence-'.$i,'business'=>2000+$i]);}),'appended',24);
    $sequenceClaims=outboxParallel(array_replace($sequence,['operation'=>'claim']),$directory,static function(array $config,int $i):array{return array_replace($config,['worker'=>'sequence-worker-'.$i]);});outboxOutcomes($sequenceClaims,'claimed',1);outboxOutcomes($sequenceClaims,'empty',23);
    $first=array_values(array_filter($sequenceClaims,static function(array $value):bool{return $value['status']==='claimed';}))[0];Check::same(1,$first['metadata']['order']);
    Check::same(true,$service->acknowledge('tenant','sequence',$first['worker'],$first['token']));$second=$service->claim('tenant','sequence','second-worker');Check::same(2,$second->status()->order());Check::same(null,$service->claim('tenant','sequence','third-worker'));

    // Capacity refusal must roll back the business row that preceded enqueue in the host transaction.
    $capacityPolicy=new Policy(['maximum_entries'=>6,'lease_seconds'=>2,'io_milliseconds'=>30000]);$capacityService=$e->service(null,null,null,null,null,$capacityPolicy);$capacityService->initialize('tenant','capacity','admin');
    $capacity=array_replace($base,['producer'=>'capacity','policy'=>$capacityPolicy->options()]);$capacityResults=outboxParallel($capacity,$directory,static function(array $config,int $i):array{return array_replace($config,['reference'=>'capacity-'.$i,'aggregate'=>'capacity-'.$i,'business'=>3000+$i]);});
    outboxOutcomes($capacityResults,'appended',6);outboxOutcomes($capacityResults,'outbox.capacity',18);Check::same(6,outboxProducerCount($e->observer,'tenant','capacity'));
    Check::same(6,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_business WHERE id>=3000 AND id<3024')->fetchColumn());
    $capacityOrders=array_column(array_column(array_values(array_filter($capacityResults,static function(array $value):bool{return $value['status']==='appended';})),'metadata'),'order');sort($capacityOrders);Check::same(range(1,6),$capacityOrders);

    // Only one of 24 failure reports schedules the next attempt. Repeats cannot move the backoff deadline.
    $service->initialize('tenant','retry','admin');$retry=array_replace($base,['producer'=>'retry','reference'=>'retry-event','business'=>4000]);Check::same('appended',outboxWorkerResult($retry)['status']);
    $retryClaim=outboxWorkerResult(array_replace($retry,['operation'=>'claim']));Check::same('claimed',$retryClaim['status']);
    $failures=outboxParallel(array_replace($retry,['operation'=>'fail','token'=>$retryClaim['token']]),$directory);outboxOutcomes($failures,'accepted',1);outboxOutcomes($failures,'denied',23);
    $retryStatus=$service->status('tenant','retry',Message::identifier($retry['reference'],$retry['created']),'alice');Check::same('pending',$retryStatus->state());Check::same(1,$retryStatus->attempts());Check::same(100005,$retryStatus->availableAt());

    // Kill host transactions on both sides of the actual COMMIT. Inspect with a different PDO while paused.
    foreach(['before','after'] as $index=>$position){
        $producer='append-crash-'.$position;$service->initialize('tenant',$producer,'admin');
        $crash=array_replace($base,['producer'=>$producer,'reference'=>'append-crash-'.$position,'business'=>5000+$index,'time'=>$e->clock->time,'pause'=>$position,'checkpoint'=>$directory.'/'.$producer]);
        $checkpoint=outboxKillAt($crash,static function(array $data)use($e,$crash,$position):void{
            Check::same(true,$data['ready']);Check::same($position==='after'?1:0,outboxBusinessCount($e->observer,$crash['business']));Check::same($position==='after'?1:0,outboxProducerCount($e->observer,'tenant',$crash['producer']));
        });
        Check::same($position==='after'?1:0,outboxBusinessCount($e->observer,$crash['business']));Check::same($position==='after'?1:0,outboxProducerCount($e->observer,'tenant',$producer));
        ++$e->clock->time;$restart=$crash;unset($restart['pause'],$restart['checkpoint']);$restart['time']=$e->clock->time;
        $recovered=outboxWorkerResult($restart);Check::same('appended',$recovered['status']);Check::same($checkpoint['row']['delivery_id'],$recovered['metadata']['delivery_id']);Check::same(1,$recovered['metadata']['order']);
        $repeated=outboxWorkerResult($restart);Check::same($recovered,$repeated);Check::same(1,outboxBusinessCount($e->observer,$crash['business']));Check::same(1,outboxProducerCount($e->observer,'tenant',$producer));
    }

    // A killed uncommitted claim rolls back; a committed held claim remains leased until real stored expiry.
    foreach(['before','held'] as $index=>$position){
        $producer='claim-crash-'.$position;$service->initialize('tenant',$producer,'admin');
        $entry=array_replace($base,['producer'=>$producer,'reference'=>$producer,'business'=>6000+$index,'time'=>$e->clock->time]);$appended=outboxWorkerResult($entry);Check::same('appended',$appended['status']);
        $crash=array_replace($entry,['operation'=>'claim','worker'=>'killed-worker','pause'=>$position,'checkpoint'=>$directory.'/'.$producer]);
        $checkpoint=outboxKillAt($crash,static function(array $data)use($e,$crash,$position):void{
            Check::same(true,$data['ready']);$stored=outboxStored($e->observer,$crash);Check::same($position==='held'?'leased':'pending',$stored['status']);Check::same($position==='held'?1:0,$stored['attempts']);
        });
        $next=array_replace($entry,['operation'=>'claim','worker'=>'recovered-worker']);
        if($position==='held'){
            Check::same('empty',outboxWorkerResult($next)['status']);$e->clock->time+=$policy->leaseSeconds()+1;$next['time']=$e->clock->time;
        }
        $recovered=outboxWorkerResult($next);Check::same('claimed',$recovered['status']);Check::same($position==='held'?2:1,$recovered['metadata']['attempts']);Check::same($appended['metadata']['delivery_id'],$recovered['metadata']['delivery_id']);
        if($position==='held'){
            Check::same(false,$checkpoint['token']===$recovered['token']);
            $stale=array_replace($next,['operation'=>'acknowledge','worker'=>'killed-worker','token'=>$checkpoint['token']]);Check::same('denied',outboxWorkerResult($stale)['status']);$stale['operation']='fail';Check::same('denied',outboxWorkerResult($stale)['status']);
        }
        Check::same('accepted',outboxWorkerResult(array_replace($next,['operation'=>'acknowledge','token'=>$recovered['token']]))['status']);
    }

    // Acknowledgement loss is recoverable on either side of its own transaction commit.
    foreach(['before','after'] as $index=>$position){
        $producer='ack-crash-'.$position;$service->initialize('tenant',$producer,'admin');
        $entry=array_replace($base,['producer'=>$producer,'reference'=>$producer,'business'=>7000+$index,'time'=>$e->clock->time]);Check::same('appended',outboxWorkerResult($entry)['status']);
        $claim=outboxWorkerResult(array_replace($entry,['operation'=>'claim']));Check::same('claimed',$claim['status']);
        $crash=array_replace($entry,['operation'=>'acknowledge','token'=>$claim['token'],'pause'=>$position,'checkpoint'=>$directory.'/'.$producer]);
        outboxKillAt($crash,static function(array $data)use($e,$crash,$position):void{
            Check::same('sent',$data['row']['status']);$stored=outboxStored($e->observer,$crash);Check::same($position==='after'?'sent':'leased',$stored['status']);Check::same($position==='after'?0:strlen($crash['body']),$stored['bytes']);
        });
        unset($crash['pause'],$crash['checkpoint']);Check::same('accepted',outboxWorkerResult($crash)['status']);Check::same('accepted',outboxWorkerResult($crash)['status']);
        $stored=outboxStored($e->observer,$crash);Check::same('sent',$stored['status']);Check::same(0,$stored['bytes']);Check::same(1,$stored['attempts']);
    }

    // Concurrent GC never resets order allocation or makes old business-event IDs admissible again.
    $e->clock->time=100000+$policy->messageAge();$maintenance=array_replace($base,['operation'=>'maintain','time'=>$e->clock->time]);$pages=outboxParallel($maintenance,$directory);outboxOutcomes($pages,'maintained',24);
    Check::same(24,array_sum(array_column(array_column($pages,'result'),'purged')));Check::same(0,outboxProducerCount($e->observer,'tenant','orders'));Check::same(24,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_business WHERE id>=1 AND id<=24')->fetchColumn());
    $old=array_replace($base,['reference'=>'event-0','aggregate'=>'aggregate-0','business'=>1,'time'=>$e->clock->time]);Check::same('outbox.expired',outboxWorkerResult($old)['status']);Check::same(0,outboxProducerCount($e->observer,'tenant','orders'));
    $new=array_replace($base,['reference'=>'new-after-gc','business'=>9000,'time'=>$e->clock->time,'created'=>$e->clock->time]);$result=outboxWorkerResult($new);Check::same('appended',$result['status']);Check::same(25,$result['metadata']['order']);Check::same(1,outboxProducerCount($e->observer,'tenant','orders'));
}finally{cleanDirectory($directory);$e->close();}
echo 'PASS SQL outbox concurrency: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; 24 real processes, namespace/capacity/order/retry/GC and SIGKILL at host/claim/ack boundaries; no network delivery\n";
