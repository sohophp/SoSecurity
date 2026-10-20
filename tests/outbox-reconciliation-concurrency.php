<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';require __DIR__.'/outbox-concurrency-support.php';require __DIR__.'/outbox-reconciliation-support.php';
$mysql=($argv[1] ?? '')==='mysql';
function resolutionWorker(OutboxEnvironment $e,string $outcome='received'):array
{
    return ['driver'=>$e->mysql?'mysql':'sqlite','target'=>$e->mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):$e->database,'policy'=>$e->policy->options(),'scope'=>'tenant','producer'=>'orders','reference'=>'retired','created'=>100000,'time'=>$e->clock->time,'aggregate'=>'order-1','body_base64'=>base64_encode("a\0b\xff"),'operation'=>'reconcile','outcome'=>$outcome,'evidence'=>hash('sha256','synthetic-'.$outcome)];
}
resolutionCase($mysql,static function(OutboxEnvironment $e):void{
    list($s,$m)=resolutionRetired($e);$config=resolutionWorker($e);$directory=$e->directory ?? privateDirectory();
    try{$results=outboxParallel($config,$directory);
        Check::same(1,count(array_filter($results,static function(array $row):bool{return $row['status']==='resolved';})));Check::same(23,count(array_filter($results,static function(array $row):bool{return $row['status']==='already_resolved';})));
        Check::same('received',$s->status('tenant','orders',$m->id(),'alice')->resolution());Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
    }finally{if($e->directory===null){cleanDirectory($directory);}}
});
// Opposing terminal decisions serialize on the immutable audit key; the winner cannot be overwritten.
resolutionCase($mysql,static function(OutboxEnvironment $e):void{
    list($s,$m)=resolutionRetired($e);$directory=$e->directory ?? privateDirectory();
    try{$results=outboxParallel(resolutionWorker($e),$directory,static function(array $row,int $index):array{if($index%2===1){$row['outcome']='cancelled';$row['evidence']=hash('sha256','synthetic-cancelled');}return $row;});
        Check::same(1,count(array_filter($results,static function(array $row):bool{return $row['status']==='resolved';})));Check::same(11,count(array_filter($results,static function(array $row):bool{return $row['status']==='already_resolved';})));Check::same(12,count(array_filter($results,static function(array $row):bool{return $row['status']==='outbox.denied';})));
        $outcome=$e->observer->query('SELECT outcome FROM outbox_test_decisions')->fetchColumn();Check::same($outcome,$s->status('tenant','orders',$m->id(),'alice')->resolution());Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
    }finally{if($e->directory===null){cleanDirectory($directory);}}
});
foreach(['before','after'] as $position){resolutionCase($mysql,static function(OutboxEnvironment $e)use($position):void{
    list($s,$m)=resolutionRetired($e);$directory=privateDirectory();$path=$directory.'/checkpoint.json';$config=resolutionWorker($e)+['pause'=>$position,'checkpoint'=>$path];$process=new OutboxTestProcess($config);
    try{
        $until=microtime(true)+12;while(!is_file($path)&&microtime(true)<$until){if(!$process->running()){$process->result();throw new RuntimeException('Resolution child ended before checkpoint.');}usleep(10000);}
        Check::same(true,is_file($path));$marker=json_decode(file_get_contents($path),true);Check::same(true,$marker['ready']);Check::same('resolved',$marker['row']['status']);
        Check::same($position==='before'?'dead':'resolved',$e->observer->query('SELECT status FROM sosecurity_outbox_records')->fetchColumn());Check::same($position==='before'?0:1,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
        Check::same(true,$process->kill());$process->close();$restart=$config;unset($restart['pause'],$restart['checkpoint']);$result=outboxWorkerResult($restart);Check::same($position==='before'?'resolved':'already_resolved',$result['status']);
        Check::same('received',$s->status('tenant','orders',$m->id(),'alice')->resolution());Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM outbox_test_decisions')->fetchColumn());
    }finally{$process->close();cleanDirectory($directory);}
});}
echo 'PASS SQL Outbox reconciliation concurrency: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; 24 real workers, conflicting decisions and SIGKILL around host audit/intent COMMIT\n";
