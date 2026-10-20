<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/idempotency-support.php';
$mysql=($argv[1] ?? '')==='mysql';$e=new IdempotencyEnvironment($mysql,new SoSecurity\Idempotency\Policy(['maximum_entries'=>6,'io_milliseconds'=>30000]));$directory=privateDirectory();
function idemWorker(array $configuration):array
{
    $cmd='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/idempotency-worker.php');$process=proc_open($cmd,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,null,['bypass_shell'=>true]);if(!is_resource($process)){throw new RuntimeException('Cannot launch idempotency worker.');}$input=json_encode($configuration);if(fwrite($pipes[0],$input)!==strlen($input)){throw new RuntimeException('Cannot supply idempotency test data.');}fclose($pipes[0]);return [$process,$pipes];
}
function idemResult(array $worker):array
{
    list($process,$pipes)=$worker;$out=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);if($exit!==0||$errors!==''){throw new RuntimeException('Idempotency worker failed: '.$exit.' '.$errors);}$result=json_decode($out,true);if(!is_array($result)){throw new RuntimeException('Worker returned invalid JSON.');}return $result;
}
function idemParallel(array $base,?callable $change=null):array
{
    $workers=[];for($i=0;$i<24;++$i){$workers[]=idemWorker($change===null?$base:$change($base,$i));}$results=[];$failure=null;foreach($workers as $worker){try{$results[]=idemResult($worker);}catch(Throwable $error){if($failure===null){$failure=$error;}}}if($failure!==null){throw $failure;}return $results;
}
try{
    $service=$e->service();$service->initialize('tenant','alice','orders.create');$config=['driver'=>$mysql?'mysql':'sqlite','target'=>$mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):$e->database,'time'=>100000,'scope'=>'tenant','subject'=>'alice','key'=>'request-key-00000001','reference'=>'order-1','operation'=>'execute','policy'=>$e->policy->options()];
    $results=idemParallel($config);$counts=array_count_values(array_column($results,'status'));if(($counts['executed'] ?? 0)!==1||($counts['replayed'] ?? 0)!==23){throw new RuntimeException('Parallel idempotency outcomes: '.json_encode($counts));}Check::same(1,$counts['executed']);Check::same(23,$counts['replayed']);Check::same(1,count(array_unique(array_column($results,'execution'))));Check::same(1,count(array_unique(array_column($results,'body'))));Check::same(1,$e->count());
    $results=idemParallel($config);Check::same(24,array_count_values(array_column($results,'status'))['replayed'] ?? 0);Check::same(1,$e->count());
    $results=idemParallel(['reference'=>'different-order']+$config);Check::same(24,array_count_values(array_column($results,'status'))['idempotency.conflict'] ?? 0);Check::same(1,$e->count());
    $service->initialize('tenant','capacity','orders.create');$results=idemParallel(['subject'=>'capacity']+$config,static function(array $base,int $i):array{$base['key']='capacity-key-'.str_pad((string)$i,8,'0',STR_PAD_LEFT);$base['reference']='capacity-'.$i;return $base;});$counts=array_count_values(array_column($results,'status'));Check::same(6,$counts['executed'] ?? 0);Check::same(18,$counts['idempotency.capacity'] ?? 0);Check::same(7,$e->count());
    $service->initialize('other','alice','orders.create');$result=idemResult(idemWorker(['scope'=>'other']+$config));Check::same('executed',$result['status']);Check::same(8,$e->count());
    // Kill real workers after business writes but on both sides of the database commit boundary.
    foreach(['before','after'] as $position){
        $subject='crash-'.$position;$service->initialize('tenant',$subject,'orders.create');$checkpoint=$directory.'/'.$position;$crash=['subject'=>$subject,'operation'=>'crash-'.$position,'checkpoint'=>$checkpoint]+$config;$worker=idemWorker($crash);list($process,$pipes)=$worker;
        try{$until=microtime(true)+15;while(!is_file($checkpoint)&&microtime(true)<$until){if(!proc_get_status($process)['running']){throw new RuntimeException('Idempotency checkpoint exited early.');}usleep(10000);}Check::same(true,is_file($checkpoint));Check::same(true,proc_get_status($process)['running']);Check::same(true,proc_terminate($process,9));}
        finally{foreach([1,2] as $pipe){fclose($pipes[$pipe]);}proc_close($process);}
        $q=$e->pdo->prepare('SELECT COUNT(*) FROM idempotency_test_business WHERE subject=:subject');$q->execute(['subject'=>$subject]);Check::same($position==='before'?'0':'1',(string)$q->fetchColumn());$q->closeCursor();
        $recovered=idemResult(idemWorker(['subject'=>$subject]+$config));Check::same($position==='before'?'executed':'replayed',$recovered['status']);$again=idemResult(idemWorker(['subject'=>$subject]+$config));Check::same('replayed',$again['status']);Check::same($recovered['execution'],$again['execution']);Check::same($recovered['body'],$again['body']);unlink($checkpoint);
    }
    Check::same(10,$e->count());
}finally{foreach(new DirectoryIterator($directory) as $file){if(!$file->isDot()){unlink($file->getPathname());}}rmdir($directory);$e->close();}
echo 'PASS SQL idempotency concurrency: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; 24 processes and real SIGKILL before/after COMMIT\n";
