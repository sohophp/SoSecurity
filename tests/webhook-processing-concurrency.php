<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$mysql=($argv[1] ?? '')==='mysql';$e=new InboxEnvironment($mysql);$target=$mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):$e->database;
function processingWorker(array $configuration):array
{
    $cmd='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/webhook-processing-worker.php');$process=proc_open($cmd,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,null,['bypass_shell'=>true]);if(!is_resource($process)){throw new RuntimeException('Cannot launch processing worker.');}$input=json_encode($configuration);if(fwrite($pipes[0],$input)!==strlen($input)){throw new RuntimeException('Cannot supply processing fixture.');}fclose($pipes[0]);return [$process,$pipes];
}
function processingResult(array $worker):array
{
    list($process,$pipes)=$worker;$out=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);if($exit!==0||$errors!==''){throw new RuntimeException('Processing worker failed: '.$exit.' '.$errors);}return json_decode($out,true);
}
function processingParallel(array $configuration):array
{
    $workers=[];for($i=0;$i<24;++$i){$workers[]=processingWorker($configuration);}$results=[];$failure=null;foreach($workers as $worker){try{$results[]=processingResult($worker);}catch(Throwable $error){if($failure===null){$failure=$error;}}}if($failure!==null){throw $failure;}return $results;
}
try{
    $e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');$schema=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql');foreach(explode(';',$schema) as $statement){if(trim($statement)!==''){$e->pdo->exec($statement);}}
    $e->pdo->exec('DROP TABLE IF EXISTS webhook_test_effects');$e->pdo->exec('CREATE TABLE webhook_test_effects(receipt_id CHAR(32) NOT NULL PRIMARY KEY,resource_id VARCHAR(64) NOT NULL,version VARCHAR(64) NOT NULL)'.($mysql?' ENGINE=InnoDB':''));
    $id=$e->receive()->id();$config=['driver'=>$mysql?'mysql':'sqlite','target'=>$target,'time'=>100000,'receipt'=>$id,'operation'=>'claim'];
    $results=processingParallel($config);$accepted=array_values(array_filter($results,static function(array $row):bool{return $row['status']==='claimed';}));Check::same(1,count($accepted));$token=$accepted[0]['token'];
    $results=processingParallel(['operation'=>'execute','token'=>$token]+$config);$counts=array_count_values(array_column($results,'status'));Check::same(1,$counts['succeeded'] ?? 0);Check::same(23,$counts['denied'] ?? 0);Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn());
    $results=processingParallel(['operation'=>'execute','token'=>$token]+$config);Check::same(24,array_count_values(array_column($results,'status'))['denied']);Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn());
    $directory=privateDirectory();try{
        foreach(['before','after'] as $position){$e->pdo->exec('DELETE FROM webhook_test_effects');$e->pdo->exec('DELETE FROM sosecurity_webhook_processing');$claim=processingResult(processingWorker($config));Check::same('claimed',$claim['status']);$checkpoint=$directory.'/'.$position;$worker=processingWorker(['operation'=>'crash-'.$position,'token'=>$claim['token'],'checkpoint'=>$checkpoint]+$config);list($process,$pipes)=$worker;
            try{$until=microtime(true)+10;while(!is_file($checkpoint)&&microtime(true)<$until){if(!proc_get_status($process)['running']){throw new RuntimeException('Processing checkpoint exited early.');}usleep(10000);}Check::same(true,is_file($checkpoint));Check::same(true,proc_get_status($process)['running']);Check::same(true,proc_terminate($process,9));}
            finally{foreach([1,2] as $pipe){fclose($pipes[$pipe]);}proc_close($process);}
            $recover=processingResult(processingWorker(['time'=>100002]+$config));Check::same($position==='before'?'claimed':'denied',$recover['status']);
            if($position==='before'){Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn());$done=processingResult(processingWorker(['operation'=>'execute','time'=>100002,'token'=>$recover['token']]+$config));Check::same('succeeded',$done['status']);}
            Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn());$old=processingResult(processingWorker(['operation'=>'execute','time'=>100002,'token'=>$claim['token']]+$config));Check::same('denied',$old['status']);Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_test_effects')->fetchColumn());unlink($checkpoint);
        }
    }finally{rmdir($directory);}
}finally{if($mysql){$e->pdo->exec('DROP TABLE IF EXISTS webhook_test_effects');$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');}$e->close();}
echo 'PASS webhook processing '.($mysql?'MySQL':'SQLite').': '.Check::$assertions." assertions; 24-process claim/transactional completion/replay and SIGKILL before/after commit recovery; local component stage\n";
