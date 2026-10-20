<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
$mysql=($argv[1] ?? '')==='mysql';$e=new InboxEnvironment($mysql);$target=$mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):$e->database;
function inboxWorker(bool $mysql,string $target,string $operation,int $index=0,string $channel=''):array
{
    $command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/webhook-inbox-worker.php').' '.escapeshellarg($mysql?'mysql':'sqlite').' '.escapeshellarg($target).' '.escapeshellarg($operation).' '.$index.' '.escapeshellarg($channel);
    $process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,null,['bypass_shell'=>true]);if(!is_resource($process)){throw new RuntimeException('Cannot launch private inbox worker.');}fclose($pipes[0]);return [$process,$pipes];
}
function inboxResult(array $worker):array
{
    list($process,$pipes)=$worker;$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$status=proc_close($process);if($status!==0||$errors!==''){throw new RuntimeException('Inbox worker failed: '.$status.' '.$errors);}return json_decode($output,true);
}
function inboxParallel(bool $mysql,string $target,string $operation):array
{
    $workers=[];for($index=0;$index<24;++$index){$workers[]=inboxWorker($mysql,$target,$operation,$index);}$results=[];$failure=null;foreach($workers as $worker){try{$results[]=inboxResult($worker);}catch(Throwable $error){if($failure===null){$failure=$error;}}}if($failure!==null){throw $failure;}return $results;
}
try{
    foreach(['duplicate','conflict','sites','invalid'] as $operation){
        $e->pdo->exec('DELETE FROM sosecurity_webhook_inbox');$results=inboxParallel($mysql,$target,$operation);$counts=array_count_values(array_column($results,'status'));
        if($operation==='duplicate'){Check::same(['created'=>1,'duplicate'=>23],['created'=>$counts['created'] ?? 0,'duplicate'=>$counts['duplicate'] ?? 0]);Check::same(1,$e->count());Check::same(1,count(array_unique(array_column($results,'id'))));}
        elseif($operation==='conflict'){Check::same(1,$counts['created'] ?? 0);Check::same(11,$counts['duplicate'] ?? 0);Check::same(12,$counts['conflict'] ?? 0);Check::same(1,$e->count());}
        elseif($operation==='sites'){Check::same(2,$counts['created'] ?? 0);Check::same(22,$counts['duplicate'] ?? 0);Check::same(2,$e->count());Check::same(2,count(array_unique(array_column($results,'id'))));}
        else{Check::same(24,$counts['denied'] ?? 0);Check::same(0,$e->count());}
    }
    // Every duplicate runs in a new PHP process/connection, including a second complete wave after persistence.
    $e->pdo->exec('DELETE FROM sosecurity_webhook_inbox');inboxParallel($mysql,$target,'duplicate');$again=inboxParallel($mysql,$target,'duplicate');Check::same(24,array_count_values(array_column($again,'status'))['duplicate']);Check::same(1,$e->count());
    $directory=privateDirectory();
    try{
        foreach(['before','after'] as $position){
            $e->pdo->exec('DELETE FROM sosecurity_webhook_inbox');$channel=$directory.'/ready-'.$position;$worker=inboxWorker($mysql,$target,'crash-'.$position,0,$channel);list($process,$pipes)=$worker;
            try{
                $until=microtime(true)+5;while(!is_file($channel)&&microtime(true)<$until){$state=proc_get_status($process);if(!$state['running']){throw new RuntimeException('Checkpoint worker exited before termination.');}usleep(10000);}
                Check::same(true,is_file($channel));Check::same(true,proc_get_status($process)['running']);Check::same(true,proc_terminate($process,9));
            }finally{foreach([1,2] as $pipe){fclose($pipes[$pipe]);}proc_close($process);}
            $result=inboxResult(inboxWorker($mysql,$target,'recover-'.$position));Check::same($position==='before'?'created':'duplicate',$result['status']);Check::same(1,$e->count());unlink($channel);
        }
    }finally{rmdir($directory);}
}finally{$e->close();}
echo 'PASS webhook receive '.($mysql?'MySQL':'SQLite').': '.Check::$assertions." assertions; 24-process duplicate/conflict/site/invalid waves, fresh-process persisted duplicates and actual SIGKILL before/after commit recovery; synthetic signed messages only\n";
