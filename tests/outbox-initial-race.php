<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
outboxCase(false,static function(OutboxEnvironment $e):void{
 $queue=$e->service();$queue->initialize('tenant','orders','admin');$message=$e->message();$e->append($queue,$message);file_put_contents($e->directory.'/initial-claim-owner','owned workers');$jobs=[];$wins=0;
 try{
  for($i=0;$i<4;++$i){$process=proc_open('exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/outbox-initial-worker.php'),[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start initial claim worker');}$jobs[]=[$process,$pipes];$data=json_encode(['directory'=>$e->directory,'id'=>$message->id(),'worker'=>'worker-'.$i]);if(fwrite($pipes[0],$data)!==strlen($data)){throw new RuntimeException('Worker input incomplete');}fclose($pipes[0]);}
  foreach($jobs as &$job){list($process,$pipes)=$job;$output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);$job=null;Check::same(0,$exit);Check::same('',$error);Check::same(true,in_array($output,['0','1'],true));$wins+=(int)$output;}unset($job);
  Check::same(1,$wins);$rows=$e->rows();Check::same(1,count($rows));Check::same('leased',$rows[0]['status']);Check::same(1,(int)$rows[0]['attempts']);Check::same(1,(int)$rows[0]['generation']);
 }finally{foreach($jobs as $job){if($job===null){continue;}list($process,$pipes)=$job;foreach($pipes as $pipe){if(is_resource($pipe)){fclose($pipe);}}if(is_resource($process)){proc_terminate($process);proc_close($process);}}}
});
echo 'PASS initial claim process race: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
