<?php
declare(strict_types=1);
require __DIR__.'/restoration-support.php';
function restorationSpawn(ManagedEnvironment $e,string $mode,array $context):array
{
    if(!function_exists('posix_kill')||!is_dir('/proc')){throw new RuntimeException('This local process test requires POSIX signals and procfs.');}$owner=bin2hex(random_bytes(16));file_put_contents($e->directory.'/restoration-process-owner',$owner);$config=['directory'=>$e->directory,'owner'=>$owner,'time'=>$e->clock->time,'mysql'=>($GLOBALS['argv'][1]??'')==='mysql','backend'=>$GLOBALS['argv'][2]??'file-store','mode'=>$mode,'context'=>$context];$path=$e->directory.'/restoration-'.$mode.'.json';file_put_contents($path,json_encode($config));$pipes=[];$process=proc_open('exec '.escapeshellarg(PHP_BINARY).' -d memory_limit=8M '.escapeshellarg(__DIR__.'/restoration-worker.php').' '.escapeshellarg($path),[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot spawn owned restoration worker.');}fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);$status=proc_get_status($process);return ['process'=>$process,'pipes'=>$pipes,'pid'=>$status['pid'],'owner'=>$owner,'ready'=>$e->directory.'/restoration-'.$mode.'.ready'];
}
function restorationStopped(array $worker):void
{
    $until=microtime(true)+60;do{$status=proc_get_status($worker['process']);if(!$status['running']){throw new RuntimeException('Owned child exited before pause: '.stream_get_contents($worker['pipes'][1]).stream_get_contents($worker['pipes'][2]));}if(is_file($worker['ready'])){$ready=json_decode(file_get_contents($worker['ready']),true);if(is_array($ready)&&$ready['pid']===$worker['pid']&&$ready['owner']===$worker['owner']){$state=@file_get_contents('/proc/'.$worker['pid'].'/status');if(is_string($state)&&preg_match('/^State:\s+[Tt]/m',$state)){return;}}}usleep(1000);}while(microtime(true)<$until);throw new RuntimeException('Owned child pause observation timeout.');
}
function restorationJoin(array &$worker,bool $kill=false):array
{
    $status=proc_get_status($worker['process']);if($kill&&$status['running']){posix_kill($worker['pid'],SIGKILL);}$until=microtime(true)+10;do{$status=proc_get_status($worker['process']);if(!$status['running']){break;}usleep(1000);}while(microtime(true)<$until);if($status['running']){posix_kill($worker['pid'],SIGKILL);throw new RuntimeException('Owned worker did not exit.');}$out=stream_get_contents($worker['pipes'][1]);$err=stream_get_contents($worker['pipes'][2]);fclose($worker['pipes'][1]);fclose($worker['pipes'][2]);$code=proc_close($worker['process']);return ['exit'=>$status['exitcode']>=0?$status['exitcode']:$code,'signal'=>$status['termsig'],'signaled'=>$status['signaled'],'output'=>$out.$err];
}
