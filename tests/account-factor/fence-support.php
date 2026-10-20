<?php
declare(strict_types=1);
require_once dirname(__DIR__,2).'/vendor/autoload.php';
require_once dirname(__DIR__,2).'/tests/bootstrap.php';

function fencePersist($handle):bool
{
    if(function_exists('fsync')){return fsync($handle);}
    // PHP 7.2 has no fsync(): the owned child receives the SAME open inode on fd 3.
    $pipes=[];$p=proc_open('python3 -c '.escapeshellarg('import os; os.fsync(3)'),[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w'],3=>$handle],$pipes);
    if(!is_resource($p)){throw new RuntimeException('No test persistence helper.');}
    fclose($pipes[0]);$out=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    if(proc_close($p)!==0){throw new RuntimeException('Test fsync failed: '.$out.$error);}return true;
}
function fence(string $directory,?callable $persist=null,?SoSecurity\Support\HmacKeys $keys=null):SoSecurity\Account\LocalEpochFence
{
    return new SoSecurity\Account\LocalEpochFence($directory,'owned-site','tenant',str_repeat('e',64),$keys ?? new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('k',32)]),$persist ?? 'fencePersist',100);
}
function fenceReason(string $reason,callable $op):void
{
    ++Check::$assertions;
    try{$op();}catch(SoSecurity\Storage\StorageException $e){Check::same($reason,$e->reason());return;}throw new RuntimeException('Expected '.$reason);
}
function fenceCase(callable $op):void
{
    $directory=privateDirectory();try{$op($directory);}finally{cleanDirectory($directory);}
}
function fencePath(string $directory):string
{
    $files=glob($directory.'/*.fence');if(count($files)!==1){throw new RuntimeException('Expected one owned authority.');}return $files[0];
}
function fenceFactors(string $directory):SoSecurity\Mfa\TotpFactors
{
    return new SoSecurity\Mfa\TotpFactors(new SoSecurity\Storage\FileStore($directory.'/factors','owned-fence',new TestClock()),new SoSecurity\Crypto\Cipher('test',['test'=>str_repeat('t',32)],'owned-fence'),'Owned fence',new TestClock());
}
