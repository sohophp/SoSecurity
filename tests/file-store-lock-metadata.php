<?php
declare(strict_types=1);
namespace SoSecurity\Storage {
 function fstat($handle){
  $stat=\fstat($handle);$target=$GLOBALS['owned_lock_metadata']??null;
  if($target!==null&&(stream_get_meta_data($handle)['uri']??null)===$target['lock']){
   unset($GLOBALS['owned_lock_metadata']);$wait=0;while(time()===$stat['ctime']&&++$wait<2000){usleep(1000);}if(time()<=$stat['ctime']){throw new \RuntimeException('Owned metadata clock unavailable');}
   $pipes=[];$command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__FILE__).' --worker '.escapeshellarg($target['directory']);$child=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($child)){throw new \RuntimeException('Cannot start owned metadata writer');}fclose($pipes[0]);$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($child)!==0||$out!=='done'||$err!==''){throw new \RuntimeException('Owned metadata writer failed: '.$err);}
  }
  return $stat;
 }
}
namespace {
 require __DIR__.'/bootstrap.php';
 use SoSecurity\Storage\FileStore;
 use SoSecurity\Storage\Change;
 if(($argv[1]??'')==='--worker'){$directory=$argv[2]??'';if(!preg_match('~\A/tmp/sosecurity-test-[a-f0-9]{16}\z~D',$directory)||is_link($directory)||!is_file($directory.'/owned-metadata')){throw new RuntimeException('Use an owned metadata directory');}$store=new FileStore($directory,'owned-metadata',new TestClock(),500);$store->transact('key',static function($state):Change{return new Change(['count'=>($state['count']??0)+1],0,null);});echo 'done';exit(0);}
 $directory=privateDirectory();
 try{
  file_put_contents($directory.'/owned-metadata','Owned metadata writers only');$hash=hash('sha256',"owned-metadata\0key");$lock=$directory.'/lock-'.(hexdec(substr($hash,0,2))%64);file_put_contents($lock,'');chmod($lock,0600);
  $GLOBALS['owned_lock_metadata']=['lock'=>$lock,'directory'=>$directory];$store=new FileStore($directory,'owned-metadata',new TestClock(),500);$count=$store->transact('key',static function($state):Change{$next=$state['count']+1;return new Change(['count'=>$next],0,$next);});Check::same(2,$count);Check::same(false,isset($GLOBALS['owned_lock_metadata']));
 }finally{unset($GLOBALS['owned_lock_metadata']);cleanDirectory($directory);}
 echo 'PASS file store lock metadata interleaved real SDK writer '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}
