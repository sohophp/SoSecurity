<?php
declare(strict_types=1);
namespace SoSecurity\Storage {
 function fopen($filename,$mode,...$args){
  $target=$GLOBALS['owned_file_node_race']??null;
  if($target!==null&&$target===$filename){
   unset($GLOBALS['owned_file_node_race']);if(!unlink($filename)){throw new \RuntimeException('Cannot replace owned node');}
   $pipes=[];$child=proc_open('/usr/bin/mkfifo --mode=600 '.escapeshellarg($filename),[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($child)){throw new \RuntimeException('Cannot create owned FIFO');}foreach($pipes as $pipe){fclose($pipe);}if(proc_close($child)!==0){throw new \RuntimeException('Cannot create owned FIFO');}
  }
  return \fopen($filename,$mode,...$args);
 }
}
namespace {
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
$directory=$argv[1]??'';$operation=$argv[2]??'';
if(!preg_match('~\A/tmp/sosecurity-file-nodes-[A-Za-z0-9_-]+/(?:value|lock|prune)-(?:fifo|race)\z~D',$directory)||!is_dir($directory)||is_link($directory)||!is_file(dirname($directory).'/owned-test')){throw new RuntimeException('Use the owned node test controller');}
$store=new FileStore($directory,'owned-nodes',new TestClock(),500);$calls=0;$reason=null;
if(substr($operation,-5)==='-race'){$hash=hash('sha256',"owned-nodes\0key");$GLOBALS['owned_file_node_race']=$directory.'/'.($operation==='lock-race'?'lock-'.(hexdec(substr($hash,0,2))%64):$hash.'.json');}
try{
 if(in_array($operation,['prune-fifo','prune-race'],true)){$store->pruneBatch(100);}
 elseif(in_array($operation,['value-fifo','lock-fifo','value-race','lock-race'],true)){$store->transact('key',static function($value)use(&$calls):Change{++$calls;return new Change($value,0,null);});}
 else{throw new RuntimeException('Unknown owned node test');}
}catch(StorageException $error){$reason=$error->reason();}
echo 'OBSERVATION file node '.json_encode(['operation'=>$operation,'callback_calls'=>$calls,'reason'=>$reason]).PHP_EOL;
Check::same($operation==='lock-race'?'storage.io':'storage.corrupt',$reason);Check::same(0,$calls);Check::same(false,isset($GLOBALS['owned_file_node_race']));
echo 'PASS file store node '.$operation.' PHP '.PHP_VERSION.PHP_EOL;
}
