<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\Change;
if(($argv[1]??'')==='--worker'){
 $directory=$argv[2]??'';if(!preg_match('~\A/tmp/sosecurity-test-[a-f0-9]{16}\z~D',$directory)||is_link($directory)||!is_file($directory.'/owned-counter')){throw new RuntimeException('Use the owned counter directory');}
 $store=new FileStore($directory,'owned-counter',new TestClock(),1000);
 for($i=0;$i<50;++$i){$store->transact('count',static function($value):Change{if(!is_array($value)||array_keys($value)!==['count']||!is_int($value['count'])){throw new RuntimeException('Invalid owned counter');}return new Change(['count'=>$value['count']+1],0,null);});}echo 'done';exit(0);
}
$directory=privateDirectory();$processes=[];
try{
 file_put_contents($directory.'/owned-counter','Owned counter processes only');$store=new FileStore($directory,'owned-counter',new TestClock(),1000);$store->transact('count',static function():Change{return new Change(['count'=>0],0,null);});
 $command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__FILE__).' --worker '.escapeshellarg($directory);
 for($i=0;$i<8;++$i){$pipes=[];$process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start owned counter process');}fclose($pipes[0]);$processes[]=[$process,$pipes];}
 foreach($processes as $index=>$entry){list($process,$pipes)=$entry;$stdout=stream_get_contents($pipes[1]);$stderr=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);unset($processes[$index]);Check::same(0,$code);Check::same('',$stderr);Check::same('done',$stdout);}
 Check::same(400,$store->transact('count',static function($value):Change{return new Change($value,0,$value['count']);}));Check::same([],glob($directory.'/.write-*'));
}finally{
 foreach($processes as $entry){list($process,$pipes)=$entry;if(proc_get_status($process)['running']){proc_terminate($process);}fclose($pipes[1]);fclose($pipes[2]);proc_close($process);}cleanDirectory($directory);
}
echo 'PASS file store concurrency 8 processes 400 committed increments '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
