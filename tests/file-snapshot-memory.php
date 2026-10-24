<?php
declare(strict_types=1);
namespace SoSecurity\Account {
 // Observe real scratch-file creation without replacing the actual filesystem operations.
 function fopen($filename,$mode){
  $probe=$GLOBALS['owned_snapshot_probe']??null;
  if(is_array($probe)&&is_string($filename)&&strpos($filename,$probe['scratch'].'/')===0&&$mode==='x+b'){++$GLOBALS['owned_snapshot_probe']['creates'];}
  return \fopen($filename,$mode);
 }
}
namespace {
 require __DIR__.'/bootstrap.php';
 use SoSecurity\Account\FileStateSnapshot;
 $reference=$argv[1]??null;if($reference!==null){if(!is_string($reference)||!is_file($reference)){throw new RuntimeException('Use the preserved pre-change snapshot implementation');}require $reference;}
 $root=privateDirectory();$source=$root.'/source';$scratch=$root.'/scratch';mkdir($source,0700);mkdir($scratch,0700);$pdo=new PDO('sqlite::memory:');$checks=0;
 try{
  foreach([0,1,2,255,256,257,511,512,4096,4097] as $count){
   foreach(new DirectoryIterator($source) as $entry){if(!$entry->isDot()){unlink($entry->getPathname());}}
   $names=[];for($i=$count-1;$i>=0;--$i){$name=hash('sha256','owned-file-'.$i).'.json';$names[$i]=$name;$data=$i===0?str_repeat("\0x",32768):('owned:'.$i."\0");file_put_contents($source.'/'.$name,$data);chmod($source.'/'.$name,0600);}
   $new=new FileStateSnapshot($pdo,'owned-memory-profile',$source,$scratch,10000,30000);$ordered=array_values($names);sort($ordered,SORT_STRING);$expected=hash_init('sha256');hash_update($expected,'SoSecurity.State.FileSnapshot.1.'.$new->fingerprint());foreach($ordered as $name){hash_update($expected,substr($name,0,64).hash('sha256',file_get_contents($source.'/'.$name),true));}hash_update($expected,':'.$count);$baseline=hash_final($expected);$baselineCreates=null;
   $GLOBALS['owned_snapshot_probe']=['scratch'=>$scratch,'creates'=>0];
   if($reference!==null){$old=new SoSecurity\Account\LegacyFileSnapshot($pdo,'owned-memory-profile',$source,$scratch,10000,30000);Check::same($baseline,$old->digest());$baselineCreates=$GLOBALS['owned_snapshot_probe']['creates'];}
   $GLOBALS['owned_snapshot_probe']['creates']=0;$digest=$new->digest();$actualCreates=$GLOBALS['owned_snapshot_probe']['creates'];
   Check::same($baseline,$digest);Check::same([] ,array_values(array_diff(scandir($scratch),['.','..'])));
   echo 'OBSERVATION snapshot memory '.json_encode(['files'=>$count,'reference_creates'=>$baselineCreates,'current_creates'=>$actualCreates,'digest_matches'=>true]).PHP_EOL;
   if($count<256){Check::same(0,$actualCreates);}elseif($baselineCreates!==null){Check::same($baselineCreates,$actualCreates);}else{Check::same(true,$actualCreates>0);}
   if($count>0){
    $capture=$new->capture(['first'=>$names[0],'last'=>$names[$count-1],'missing'=>str_repeat('f',64).'.json']);Check::same($digest,$capture->digest());Check::same(str_repeat("\0x",32768),$capture->file('first'));Check::same($count===1?str_repeat("\0x",32768):('owned:'.($count-1)."\0"),$capture->file('last'));Check::same(null,$capture->file('missing'));
    $capacity=new FileStateSnapshot($pdo,'owned-capacity-profile',$source,$scratch,$count,30000);Check::same(false,$capacity->canStoreFile(str_repeat('f',64).'.json'));Check::same(true,$capacity->canStoreFile($names[0]));
   }
   Check::same([] ,array_values(array_diff(scandir($scratch),['.','..'])));++$checks;
  }
  Check::same(true,memory_get_peak_usage(true)<8388608);
 }finally{
  unset($GLOBALS['owned_snapshot_probe']);foreach([$source,$scratch] as $dir){foreach(new DirectoryIterator($dir) as $entry){if(!$entry->isDot()){unlink($entry->getPathname());}}rmdir($dir);}rmdir($root);
 }
 echo 'PASS file snapshot memory '.$checks.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}
