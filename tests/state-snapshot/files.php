<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$root=privateDirectory();$source=$root.'/state';$scratch=$root.'/scratch';mkdir($source,0700);mkdir($scratch,0700);$pdo=new PDO('sqlite::memory:');
$put=static function(string $name,string $value)use($source):void{file_put_contents($source.'/'.$name,$value);chmod($source.'/'.$name,0600);};
$snapshot=static function(int $limit=100000)use($pdo,$source,$scratch):SoSecurity\Account\FileStateSnapshot{return new SoSecurity\Account\FileStateSnapshot($pdo,'owned-file-profile',$source,$scratch,$limit,30000);};
try{
    $s=$snapshot();$empty=$s->digest();Check::same(64,strlen($empty));Check::same($empty,$s->digest());
    $a=str_repeat('a',64).'.json';$b=str_repeat('b',64).'.json';$put($b,"c\0d");$put($a,"a\0b");$first=$s->digest();Check::same(false,$empty===$first);
    $put($a,"a\0c");Check::same(false,$first===$s->digest());$put($a,"a\0b");Check::same($first,$s->digest());
    unlink($source.'/'.$a);unlink($source.'/'.$b);$put($a,"a\0b");$put($b,"c\0d");Check::same($first,$s->digest());
    $put('lock-0','');$put('lock-63','');Check::same($first,$s->digest());
    $small=$snapshot(1);snapshotReason('account.snapshot_capacity',static function()use($small):void{$small->digest();});Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));
    foreach(['unexpected','.write-abandoned','lock-64'] as $bad){$put($bad,'');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});unlink($source.'/'.$bad);}
    $put('lock-0','x');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});$put('lock-0','');
    chmod($source.'/'.$a,0644);snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});chmod($source.'/'.$a,0600);
    chmod($source.'/'.$a,0400);snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});chmod($source.'/'.$a,0600);
    link($source.'/'.$a,$scratch.'/hard');snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});unlink($scratch.'/hard');
    unlink($source.'/'.$a);symlink($source.'/'.$b,$source.'/'.$a);snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});unlink($source.'/'.$a);
    mkdir($source.'/'.$a,0700);snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});rmdir($source.'/'.$a);
    $put($a,str_repeat('x',65536));Check::same(64,strlen($s->digest()));$put($a,str_repeat('x',65537));snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});
    $h=fopen($source.'/'.$a,'wb');for($i=0;$i<256;++$i){fwrite($h,str_repeat('x',65536));}fclose($h);snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});unlink($source.'/'.$a);
    foreach([$source.'/../state',$root,$source] as $bad){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$bad,$source):void{new SoSecurity\Account\FileStateSnapshot($pdo,'owned',$source,$bad);});}
    $exports=print_r($s,true).var_export($s,true).json_encode($s);Check::same(false,strpos($exports,$source)!==false);Check::same(false,strpos($exports,$scratch)!==false);Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{serialize($s);});
    unlink($source.'/'.$b);$store=new SoSecurity\Storage\FileStore($source,'owned');$store->transact('key',static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(['value'=>"\0binary"],time()+3600,true);});$state=$s->digest();Check::same(64,strlen($state));
    $store->transact('key',static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(['value'=>"\0binarz"],time()+3600,true);});Check::same(false,$state===$s->digest());
    Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));Check::same(true,memory_get_peak_usage(true)<8388608);
    foreach([$source,$scratch] as $dir){rename($dir,$dir.'-old');mkdir($dir,0700);try{snapshotReason('account.snapshot_corrupt',static function()use($s):void{$s->digest();});}finally{rmdir($dir);rename($dir.'-old',$dir);}}
}finally{
    foreach([$source,$scratch] as $dir){foreach(new DirectoryIterator($dir) as $file){if(!$file->isDot()){if($file->isDir()&&!$file->isLink()){rmdir($file->getPathname());}else{unlink($file->getPathname());}}}rmdir($dir);}rmdir($root);
}
echo 'PASS bounded physical state: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; complete byte hashing, order independence, genuine FileStore values, file limits/types/links/permissions, capacity and private scratch cleanup\n";
