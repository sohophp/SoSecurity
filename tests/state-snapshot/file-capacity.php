<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$root=privateDirectory();$source=$root.'/state';$scratch=$root.'/scratch';mkdir($source,0700);mkdir($scratch,0700);$pdo=new PDO('sqlite::memory:');
try{
    for($i=0;$i<10000;++$i){$n=($i*7919)%10000;$path=$source.'/'.sprintf('%064x',$n).'.json';file_put_contents($path,"v\0".$n);chmod($path,0600);}
    $s=new SoSecurity\Account\FileStateSnapshot($pdo,'owned-capacity',$source,$scratch,10000,30000);$expected=hash_init('sha256');hash_update($expected,'SoSecurity.State.FileSnapshot.1.'.$s->fingerprint());
    for($i=0;$i<10000;++$i){hash_update($expected,sprintf('%064x',$i).hash('sha256',"v\0".$i,true));}hash_update($expected,':10000');$expected=hash_final($expected);
    Check::same($expected,$s->digest());Check::same($expected,$s->digest());Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));
    $small=new SoSecurity\Account\FileStateSnapshot($pdo,'owned-capacity',$source,$scratch,9999,30000);snapshotReason('account.snapshot_capacity',static function()use($small):void{$small->digest();});
    Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));Check::same(true,memory_get_peak_usage(true)<8388608);
}finally{
    foreach(new DirectoryIterator($source) as $file){if(!$file->isDot()){unlink($file->getPathname());}}rmdir($source);rmdir($scratch);rmdir($root);
}
echo 'PASS physical snapshot capacity: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; 10000 actual files in scrambled creation order, streaming reference digest, 16-way external merge, limit rejection, cleanup and memory_limit=8M\n";
