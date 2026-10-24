<?php
declare(strict_types=1);
require __DIR__.'/support.php';
snapshotCase(($argv[1]??'')==='mysql',static function(PDO $pdo,PDO $observer,string $dir):void{
    mkdir($dir.'/files',0700);mkdir($dir.'/scratch',0700);$files=$dir.'/files';$source=new SoSecurity\Account\FileStateSnapshot($pdo,'owned-staging',$files,$dir.'/scratch',1,30000);$empty=$source->digest();
    for($i=0;$i<64;++$i){file_put_contents($files.'/stage-'.$i,str_repeat('s',65536));chmod($files.'/stage-'.$i,0600);}Check::same($empty,$source->digest());
    $active=str_repeat('a',64).'.json';file_put_contents($files.'/'.$active,'committed');chmod($files.'/'.$active,0600);$committed=$source->digest();Check::same(false,$empty===$committed);file_put_contents($files.'/stage-0','different uncommitted bytes');Check::same($committed,$source->digest());Check::same('committed',$source->capture(['active'=>$active])->file('active'));
    foreach(['stage-64','stage-00','.contain-unrecognized'] as $invalid){file_put_contents($files.'/'.$invalid,'x');chmod($files.'/'.$invalid,0600);snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});unlink($files.'/'.$invalid);}
    chmod($files.'/stage-0',0644);snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});chmod($files.'/stage-0',0600);file_put_contents($files.'/stage-0',str_repeat('x',65537));snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});unlink($files.'/stage-0');symlink($files.'/'.$active,$files.'/stage-0');snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});unlink($files.'/stage-0');link($files.'/'.$active,$files.'/stage-0');snapshotReason('account.snapshot_corrupt',static function()use($source):void{$source->digest();});unlink($files.'/stage-0');Check::same($committed,$source->digest());
});
echo 'PASS bounded non-authoritative staging: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; 64 private 64KiB slots, active bytes still covered, malformed names/modes/links/size rejected\n";
