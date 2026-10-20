<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Upload\ArchiveInspector;

$fixtures=$argv[1]??'';
if($fixtures===''||!is_dir($fixtures)){throw new RuntimeException('Use an owned local ZIP test directory.');}
$inspector=new ArchiveInspector();
foreach([['entries'=>0],['ratio'=>101],['unknown'=>1],['path_bytes'=>null]] as $bad){
    Check::throws(ConfigurationException::class,static function()use($bad):void{new ArchiveInspector($bad);});
}
if(!class_exists(ZipArchive::class)){
    Check::throws(DependencyException::class,static function()use($inspector,$fixtures):void{$inspector->inspect($fixtures.'/valid.zip');});
    echo 'PASS ZIP inspection dependency refusal: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
    exit(0);
}
foreach(['','http://127.0.0.1:1/archive.zip',"bad\0path"] as $path){
    Check::throws(ValidationException::class,static function()use($inspector,$path):void{$inspector->inspect($path);});
}
$accepted=$inspector->inspect($fixtures.'/valid.zip');
Check::same(5,$accepted['uncompressed_bytes']);
Check::same(2,count($accepted['entries']));
Check::same(hash_file('sha256',$fixtures.'/valid.zip'),$accepted['sha256']);
Check::same('sub/file.bin',$accepted['entries'][1]['path']);
Check::same(false,$accepted['entries'][1]['directory']);
Check::same(5,(new ArchiveInspector(['entries'=>2,'entry_bytes'=>5,'total_bytes'=>5,'depth'=>2]))->inspect($fixtures.'/valid.zip')['uncompressed_bytes']);
Check::same(100,count($inspector->inspect($fixtures.'/exact_entries.zip')['entries']));
Check::same(8,(new ArchiveInspector(['entry_bytes'=>4,'total_bytes'=>8]))->inspect($fixtures.'/total.zip')['uncompressed_bytes']);
Check::same(5,(new ArchiveInspector(['archive_bytes'=>filesize($fixtures.'/valid.zip')]))->inspect($fixtures.'/valid.zip')['uncompressed_bytes']);
foreach([['entry_bytes'=>4],['entries'=>1],['archive_bytes'=>filesize($fixtures.'/valid.zip')-1],['path_bytes'=>4]] as $limit){
    Check::throws(ValidationException::class,static function()use($fixtures,$limit):void{(new ArchiveInspector($limit))->inspect($fixtures.'/valid.zip');});
}
Check::throws(ValidationException::class,static function()use($fixtures):void{(new ArchiveInspector(['total_bytes'=>7]))->inspect($fixtures.'/total.zip');});
$rejected=['traversal','absolute','backslash','hidden','trailing_dot','reserved','duplicate','case_collision','nested','nested_bzip','nested_xz','bomb','ratio','depth','symlink','conflict','nul','many','over_entries','false_count','false_crc','false_size','local_mismatch','reused_local'];
foreach($rejected as $case){
    Check::throws(ValidationException::class,static function()use($inspector,$fixtures,$case):void{$inspector->inspect($fixtures.'/'.$case.'.zip');});
}
$sourceLink=$fixtures.'/source-link.zip';
if(!symlink($fixtures.'/valid.zip',$sourceLink)){throw new RuntimeException('Could not create local symlink test.');}
try{
    Check::throws(ValidationException::class,static function()use($inspector,$sourceLink):void{$inspector->inspect($sourceLink);});
}finally{unlink($sourceLink);}
Check::same(false,file_exists($fixtures.'/target'));
echo 'PASS ZIP inspection: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
