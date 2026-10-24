<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\FenceStateSnapshot;
use SoSecurity\Account\LocalEpochFence;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Storage\StorageException;
$p=new PDO('sqlite::memory:');$dir=privateDirectory();$keys=new HmacKeys('test',['test'=>str_repeat('k',32)]);$persist=static function($h):bool{return fflush($h);};
try{
    $source=new FenceStateSnapshot($p,'fences',$dir,1,30000);$empty=$source->digest();$fence=new LocalEpochFence($dir,'site','scope',str_repeat('e',64),$keys,$persist);Check::same(true,$source->coversFence($fence));Check::same($p,$source->connection());$fence->initialize();$open=$source->digest();Check::same(false,$empty===$open);$fence->work(static function()use($source,$open):void{Check::same($open,$source->digest());});$fence->drain(static function()use($source):void{Check::same(64,strlen($source->digest()));});$closed=$source->digest();Check::same(false,$open===$closed);$path=glob($dir.'/*.fence')[0];$raw=file_get_contents($path);Check::same(true,strpos($raw,"closed\n")===0);Check::same($closed,$source->digest());Check::same($raw,file_get_contents($path));
    foreach(['unknown','oversize','malformed','permission','hardlink','symlink','capacity'] as $mode){$extra=$dir.'/'.str_repeat('a',64).'.fence';if($mode==='unknown'){$extra=$dir.'/unexpected';file_put_contents($extra,'x');chmod($extra,0600);}elseif($mode==='hardlink'){link($path,$extra);}elseif($mode==='symlink'){symlink($path,$extra);}elseif($mode==='capacity'){file_put_contents($extra,$raw);chmod($extra,0600);}elseif($mode==='permission'){chmod($path,0644);}else{file_put_contents($path,$mode==='oversize'?str_repeat('x',129):'malformed');}try{Check::throws(StorageException::class,static function()use($source):void{$source->digest();});}finally{if(file_exists($extra)||is_link($extra)){unlink($extra);}file_put_contents($path,$raw);chmod($path,0600);}}
    Check::same($closed,$source->digest());Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($source):void{serialize($source);});$domains=$source->storageDomains();Check::same($dir,$domains[0]['path']);Check::same('file',$domains[0]['kind']);
}finally{cleanDirectory($dir);}
echo 'PASS physical fence state source: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual open/closed bytes, SH/EX-owner observation without nested locks, strict names/permissions/size/links/counts and no mutation\n";
