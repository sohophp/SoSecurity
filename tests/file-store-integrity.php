<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
$directory=privateDirectory();$clock=new TestClock();$store=new FileStore($directory,'owned-integrity',$clock,500);$hash=hash('sha256',"owned-integrity\0key");$path=$directory.'/'.$hash.'.json';$lock=$directory.'/lock-'.(hexdec(substr($hash,0,2))%64);
$read=static function()use($store){return $store->transact('key',static function($value):Change{return new Change($value,0,$value);});};
$refuse=static function(string $reason,callable $call):void{try{$call();throw new RuntimeException('Invalid file node accepted');}catch(StorageException $error){Check::same($reason,$error->reason());}};
try{
 Check::same(null,$read());Check::same(1,$store->transact('key',static function($value):Change{return new Change(['owned'=>true],0,1);}));Check::same(['owned'=>true],$read());
 chmod($path,0400);Check::same(['owned'=>true],$read());Check::same(0600,fileperms($path)&0777);
 $original=file_get_contents($path);file_put_contents($path,str_repeat('x',65537));$refuse('storage.capacity',$read);Check::same(65537,filesize($path));file_put_contents($path,$original);
 unlink($path);mkdir($path,0700);$refuse('storage.corrupt',$read);rmdir($path);
 symlink($directory.'/absent',$path);$refuse('storage.corrupt',$read);unlink($path);
 $store->transact('key',static function():Change{return new Change(['expired'=>true],100001,null);});$clock->time=100001;Check::same(1,$store->pruneBatch(100)->removed());Check::same(false,file_exists($path));Check::same(true,is_file($lock));
 file_put_contents($lock,'invalid lock bytes');$refuse('storage.capacity',$read);file_put_contents($lock,'');Check::same(null,$read());
 $store->transact('key',static function():Change{return new Change(['permanent'=>true],0,null);});Check::throws(RuntimeException::class,static function()use($store):void{$store->transact('key',static function(){throw new RuntimeException('owned callback abort');});});Check::same(['permanent'=>true],$read());
 Check::same([],glob($directory.'/.write-*'));
}finally{cleanDirectory($directory);}
echo 'PASS file store integrity '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
