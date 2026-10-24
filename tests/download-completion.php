<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Download as D;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
$mode=$argv[1]??'close-denial';$clock=new TestClock();$allowed=true;$version='1';$closed=0;$writes=0;
$make=static function(string $version):D\File{return new D\File(new SoSecurity\Authorization\Resource('owned','file','one',$version),'one.txt','one.txt',5,hash('sha256','owned'));};$file=$make('1');
$grant=new D\Grant($file->fingerprint(),$clock->time+60,static function()use(&$allowed):bool{return $allowed;});
$close=static function()use($mode,&$closed,&$allowed,&$version,$clock):void{++$closed;if($mode==='close-denial'){$allowed=false;}if($mode==='close-expiry'){$clock->time+=60;}if($mode==='close-version'){$version='2';}if($mode==='close-error'){throw new RuntimeException('private cleanup detail');}};
$transfer=new D\Transfer($file,new D\Request($mode==='head-denial'?'HEAD':'GET'),$grant,new D\Policy(),static function(int $limit):string{return 'owned';},$mode==='head-denial'?static function()use(&$closed,&$allowed):void{++$closed;$allowed=false;}:$close,static function()use($make,&$version):D\File{return $make($version);},$clock);
$operation=static function()use($mode,$transfer,&$allowed,&$version,&$writes,$clock){
 if(strpos($mode,'writer-')===0){return $transfer->send(static function(string $chunk)use($mode,&$allowed,&$version,&$writes,$clock):int{++$writes;if($mode==='writer-denial'){$allowed=false;}if($mode==='writer-version'){$version='2';}if($mode==='writer-expiry'){$clock->time+=60;}return strlen($chunk);});}return $transfer->read();
};
if($mode==='normal'){Check::same('owned',$operation());Check::same(true,$transfer->complete());Check::same('',$transfer->read());}
else{Check::throws($mode==='close-error'?StorageException::class:SecurityException::class,$operation);Check::same(false,$transfer->complete());Check::throws(StorageException::class,static function()use($transfer):void{$transfer->read();});}
Check::same(1,$closed);Check::same(strpos($mode,'writer-')===0?1:0,$writes);
echo 'PASS download completion '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
