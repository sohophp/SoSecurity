<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Download as D;
$mode=$argv[1]??'writer-send';$phase=explode('-',$mode)[0];$clock=new TestClock();$raw=str_repeat('a',3072);$offset=0;$closed=0;$calls=0;$nested='';$transfer=null;$entered=false;
$probe=static function(string $where)use($mode,$phase,&$transfer,&$entered,&$nested):void{
 if($where!==$phase||$entered||$mode==='normal'){return;}$entered=true;
 try{
  if(strpos($mode,'send')!==false){$transfer->send(static function(string $part)use(&$nested):int{$nested.=$part;return strlen($part);});}
  elseif(strpos($mode,'headers')!==false){$transfer->headers();}
  elseif(strpos($mode,'status')!==false){$transfer->status();}
  else{$nested.=$transfer->read(1);}
 }catch(Throwable $error){if(strpos($mode,'swallow')===false){throw $error;}}
};
$file=new D\File(new SoSecurity\Authorization\Resource('owned','file','one','1'),'one.bin','one.bin',strlen($raw),hash('sha256',$raw));
$grant=new D\Grant($file->fingerprint(),$clock->time+60,static function()use($probe):bool{$probe('grant');return true;});
$transfer=new D\Transfer($file,new D\Request(),$grant,new D\Policy(['chunk_bytes'=>1024]),static function(int $limit)use($probe,$raw,&$offset):string{$probe('reader');$part=substr($raw,$offset,$limit);$offset+=strlen($part);return $part;},static function()use(&$closed,$probe):void{++$closed;$probe('closer');},static function()use($probe,$file):D\File{$probe('reload');return $file;},$clock);
$output='';$run=static function()use($transfer,$probe,&$output,&$calls):int{return $transfer->send(static function(string $part)use($probe,&$output,&$calls):int{++$calls;$probe('writer');$output.=$part;return strlen($part);});};
if($mode==='normal'){Check::same(strlen($raw),$run());Check::same($raw,$output);Check::same(true,$transfer->complete());}
else{
 $failed=false;try{$count=$run();echo 'UNEXPECTED_SUCCESS bytes='.$count.' nested='.strlen($nested).' read='.$transfer->bytesRead().PHP_EOL;}catch(Throwable $error){$failed=true;Check::same(null,$error->getPrevious());}
 Check::same(true,$failed);Check::same(false,$transfer->complete());Check::same('', $nested);Check::throws(SoSecurity\Storage\StorageException::class,static function()use($transfer):void{$transfer->read();});
}
Check::same(1,$closed);echo 'PASS download reentry '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
