<?php
declare(strict_types=1);
namespace SoSecurity\Support {
 function hrtime($number=false){return \ArchiveDeadlineProbe::clock()*1000000000;}
 function microtime($number=false){return \ArchiveDeadlineProbe::clock();}
}
namespace SoSecurity\Upload {
 function microtime($number=false){return \ArchiveDeadlineProbe::$time;}
 function hash_file($algorithm,$path){$result=\hash_file($algorithm,$path);++\ArchiveDeadlineProbe::$hashes;\ArchiveDeadlineProbe::step(\ArchiveDeadlineProbe::$hashes===1?'first-hash':'last-hash');return $result;}
 function fread($stream,$length){$result=\fread($stream,$length);\ArchiveDeadlineProbe::step($length===6?'body':'preflight');return $result;}
}
namespace {
 require __DIR__.'/bootstrap.php';
 final class ArchiveDeadlineProbe {
  public static $time=100.0;public static $hashes=0;public static $mode;public static $fault=false;
  public static function step(string $phase):void{if(self::$mode===$phase){self::$time+=1;}if($phase==='first-hash'&&self::$mode==='backwards'){self::$time-=1;}if($phase==='first-hash'&&self::$mode==='clock-fault'){self::$fault=true;}}
  public static function clock():float{if(self::$fault){throw new \RuntimeException('private-clock-detail');}return self::$time;}
 }
 ArchiveDeadlineProbe::$mode=$argv[2]??'normal';$path=$argv[1].'/valid.zip';$digest=hash_file('sha256',$path);$files=scandir($argv[1]);
 $run=static function()use($path):array{return (new SoSecurity\Upload\ArchiveInspector(['milliseconds'=>100]))->inspect($path);};
 if(ArchiveDeadlineProbe::$mode==='normal'){Check::same(5,$run()['uncompressed_bytes']);}
 else{try{$run();throw new RuntimeException('Expired ZIP inspection returned successfully');}catch(SoSecurity\Exception\ValidationException $error){Check::same('upload.archive',$error->reason());Check::same(null,$error->getPrevious());}}
 Check::same($digest,hash_file('sha256',$path));Check::same($files,scandir($argv[1]));
 echo 'PASS archive deadline '.ArchiveDeadlineProbe::$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}
