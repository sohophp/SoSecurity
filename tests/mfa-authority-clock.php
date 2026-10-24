<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
final class AuthorityFaultClock implements SoSecurity\Support\Clock
{
 public $calls=0;public $failAt=0;
 public function now():int {if(++$this->calls===$this->failAt){throw new RuntimeException('PRIVATE-FACTOR-CLOCK-DETAIL');}return 100000;}
}
$directory=privateDirectory();$stores=[];
try{
 $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);
 $fence=new SoSecurity\Account\LocalEpochFence($directory,'owned-clock','tenant',str_repeat('e',64),$keys,static function($h):bool{return fflush($h);},10000);
 $fence->initialize();
 foreach([1,2,3,4] as $failAt){
  if(isset($argv[1])&&(int)$argv[1]!==$failAt){continue;}
  $clock=new AuthorityFaultClock();$clock->failAt=$failAt;$effects=0;$error=null;
  $authority=new SoSecurity\Mfa\FactorAuthority($fence,static function():bool{return true;},$clock,10000);
  try{$authority->work('status','tenant','owned',[],static function()use(&$effects):string{++$effects;return 'owned-result';});}catch(Throwable $caught){$error=$caught;}
  Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);
  Check::same($failAt===4?'mfa.completion_unknown':'mfa.clock',$error->reason());
  Check::same(null,$error->getPrevious());Check::same(false,strpos((string)$error,'PRIVATE-FACTOR-CLOCK-DETAIL')!==false);
  Check::same($failAt===4?1:0,$effects);
  // A failed read must release its authority context; a new current read remains possible.
  $clock->failAt=0;Check::same('next',$authority->work('status','tenant','owned',[],static function():string{return 'next';}));
 }
 if(!isset($argv[1])){
  foreach(['deny','throw'] as $mode){
   $effects=0;$clock=new AuthorityFaultClock();$error=null;
   $authority=new SoSecurity\Mfa\FactorAuthority($fence,static function(string $action,string $phase)use($mode):bool{if($phase==='return'){if($mode==='throw'){throw new RuntimeException('PRIVATE-FACTOR-GUARD');}return false;}return true;},$clock,10000);
   try{$authority->work('status','tenant','owned',[],static function()use(&$effects):void{++$effects;});}catch(Throwable $caught){$error=$caught;}
   Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same('mfa.completion_unknown',$error->reason());Check::same(null,$error->getPrevious());Check::same(1,$effects);
  }
  foreach(['before','return'] as $phase){
   $clock=new AuthorityFaultClock();$inject=false;$error=null;$storeDirectory=privateDirectory();$stores[]=$storeDirectory;
   $raw=new SoSecurity\Mfa\TotpFactors(new SoSecurity\Storage\FileStore($storeDirectory,'owned-factor',$clock),new SoSecurity\Crypto\Cipher('owned',['owned'=>str_repeat('c',32)],'owned-clock'),'Owned',$clock);
   $managed=$raw->managed('owned-clock','tenant',str_repeat('e',64),$keys,$fence,static function(string $action,string $at)use($clock,$phase,&$inject):bool{if($inject&&$at===$phase){$clock->failAt=$clock->calls+1;}return true;},10000);
   $managed->prepare('tenant','owned',str_repeat('a',32),'owned@example.test');$inject=true;
   try{$managed->status('tenant','owned');}catch(Throwable $caught){$error=$caught;}
   Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same($phase==='before'?'mfa.clock':'mfa.completion_unknown',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos((string)$error,'PRIVATE-FACTOR-CLOCK-DETAIL')!==false);
   $inject=false;$clock->failAt=0;Check::same(false,$managed->status('tenant','owned')['enabled']);
  }
 }
}finally{foreach($stores as $storeDirectory){cleanDirectory($storeDirectory);}cleanDirectory($directory);}
echo 'PASS managed authority clock privacy: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
