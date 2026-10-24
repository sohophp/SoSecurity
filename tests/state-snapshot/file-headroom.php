<?php
declare(strict_types=1);
require __DIR__.'/support.php';
$dir=privateDirectory();mkdir($dir.'/state',0700);mkdir($dir.'/scratch',0700);$pdo=new PDO('sqlite::memory:');$s=new SoSecurity\Account\FileStateSnapshot($pdo,'owned-headroom',$dir.'/state',$dir.'/scratch',1,30000);$a=str_repeat('a',64).'.json';$b=str_repeat('b',64).'.json';
try{Check::same(true,$s->canStoreFile($a));file_put_contents($dir.'/state/'.$a,'expired but physically present');chmod($dir.'/state/'.$a,0600);$before=$s->digest();Check::same(true,$s->canStoreFile($a));Check::same(false,$s->canStoreFile($b));Check::same($before,$s->digest());Check::same('expired but physically present',file_get_contents($dir.'/state/'.$a));Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($s):void{$s->canStoreFile('stage-0');});}finally{cleanDirectory($dir.'/state');cleanDirectory($dir.'/scratch');rmdir($dir);}
echo 'PASS exact physical file headroom: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; overwrite versus absent slot, expired bytes count, no mutation or pruning, bounded names\n";
