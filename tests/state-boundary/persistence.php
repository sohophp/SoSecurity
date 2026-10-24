<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SoSecurity\Account\LocalStatePersistence;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

function persistenceReason(string $reason,callable $operation):void
{
    ++Check::$assertions;
    try{$operation();}catch(StorageException $error){Check::same($reason,$error->reason());return;}
    throw new RuntimeException('Expected persistence refusal.');
}
$directory=privateDirectory();$foreign=privateDirectory();$handle=null;
try{
    $path=$directory.'/state';$handle=fopen($path,'x+b');chmod($path,0600);fwrite($handle,'owned sealed bytes');
    $persist=new LocalStatePersistence($directory,5000);Check::same(true,$persist($handle));Check::same('owned sealed bytes',file_get_contents($path));
    $temporary=fopen('php://temp','w+b');try{persistenceReason('account.state_persistence',static function()use($persist,$temporary):void{$persist($temporary);});}finally{fclose($temporary);}
    $other=fopen($foreign.'/foreign','x+b');chmod($foreign.'/foreign',0600);try{persistenceReason('account.state_persistence',static function()use($persist,$other):void{$persist($other);});}finally{fclose($other);}
    chmod($path,0644);persistenceReason('account.state_persistence',static function()use($persist,$handle):void{$persist($handle);});chmod($path,0600);
    link($path,$directory.'/link');persistenceReason('account.state_persistence',static function()use($persist,$handle):void{$persist($handle);});unlink($directory.'/link');
    rename($path,$foreign.'/original');file_put_contents($path,'substituted');chmod($path,0600);persistenceReason('account.state_persistence',static function()use($persist,$handle):void{$persist($handle);});unlink($path);rename($foreign.'/original',$path);
    rename($path,$directory.'/renamed');Check::same(true,$persist($handle));rename($directory.'/renamed',$path);
    // The helper receives the exact existing descriptors rather than opening filenames.
    $probe=$directory.'/probe';$report=$directory.'/descriptor-report';
    $python="#!/usr/bin/python3\nimport json,os\na=os.fstat(3);b=os.fstat(4)\nwith open(".json_encode($report,JSON_UNESCAPED_SLASHES).",'w') as f: json.dump([a.st_dev,a.st_ino,b.st_dev,b.st_ino],f)\nos.fsync(3);os.fsync(4)\n";
    file_put_contents($probe,$python);chmod($probe,0700);Check::same(true,(new LocalStatePersistence($directory,5000,$probe))($handle));
    $a=fstat($handle);$b=lstat($directory);Check::same([$a['dev'],$a['ino'],$b['dev'],$b['ino']],json_decode(file_get_contents($report),true));
    file_put_contents($probe,"#!/usr/bin/python3\nimport sys\nsys.exit(1)\n");persistenceReason('account.state_persistence',static function()use($directory,$probe,$handle):void{(new LocalStatePersistence($directory,5000,$probe))($handle);});
    $pidFile=$directory.'/helper-pid';file_put_contents($probe,"#!/usr/bin/python3\nimport os,time\nwith open(".json_encode($pidFile,JSON_UNESCAPED_SLASHES).",'w') as f: f.write(str(os.getpid()))\ntime.sleep(30)\n");
    persistenceReason('account.persistence_timeout',static function()use($directory,$probe,$handle):void{(new LocalStatePersistence($directory,1000,$probe))($handle);});
    Check::same(true,is_file($pidFile));if(function_exists('posix_kill')){Check::same(false,posix_kill((int)file_get_contents($pidFile),0));}
    Check::same(true,$persist($handle));
    Check::throws(ConfigurationException::class,static function()use($directory):void{new LocalStatePersistence($directory,5000,$directory.'/missing');});
    foreach([var_export($persist,true),print_r($persist,true),json_encode($persist)] as $dump){Check::same(false,strpos($dump,$directory)!==false);}
    Check::throws(ConfigurationException::class,static function()use($persist):void{serialize($persist);});
}finally{if(is_resource($handle)){fclose($handle);}cleanDirectory($directory);cleanDirectory($foreign);}
echo 'PASS exact local persistence: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; real file/directory fsync, descriptor identity, substitution/hardlink/mode refusal, failed helper and terminated timeout',PHP_EOL;
