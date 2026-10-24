<?php
declare(strict_types=1);
use SoSecurity\Account as A;
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sdk):void{$sdk->quarantine();});Check::same($before,$source->digest());
$queueStore=new SoSecurity\Storage\FileStore($directory.'/files','fresh-site:shared',$clock);
$connection=new A\StateQuarantineConnection($boundary,$witness,$source,$files,'files',$queueStore,$spoolSource,'spool','fresh-site','tenant',$epoch,$clock,$services['scanner'],static function(string $action,string $scope):?string{return $scope==='tenant'?'owned-uploader':null;},30000);
$queue=$sdk->quarantine($connection);file_put_contents($directory.'/upload.txt','owned protected factory payload');chmod($directory.'/upload.txt',0600);
$item=$queue->enqueueFile($directory.'/upload.txt','owned.txt');Check::same('pending',$item->state());Check::same('available',$queue->process($item->id())->state());Check::same('owned protected factory payload',$queue->readAvailable($item->id())->contents());Check::same('rejected',$queue->reject($item->id())->state());Check::same(true,$queue->remove($item->id()));Check::same([],$queue->items());Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
echo 'PASS protected authentication quarantine factory '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
