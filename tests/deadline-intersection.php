<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\Deadline;
use SoSecurity\Storage\StorageException;
$short=new Deadline(10);usleep(30000);$long=new Deadline(5000);$long->restrictTo($short);Check::throws(StorageException::class,static function()use($long):void{$long->check();});
$short=new Deadline(10);$long=new Deadline(5000);$short->restrictTo($long);usleep(30000);Check::throws(StorageException::class,static function()use($short):void{$short->check();});Check::same(true,$long->remaining()>0);
$budget=new Deadline(5000);$before=$budget->remaining();$budget->restrictTo($budget);Check::same(true,$budget->remaining()<=$before);Check::same(true,$budget->remaining()>0);
echo 'PASS deadline intersection: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
