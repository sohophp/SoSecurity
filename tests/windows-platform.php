<?php
declare(strict_types=1);
// Explicit unsupported-backend checks: do not bypass POSIX permission invariants to get Windows green.
require __DIR__.'/bootstrap.php';
if (stripos(PHP_OS,'WIN')!==0) { throw new RuntimeException('Run this boundary test with native Windows PHP.'); }
if (!extension_loaded('fileinfo')) { throw new RuntimeException('Windows boundary check requires test ext-fileinfo.'); }
$directory=privateDirectory();$webRoot=privateDirectory();
try {
    Check::same(0777,fileperms($directory)&0777);
    try { new SoSecurity\Storage\FileStore($directory,'windows');throw new RuntimeException('FileStore accepted unverifiable private permissions.'); }
    catch (SoSecurity\Storage\StorageException $error) { Check::same('storage.unavailable',$error->reason()); }
    $security=SoSecurity\Security::fromArray(['site'=>'windows','storage'=>['driver'=>'file','directory'=>$directory]]);
    Check::throws(SoSecurity\Storage\StorageException::class,static function () use ($security): void { $security->rateLimiter('login'); });
    $validator=new SoSecurity\Upload\Validator();
    try { new SoSecurity\Upload\Saver($validator,$directory,$webRoot);throw new RuntimeException('Saver accepted unverifiable private permissions.'); }
    catch (SoSecurity\Storage\StorageException $error) { Check::same('upload.directory',$error->reason()); }
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function () use ($validator,$directory): void { $validator->withTemporaryDirectory($directory); });
    Check::same([],array_values(array_diff(scandir($directory),['.','..'])));
    echo 'PHP '.PHP_VERSION.' / '.PHP_OS.': '.Check::$assertions." native Windows private-filesystem refusal assertions passed\n";
} finally { cleanDirectory($directory);cleanDirectory($webRoot); }
