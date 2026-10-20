<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;

$directory = getenv('SOSECURITY_TEST_FULL_DISK');
if (!$directory) { fwrite(STDERR, "Use bin/full-disk-check.sh to create an isolated tiny filesystem.\n"); exit(2); }
$real = realpath($directory);
if ($real === false || strpos($real, sys_get_temp_dir() . '/sosecurity-full-disk.') !== 0 || disk_total_space($real) > 65536
    || (fileperms($real) & 0077) !== 0 || count(array_diff(scandir($real), ['.', '..'])) !== 0) {
    throw new RuntimeException('Refusing to fill anything except the empty dedicated tiny test filesystem.');
}
$source = privateDirectory(); $web = privateDirectory();
try {
$store = new FileStore($directory, 'full-disk');
$store->transact('key', function () { return new Change(['original' => true], 0, null); });
$uploader = null; $published = null;
if (extension_loaded('gd') && extension_loaded('fileinfo')) {
    $image = imagecreatetruecolor(2, 2); imagepng($image, $source . '/image');
    if (is_resource($image)) { imagedestroy($image); } unset($image);
    $uploader = new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(), $directory, $web);
    $published = $uploader->saveFile($source . '/image', 'photo.png');
}
$fill = fopen($directory . '/fill', 'wb');
if ($fill === false) { throw new RuntimeException('Cannot allocate isolated fill file.'); }
while (@fwrite($fill, str_repeat('x', 4096)) > 0) {}
fclose($fill);
Check::same(true, disk_free_space($directory) < 4096);
Check::throws(StorageException::class, function () use ($store) {
    $store->transact('key', function () { return new Change(['replacement' => true], 0, true); });
});
if ($uploader !== null) {
    Check::throws(StorageException::class, function () use ($uploader, $source) { $uploader->saveFile($source . '/image', 'photo.png'); });
    Check::same(1, count(glob($directory . '/*.png')));
    Check::same($published->metadata()['sha256'], hash_file('sha256', $published->path()));
}
Check::same(['original' => true], $store->transact('key', function ($value) { return new Change(null, 0, $value); }));
Check::same([], glob($directory . '/.write-*'));
$downloadBytes=str_repeat('D',131072);$downloadPath=$source.'/download.bin';file_put_contents($downloadPath,$downloadBytes);chmod($downloadPath,0600);
$downloadFile=new SoSecurity\Download\File(new SoSecurity\Authorization\Resource('disk-test','file','a','1'),'download.bin','download.bin',strlen($downloadBytes),hash('sha256',$downloadBytes));
$downloadAccess=new class implements SoSecurity\Download\Access {
    public function authorize(SoSecurity\Download\File $file,SoSecurity\Download\Request $request):?SoSecurity\Download\Grant {return new SoSecurity\Download\Grant($file->fingerprint(),time()+60,static function(){return true;});}
};
$downloads=new SoSecurity\Download\Downloads($source,$directory,$web);$freeBefore=disk_free_space($directory);
Check::throws(StorageException::class,static function()use($downloads,$downloadFile,$downloadAccess){$downloads->prepare($downloadFile,new SoSecurity\Download\Request(),$downloadAccess,static function()use($downloadFile){return $downloadFile;});});
Check::same([],glob($directory.'/.download-*'));Check::same($freeBefore,disk_free_space($directory));Check::same($downloadFile->sha256(),hash_file('sha256',$downloadPath));
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " real ENOSPC assertions passed\n";

} finally { cleanDirectory($source); cleanDirectory($web); }
