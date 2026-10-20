<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
if(!extension_loaded('fileinfo')){echo "NOT RUN upload read budget: fileinfo unavailable\n";exit(0);}
$directory=privateDirectory();$path=$directory.'/source.txt';$raw="small validated text\n";file_put_contents($path,$raw);
try{
    $policy=new SoSecurity\Upload\Policy(['extensions'=>['txt'],'maximum_bytes'=>20971520,'working_bytes'=>2097152]);
    $candidate=(new SoSecurity\Upload\Validator($policy))->inspectFile($path,'source.txt');
    Check::same($raw,$candidate->contents());Check::same(strlen($raw),$candidate->bytes());Check::same(hash('sha256',$raw),$candidate->digest());Check::same(true,memory_get_peak_usage(false)<8388608);
    $h=fopen($path,'wb');ftruncate($h,20971521);fclose($h);Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($policy,$path):void{(new SoSecurity\Upload\Validator($policy))->inspectFile($path,'source.txt');});Check::same(true,memory_get_peak_usage(false)<8388608);
}finally{unlink($path);rmdir($directory);}
echo 'PASS upload read allocation budget: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; small input under 8M despite 20MiB policy ceiling\n";
