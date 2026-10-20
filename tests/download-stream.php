<?php
declare(strict_types=1);
// Run in a fresh process with memory_limit=8M: full digest validation and output cannot buffer the full file.
require __DIR__.'/bootstrap.php';
$base=privateDirectory();$response=null;
try {
    foreach(['source','temporary','web'] as $part){mkdir($base.'/'.$part,0700);}
    $path=$base.'/source/large.bin';$handle=fopen($path,'x+b');chmod($path,0600);$block=str_repeat('binary\0',128);$expected=hash_init('sha256');$size=16777216;$left=$size;
    while($left>0){$chunk=substr($block,0,min($left,strlen($block)));if(fwrite($handle,$chunk)!==strlen($chunk)){throw new RuntimeException('Cannot create test file.');}hash_update($expected,$chunk);$left-=strlen($chunk);}fclose($handle);$expected=hash_final($expected);
    $file=new SoSecurity\Download\File(new SoSecurity\Authorization\Resource('stream-test','file','large','1'),'large.bin','large.bin',$size,$expected);
    $access=new class implements SoSecurity\Download\Access {
        public function authorize(SoSecurity\Download\File $file,SoSecurity\Download\Request $request):?SoSecurity\Download\Grant {
            return new SoSecurity\Download\Grant($file->fingerprint(),time()+300,static function(){return true;});
        }
    };
    $downloads=new SoSecurity\Download\Downloads($base.'/source',$base.'/temporary',$base.'/web',new SoSecurity\Download\Policy(['io_milliseconds'=>10000]));
    $response=$downloads->prepare($file,new SoSecurity\Download\Request(),$access,static function()use($file){return $file;});$hash=hash_init('sha256');$chunks=0;
    Check::same((string)$size,$response->headers()['Content-Length']);Check::same([],glob($base.'/temporary/.download-*'));
    $written=$response->send(static function(string $chunk)use($hash,&$chunks):int{++$chunks;Check::same(true,strlen($chunk)<=65536);hash_update($hash,$chunk);return strlen($chunk);});
    Check::same($size,$written);Check::same($expected,hash_final($hash));Check::same(true,$response->complete());Check::same(256,$chunks);Check::same(true,memory_get_peak_usage(true)<8388608);
    echo 'PASS download streaming: '.Check::$assertions.' assertions, 16MiB actual private source, peak '.memory_get_peak_usage(true).' bytes, memory_limit='.ini_get('memory_limit').' on PHP '.PHP_VERSION."\n";
} finally {
    if($response!==null){$response->close();}if(isset($path)&&is_file($path)){unlink($path);}foreach(['source','temporary','web'] as $part){if(is_dir($base.'/'.$part)){rmdir($base.'/'.$part);}}rmdir($base);
}
