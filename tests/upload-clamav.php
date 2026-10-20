<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$variant=getenv('SOSECURITY_TEST_CLAM_SCANNER');if($variant!==false){if(strpos($variant,'/tmp/sosecurity-clamav-')!==0){throw new RuntimeException('Owned scanner variant required.');}require $variant;}
use SoSecurity\Upload\ClamAvScanner;
use SoSecurity\Upload\Candidate;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

$mode=$argv[1]??'configuration';$socket=getenv('SOSECURITY_TEST_CLAM_SOCKET');
function clamReason(string $reason,callable $work):void{
    ++Check::$assertions;try{$work();}catch(DependencyException $e){Check::same($reason,$e->reason());return;}throw new RuntimeException('Expected '.$reason);
}
if($mode==='configuration'){
    foreach(['tcp://127.0.0.1:3310','relative.sock',"/tmp/a\0b",'/tmp/../scan.sock','/tmp/./scan.sock','/'.str_repeat('s',101)] as $path){Check::throws(ConfigurationException::class,static function()use($path):void{new ClamAvScanner($path);});}
    foreach([[0,1],[30001,1],[1,0],[1,20971521]] as $limits){Check::throws(ConfigurationException::class,static function()use($limits):void{new ClamAvScanner('/tmp/configured-scan.sock',$limits[0],$limits[1]);});}
    $path='/tmp/private-scan-configuration.sock';$scanner=new ClamAvScanner($path);foreach([print_r($scanner,true),var_export($scanner,true),json_encode($scanner)] as $dump){Check::same(false,strpos($dump,$path)!==false);}
    Check::throws(ConfigurationException::class,static function()use($scanner):void{serialize($scanner);});Check::throws(ConfigurationException::class,static function()use($scanner):void{$scanner->socketPath='tcp://invalid';});
    clamReason('dependency.clamav_limit',static function():void{(new ClamAvScanner('/tmp/not-connected.sock',100,1))->scan(new Candidate("a\0",'application/octet-stream','bin',2));});
}else{
    if(!is_string($socket)||strpos($socket,'/tmp/sosecurity-clamav-')!==0){throw new RuntimeException('Use the owned local scanner test server.');}
    if(strpos($mode,'save-')===0){
        $root=dirname($socket).'/fixture-'.bin2hex(random_bytes(8));mkdir($root,0700);mkdir($root.'/web',0700);mkdir($root.'/saved',0700);$source=$root.'/source.txt';$raw="scanner text\n";file_put_contents($source,$raw);
        try{
            $scanner=new ClamAvScanner($socket,200,1000);$saver=new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(new SoSecurity\Upload\Policy(['extensions'=>['txt'],'require_scan'=>true])),$root.'/saved',$root.'/web',$scanner);
            if($mode==='save-clean'){$stored=$saver->saveFile($source,'scan.txt');Check::same($raw,file_get_contents($stored->path()));Check::same(true,$stored->metadata()['scanner_passed']);Check::same(hash('sha256',$raw),$stored->metadata()['sha256']);Check::same(0600,fileperms($stored->path())&0777);unlink($stored->path());}
            else{$expected=$mode==='save-infected'?'upload.scan_rejected':'upload.scan_failed';$error=null;$unexpected=null;try{$unexpected=$saver->saveFile($source,'scan.txt');}catch(Throwable $caught){$error=$caught;}if($unexpected!==null&&is_file($unexpected->path())&&file_get_contents($unexpected->path())===$raw){throw new RuntimeException('UNSAFE_CLAMAV_REJECTED_SCAN_SAVED_FILE');}Check::same(true,$error instanceof SoSecurity\Exception\SecurityException||$error instanceof SoSecurity\Exception\ValidationException);Check::same($expected,$error->reason());}
            Check::same($raw,file_get_contents($source));Check::same([],glob($root.'/saved/*'));
        }finally{foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $f){if($f->isDir()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($root);}
    }else{
        $binary='';for($i=0;$i<256;++$i){$binary.=chr($i);}$body=str_repeat($binary,65)."zPING\0stream: OK\0";
        if($mode==='write-timeout'){$body=str_repeat("\0",2097152);}
        $milliseconds=in_array($mode,['timeout','hold-open','trickle','write-timeout'],true)?100:2000;
        $scanner=new ClamAvScanner($socket,$milliseconds,20971520);$candidate=new Candidate($body,'application/octet-stream','bin',strlen($body));
        $reasons=['error'=>'dependency.clamav_protocol','truncated'=>'dependency.clamav_protocol','multiple'=>'dependency.clamav_protocol','oversized'=>'dependency.clamav_protocol','wrong-prefix'=>'dependency.clamav_protocol','trailing'=>'dependency.clamav_protocol','limit'=>'dependency.clamav_limit','heuristic-limit'=>'dependency.clamav_limit','timeout'=>'dependency.clamav_timeout','hold-open'=>'dependency.clamav_timeout','trickle'=>'dependency.clamav_timeout','write-timeout'=>'dependency.clamav_timeout','replaced'=>'dependency.clamav_socket','world-socket'=>'dependency.clamav_socket','symlink'=>'dependency.clamav_socket','world-directory'=>'dependency.clamav_socket','regular'=>'dependency.clamav_socket'];
        if(isset($reasons[$mode])){clamReason($reasons[$mode],static function()use($scanner,$candidate):void{$scanner->scan($candidate);});}
        else{Check::same(!in_array($mode,['infected','infected-ok'],true),$scanner->scan($candidate));}
    }
}
echo 'PASS ClamAV '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
