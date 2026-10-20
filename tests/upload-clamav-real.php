<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_CLAM_SOCKET');
if(!is_string($socket)||strpos($socket,'/tmp/sosecurity-clamav-real-')!==0){throw new RuntimeException('Owned private ClamAV instance required.');}
$scanner=new SoSecurity\Upload\ClamAvScanner($socket,5000,2097152);
$metadataBackend=getenv('SOSECURITY_TEST_QUARANTINE_BACKEND');
if($metadataBackend!==false && !in_array($metadataBackend,['redis','mysql'],true)){throw new RuntimeException('Select an owned metadata backend.');}
if($metadataBackend!==false){require __DIR__.'/upload-quarantine-backend-support.php';}
$clean="owned clean scanner acceptance\n";$marker="SoSecurity antivirus acceptance marker.\n";
Check::same(true,$scanner->scan(new SoSecurity\Upload\Candidate($clean,'text/plain','txt',strlen($clean))));
Check::same(false,$scanner->scan(new SoSecurity\Upload\Candidate($marker,'text/plain','txt',strlen($marker))));
$limited=false;try{$body=str_repeat('x',262145);$scanner->scan(new SoSecurity\Upload\Candidate($body,'application/octet-stream','bin',strlen($body)));}catch(SoSecurity\Exception\DependencyException $e){Check::same('dependency.clamav_limit',$e->reason());$limited=true;}Check::same(true,$limited);
$limited=false;try{$body=str_repeat('x',1048577);$scanner->scan(new SoSecurity\Upload\Candidate($body,'application/octet-stream','bin',strlen($body)));}catch(SoSecurity\Exception\DependencyException $e){Check::same(true,strpos($e->reason(),'dependency.clamav_')===0);$limited=true;}Check::same(true,$limited);
$root=dirname($socket).'/fixture-'.bin2hex(random_bytes(8));mkdir($root,0700);mkdir($root.'/web',0700);mkdir($root.'/saved',0700);
try{
    $saver=new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(new SoSecurity\Upload\Policy(['extensions'=>['txt'],'require_scan'=>true])),$root.'/saved',$root.'/web',$scanner);
    file_put_contents($root.'/source.txt',$clean);$saved=$saver->saveFile($root.'/source.txt','file.txt');Check::same($clean,file_get_contents($saved->path()));Check::same(true,$saved->metadata()['scanner_passed']);unlink($saved->path());
    file_put_contents($root.'/source.txt',$marker);$rejected=false;try{$saver->saveFile($root.'/source.txt','file.txt');}catch(SoSecurity\Exception\ValidationException $e){Check::same('upload.scan_rejected',$e->reason());$rejected=true;}Check::same(true,$rejected);Check::same($marker,file_get_contents($root.'/source.txt'));Check::same([],glob($root.'/saved/*'));
    unset($body);mkdir($root.'/spool',0700);mkdir($root.'/ledger',0700);
    $metadata=$metadataBackend===false?new SoSecurity\Storage\FileStore($root.'/ledger','real-scan'):quarantineBackendStore($metadataBackend,null,true);
    $queue=new SoSecurity\Upload\Quarantine($metadata,
        new SoSecurity\Upload\Policy(['extensions'=>['txt'],'maximum_bytes'=>1024,'working_bytes'=>2097152]),$scanner,$root.'/spool',$root.'/web','uploads');
    file_put_contents($root.'/source.txt',$clean);$pending=$queue->enqueueFile($root.'/source.txt','clean.txt');$id=$pending->id();
    Check::same('pending',$pending->state());Check::same('available',$queue->process($id)->state());Check::same($clean,$queue->readAvailable($id)->contents());
    Check::same('pending',$queue->rescan($id)->state());Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($queue,$id):void{$queue->readAvailable($id);});
    Check::same('available',$queue->process($id)->state());Check::same('rejected',$queue->reject($id)->state());Check::same(true,$queue->remove($id));
    file_put_contents($root.'/source.txt',$marker);$pending=$queue->enqueueFile($root.'/source.txt','test-signature.txt');$id=$pending->id();
    Check::same('pending',$pending->state());Check::same('rejected',$queue->process($id)->state());
    Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($queue,$id):void{$queue->readAvailable($id);});
    Check::same(true,$queue->remove($id));Check::same($marker,file_get_contents($root.'/source.txt'));Check::same([],$queue->items());
    $storage=['driver'=>'file','directory'=>$root.'/ledger'];$services=['engine'=>$scanner];
    if($metadataBackend!==false){$storage=['driver'=>$metadataBackend,'connection'=>'state'];$services['state']=quarantineBackendConnection($metadataBackend);}
    $factory=SoSecurity\Security::fromArray(['site'=>'real-clam-factory','storage'=>$storage,
        'upload_quarantine'=>['directory'=>$root.'/spool','document_root'=>$root.'/web','scanner'=>'engine',
            'policy'=>['extensions'=>['txt'],'maximum_bytes'=>1024,'working_bytes'=>2097152]]],$services);
    if($metadataBackend!==false){$factory->initializeStorage();}
    $checks=array_column($factory->diagnose($root.'/web'),null,'check');
    Check::same('manual',$checks['quarantine.scanner']['status']);Check::same('manual',$checks['quarantine.workflow']['status']);
    $queue=$factory->quarantine();file_put_contents($root.'/source.txt',$clean);$id=$queue->enqueueFile($root.'/source.txt','factory.txt')->id();
    Check::same('available',$queue->process($id)->state());Check::same($clean,$queue->readAvailable($id)->contents());
    Check::same('rejected',$queue->reject($id)->state());Check::same(true,$queue->remove($id));
    file_put_contents($root.'/source.txt',$marker);$id=$queue->enqueueFile($root.'/source.txt','signature.txt')->id();
    Check::same('rejected',$queue->process($id)->state());Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($queue,$id):void{$queue->readAvailable($id);});
    Check::same(true,$queue->remove($id));Check::same([],$queue->items());
}finally{foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $f){if($f->isDir()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($root);}
echo 'PASS owned real ClamAV engine, private saver and persistent quarantine: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; backend='.($metadataBackend===false?'file':$metadataBackend)."; synthetic local test signature database, clean/rejected/engine and stream limits, no rejected destination file\n";
