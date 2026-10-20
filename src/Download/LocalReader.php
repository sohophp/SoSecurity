<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;

/** Internal local POSIX reader: private path chain, descriptor identity and full digest before any body leaves. */
final class LocalReader
{
    private $root;
    private $temporary;
    private $rootStat;
    private $temporaryStat;
    private $policy;
    public function __construct(string $directory,string $temporaryDirectory,string $documentRoot,Policy $policy)
    {
        if(DIRECTORY_SEPARATOR!=='/'){throw new ConfigurationException('Private download snapshots require the supported local POSIX filesystem.','configuration.download_platform');}
        $web=realpath($documentRoot);if($web===false||!is_dir($web)){throw new ConfigurationException('Provide the actual existing document root.','configuration.document_root');}
        foreach([$directory,$temporaryDirectory] as $path){
            if($path===''||strlen($path)>4096||strpos($path,"\0")!==false||$path[0]!=='/'||realpath($path)!==rtrim($path,'/')){throw new ConfigurationException('Configure canonical private absolute download directories.','configuration.download_directory');}
            $real=rtrim($path,'/');if($real===$web||strpos($real,rtrim($web,'/').'/')===0){throw new ConfigurationException('Download directories must be outside the web root.','configuration.web_root');}
        }
        $this->root=rtrim($directory,'/');$this->temporary=rtrim($temporaryDirectory,'/');$this->rootStat=$this->directory($this->root);$this->temporaryStat=$this->directory($this->temporary);
        if(!is_writable($this->temporary)){throw new StorageException('Private download snapshot directory is not writable.','download.directory');}$this->policy=$policy;
    }
    private function directory(string $path):array
    {
        clearstatcache(true,$path);$stat=@lstat($path);
        if(!is_array($stat)||($stat['mode']&0170000)!==0040000||($stat['mode']&0077)!==0||($stat['mode']&0500)!==0500){throw new StorageException('Download path contains a non-private directory.','download.directory');}return $stat;
    }
    private function same(array $a,array $b):bool {return $a['dev']===$b['dev']&&$a['ino']===$b['ino'];}
    private function regular(array $stat):void
    {
        if(($stat['mode']&0170000)!==0100000||($stat['mode']&0077)!==0||($stat['mode']&0400)===0||$stat['nlink']!==1){throw new SecurityException('Download source must be a private non-linked regular file.','download.source');}
    }
    private function chain(File $file):array
    {
        $root=$this->directory($this->root);if(!$this->same($this->rootStat,$root)){throw new SecurityException('Download root changed.','download.source');}$directories=[$this->root=>$root];$path=$this->root;$segments=explode('/',$file->relativePath());$last=array_pop($segments);
        foreach($segments as $segment){$path.='/'.$segment;$directories[$path]=$this->directory($path);}$path.='/'.$last;clearstatcache(true,$path);$stat=@lstat($path);
        if(!is_array($stat)){throw new SecurityException('Download source unavailable.','download.source');}$this->regular($stat);return ['path'=>$path,'stat'=>$stat,'directories'=>$directories];
    }
    private function allocate():Snapshot
    {
        $stat=$this->directory($this->temporary);if(!$this->same($stat,$this->temporaryStat)){throw new StorageException('Download snapshot directory changed.','download.directory');}
        for($attempt=0;$attempt<4;++$attempt){
            $path=$this->temporary.'/.download-'.bin2hex(random_bytes(16));$handle=@fopen($path,'x+b');
            if($handle===false){if(file_exists($path)||is_link($path)){continue;}throw new StorageException('Cannot allocate private download snapshot.','download.io');}
            $owned=@fstat($handle);$complete=false;
            try{
                if(!is_array($owned)||!@chmod($path,0600)){throw new StorageException('Cannot protect private snapshot.','download.io');}clearstatcache(true,$path);$named=@lstat($path);$current=$this->directory($this->temporary);
                if(!is_array($named)||!$this->same($owned,$named)||!$this->same($current,$this->temporaryStat)||$named['nlink']!==1){throw new StorageException('Private snapshot identity changed.','download.io');}
                if(!@unlink($path)){throw new StorageException('Cannot unlink private snapshot before use.','download.cleanup');}$complete=true;return new Snapshot($handle);
            }finally{
                if(!$complete){@fclose($handle);clearstatcache(true,$path);$named=@lstat($path);if(is_array($named)&&is_array($owned)&&$this->same($owned,$named)){@unlink($path);}}
            }
        }
        throw new StorageException('Private snapshot allocation exhausted.','download.io');
    }
    public function snapshot(File $file,Deadline $deadline):Snapshot
    {
        $deadline->check('download.timeout');if($file->bytes()>$this->policy->maximumBytes()){throw new ValidationException('File exceeds the verified-read budget.','download.too_large');}
        $before=$this->chain($file);$handle=@fopen($before['path'],'rb');if($handle===false){throw new StorageException('Cannot open authorized private source.','download.io');}$snapshot=null;$complete=false;
        try{
            $opened=@fstat($handle);if(!is_array($opened)||!$this->same($before['stat'],$opened)){throw new SecurityException('Opened download source changed.','download.source');}$this->regular($opened);
            if($opened['size']!==$file->bytes()){throw new SecurityException('Download size disagrees with content version.','download.version');}
            while(!@flock($handle,LOCK_SH|LOCK_NB)){$deadline->check('download.timeout');usleep(1000);}$snapshot=$this->allocate();$hash=hash_init('sha256');$bytes=0;
            while(true){
                $deadline->check('download.timeout');$chunk=@stream_get_contents($handle,min($this->policy->chunkBytes(),$file->bytes()-$bytes+1));
                if($chunk===false){throw new StorageException('Cannot read authorized private source.','download.io');}
                if($chunk===''){if(!feof($handle)){throw new StorageException('Private file read made no progress.','download.io');}break;}
                $bytes+=strlen($chunk);if($bytes>$file->bytes()){throw new SecurityException('Download source grew during verification.','download.version');}hash_update($hash,$chunk);$snapshot->write($chunk);$deadline->check('download.timeout');
            }
            $after=@fstat($handle);$current=$this->chain($file);
            if(!is_array($after)||!$this->same($opened,$after)||!$this->same($opened,$current['stat'])||$after['size']!==$opened['size']||$after['mtime']!==$opened['mtime']||$after['ctime']!==$opened['ctime']){throw new SecurityException('Download source changed while copying.','download.version');}$this->regular($after);
            foreach($before['directories'] as $path=>$directory){if(!isset($current['directories'][$path])||!$this->same($directory,$current['directories'][$path])){throw new SecurityException('Private path chain changed.','download.source');}}
            if($bytes!==$file->bytes()||!hash_equals($file->sha256(),hash_final($hash))){throw new SecurityException('Actual download bytes do not match the authorized digest.','download.version');}
            $snapshot->rewind();$deadline->check('download.timeout');$complete=true;return $snapshot;
        }finally{@fclose($handle);if(!$complete&&$snapshot!==null){$snapshot->close();}}
    }
    public function __debugInfo():array {return ['private_download_reader'=>'[redacted]'];}
}
