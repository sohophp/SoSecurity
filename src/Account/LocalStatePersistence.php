<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;

/** Explicit local POSIX adapter: sync the exact inherited file and directory descriptors. */
final class LocalStatePersistence
{
    private $dependencies;
    private $milliseconds;

    /** Optional Python 3 helper; construction never starts a process or creates state. */
    public function __construct(string $directory,int $milliseconds=1000,string $python='/usr/bin/python3')
    {
        new Deadline($milliseconds);
        $stat=@lstat($directory);$interpreter=realpath($python);
        if(PHP_OS_FAMILY!=='Linux'||!function_exists('proc_open')||!function_exists('proc_get_status')||!function_exists('proc_terminate')
            ||realpath($directory)!==$directory||!is_array($stat)||($stat['mode']&0170777)!==0040700
            ||$interpreter===false||!is_file($interpreter)||!is_executable($interpreter)){
            throw new ConfigurationException('Configure a canonical private local directory and an explicit Python 3 persistence helper.','configuration.state_persistence');
        }
        $this->dependencies=static function()use($directory,$stat,$interpreter):array{return [$directory,$stat,$interpreter];};$this->milliseconds=$milliseconds;
    }

    private function d():array{return ($this->dependencies)();}

    private function directory():void
    {
        $d=$this->d();clearstatcache(true,$d[0]);$stat=@lstat($d[0]);
        if(realpath($d[0])!==$d[0]||!is_array($stat)||($stat['mode']&0170777)!==0040700
            ||$stat['dev']!==$d[1]['dev']||$stat['ino']!==$d[1]['ino']||$stat['uid']!==$d[1]['uid']){self::failed();}
    }

    private function file($handle):void
    {
        $this->directory();$d=$this->d();$metadata=is_resource($handle)?stream_get_meta_data($handle):[];$path=$metadata['uri']??null;
        if(!is_string($path)||dirname($path)!==$d[0]){self::failed();}
        // A FileStore CAS renames the open temporary inode. PHP keeps its original stream URI;
        // the helper validates its current kernel pathname against the inherited directory FD.
        $opened=fstat($handle);
        if(!is_array($opened)||($opened['mode']&0170777)!==0100600||$opened['nlink']!==1||$opened['uid']!==$d[1]['uid']){self::failed();}
    }

    /** No pathname is passed to the helper, and it cannot reopen a substituted file. */
    public function __invoke($handle):bool
    {
        $this->file($handle);$d=$this->d();$deadline=new Deadline($this->milliseconds);$directory=@fopen($d[0],'r');$process=null;$pipes=[];
        try{
            $stat=is_resource($directory)?fstat($directory):false;
            if(!is_array($stat)||$stat['dev']!==$d[1]['dev']||$stat['ino']!==$d[1]['ino']||!fflush($handle)){self::failed();}
            $code="import os\np=os.readlink('/proc/self/fd/3');d=os.readlink('/proc/self/fd/4')\n".
                "if os.path.dirname(p)!=d: raise OSError('Foreign state descriptor')\n".
                "name=os.path.basename(p)\n".
                "def check():\n a=os.fstat(3);b=os.stat(name,dir_fd=4,follow_symlinks=False)\n if (a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_nlink)!=(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_nlink) or a.st_nlink!=1 or a.st_mode&0o170777!=0o100600: raise OSError('Changed state descriptor')\n".
                "check();os.fsync(3);os.fsync(4);check()\n";
            $command='exec '.escapeshellarg($d[2]).' -I -S -c '.escapeshellarg($code);
            $process=@proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w'],3=>$handle,4=>$directory],$pipes);
            if(!is_resource($process)){self::failed();}fclose($pipes[0]);unset($pipes[0]);
            foreach($pipes as $pipe){stream_set_blocking($pipe,false);}
            $output=0;
            do{
                foreach($pipes as $pipe){$output+=strlen(fread($pipe,1025));}
                if($output>1024){self::failed();}$status=proc_get_status($process);$deadline->check('account.persistence_timeout');
                if(!$status['running']){break;}usleep(1000);
            }while(true);
            foreach($pipes as $pipe){fclose($pipe);}$pipes=[];$code=proc_close($process);$process=null;
            if(($status['exitcode']<0?$code:$status['exitcode'])!==0){self::failed();}
            $this->file($handle);$deadline->check('account.persistence_timeout');return true;
        }finally{
            foreach($pipes as $pipe){if(is_resource($pipe)){fclose($pipe);}}
            if(is_resource($process)){proc_terminate($process,9);proc_close($process);}
            if(is_resource($directory)){fclose($directory);}
        }
    }

    /** @return never */
    private static function failed():void{throw new StorageException('Exact local state persistence was not confirmed.','account.state_persistence');}
    public function __debugInfo():array{return ['local_state_persistence'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload local persistence dependencies.','configuration.state_persistence');}
    public function __wakeup():void{throw new ConfigurationException('Reload local persistence dependencies.','configuration.state_persistence');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Local persistence is immutable.','configuration.immutable');}
}
