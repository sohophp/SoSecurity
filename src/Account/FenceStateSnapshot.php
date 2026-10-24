<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
/** Complete bounded raw epoch-authority directory. Observes bytes, never creates or opens an authority. */
final class FenceStateSnapshot implements StateSnapshot
{
    private $dependencies;private $fingerprint;
    public function __construct(PDO $connection,string $profile,string $directory,int $maximumFiles=128,int $milliseconds=10000)
    {
        Guard::label($profile);new Deadline($milliseconds);$s=@lstat($directory);if(preg_match('//u',$profile)!==1||realpath($directory)!==$directory||!is_array($s)||($s['mode']&0170777)!==0040700||$maximumFiles<1||$maximumFiles>4096){throw new ConfigurationException('Use a canonical private fence directory and fixed bounds.','configuration.state_snapshot');}
        $this->dependencies=static function()use($connection,$directory,$s,$maximumFiles,$milliseconds):array{return [$connection,$directory,$s,$maximumFiles,$milliseconds];};$this->fingerprint=hash('sha256','SoSecurity.State.FenceSnapshot.Profile.1.'.json_encode([$profile,base64_encode($directory),$s['dev'],$s['ino'],$s['uid'],$maximumFiles],JSON_UNESCAPED_SLASHES));
    }
    private function d():array{return ($this->dependencies)();}
    private function directory():void
    {
        $d=$this->d();clearstatcache(true,$d[1]);$s=@lstat($d[1]);if(realpath($d[1])!==$d[1]||!is_array($s)||($s['mode']&0170777)!==0040700||$s['dev']!==$d[2]['dev']||$s['ino']!==$d[2]['ino']||$s['uid']!==$d[2]['uid']){self::corrupt();}
    }
    /** @return never */
    private static function corrupt():void{throw new StorageException('Fence directory state is missing, changed, malformed or outside its bound.','account.fence_snapshot_corrupt');}
    private function file(array $s):void{if(($s['mode']&0170777)!==0100600||$s['uid']!==$this->d()[2]['uid']||$s['nlink']!==1||$s['size']<1||$s['size']>128){self::corrupt();}}
    private function scan(Deadline $deadline):array
    {
        $d=$this->d();$this->directory();$rows=[];foreach(new \DirectoryIterator($d[1]) as $entry){$deadline->check('account.snapshot_timeout');if($entry->isDot()){continue;}$name=$entry->getFilename();if(!preg_match('/\A[a-f0-9]{64}\.fence\z/D',$name)||count($rows)>=$d[3]){self::corrupt();}$path=$d[1].'/'.$name;clearstatcache(true,$path);$before=@lstat($path);if(!is_array($before)){self::corrupt();}$this->file($before);$h=@fopen($path,'rb');if($h===false){self::corrupt();}
            try{$opened=fstat($h);if(!is_array($opened)){self::corrupt();}$this->file($opened);$raw=stream_get_contents($h,129);clearstatcache(true,$path);$named=@lstat($path);$after=fstat($h);if(!is_array($named)||!is_array($after)){self::corrupt();}$this->file($named);$this->file($after);foreach([$before,$named,$after] as $s){if($s['dev']!==$opened['dev']||$s['ino']!==$opened['ino']){self::corrupt();}}if(!is_string($raw)||strlen($raw)!==$opened['size']||strlen($raw)!==$after['size']||strlen($raw)!==$named['size']||!preg_match('/\A(?:open|closed)\n[A-Za-z][A-Za-z0-9_-]{0,31}\n[a-f0-9]{64}\n\z/D',$raw)){self::corrupt();}$rows[$name]=hash('sha256',$raw);
            }finally{fclose($h);}
        }$this->directory();ksort($rows,SORT_STRING);return $rows;
    }
    public function connection():PDO{return $this->d()[0];}
    public function fingerprint():string{return $this->fingerprint;}
    public function storageDomains():array{$this->directory();$d=$this->d();return [StateStorageDomain::directory($d[1],$d[2])];}
    public function coversFence(LocalEpochFence $fence):bool{return $fence->storageDomain()===$this->storageDomains()[0];}
    public function digest():string
    {
        $deadline=new Deadline($this->d()[4]);$first=$this->scan($deadline);$second=$this->scan($deadline);if($first!==$second){self::corrupt();}return hash('sha256','SoSecurity.State.FenceSnapshot.1.'.$this->fingerprint.json_encode($first,JSON_UNESCAPED_SLASHES));
    }
    public function __debugInfo():array{return ['fence_state_snapshot'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload exact fence source declarations.','configuration.state_snapshot');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize fence sources.','configuration.state_snapshot');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State sources are immutable.','configuration.immutable');}
}
