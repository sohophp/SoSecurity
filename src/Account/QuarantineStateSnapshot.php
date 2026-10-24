<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\FileStateBoundary;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Upload\Policy;
use SoSecurity\Upload\QuarantineFiles;
use SoSecurity\Upload\QuarantineState;

/** Complete bounded private quarantine content, including the permanent writer lock. No provisioning or scanning. */
final class QuarantineStateSnapshot implements StateSnapshot
{
    private $dependencies;
    private $fingerprint;
    public function __construct(PDO $pdo,string $profile,string $directory,string $documentRoot,Policy $policy,int $maximumFiles=64,int $maximumBytes=67108864,int $milliseconds=10000)
    {
        Guard::label($profile);new Deadline($milliseconds);
        if(preg_match('//u',$profile)!==1||$maximumFiles<1||$maximumFiles>64||$maximumBytes<1||$maximumBytes>1073741824){self::invalid();}
        $files=new QuarantineFiles($directory,$documentRoot,$policy);$stat=@lstat($directory);if(!is_array($stat)){self::invalid();}$binding=$files->binding();
        $domain=hash('sha256','SoSecurity.FileStore.Directory.1.'.base64_encode($directory).':'.$stat['dev'].':'.$stat['ino'].':'.$stat['uid']);
        $this->dependencies=static function()use($pdo,$directory,$stat,$policy,$maximumFiles,$maximumBytes,$milliseconds,$binding,$domain):array{return compact('pdo','directory','stat','policy','maximumFiles','maximumBytes','milliseconds','binding','domain');};
        $this->fingerprint=hash('sha256','SoSecurity.QuarantineSnapshot.Profile.1.'.json_encode([$profile,$binding,$policy->options(),$maximumFiles,$maximumBytes]));
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use exact private quarantine content and bounded policy.','configuration.quarantine_snapshot');}
    /** @return never */
    private static function corrupt():void{throw new StorageException('Quarantine content is missing, changed or outside its declared bound.','account.quarantine_snapshot_corrupt');}
    private function d():array{return ($this->dependencies)();}
    private function directory():void
    {
        $d=$this->d();clearstatcache(true,$d['directory']);$s=@lstat($d['directory']);
        if(!is_array($s)||realpath($d['directory'])!==$d['directory']||($s['mode']&0170777)!==0040700||$s['dev']!==$d['stat']['dev']||$s['ino']!==$d['stat']['ino']||$s['uid']!==$d['stat']['uid']){self::corrupt();}
    }
    private function regular(array $s,bool $lock):void
    {
        $d=$this->d();if(($s['mode']&0170777)!==0100600||$s['uid']!==$d['stat']['uid']||$s['nlink']!==1||($lock?$s['size']!==0:($s['size']<1||$s['size']>$d['policy']->maximumBytes()))){self::corrupt();}
    }
    private function scan(Deadline $deadline):array
    {
        $d=$this->d();$this->directory();$rows=[];$total=0;$count=0;
        try{$iterator=new \DirectoryIterator($d['directory']);}catch(\Throwable $error){self::corrupt();}
        foreach($iterator as $entry){
            $deadline->check('account.snapshot_timeout');if($entry->isDot()){continue;}$name=$entry->getFilename();$lock=$name==='.quarantine.lock';
            if(!$lock&&(!preg_match('/\A[a-f0-9]{32}\.([a-z0-9]{1,8})\z/D',$name,$parts)||QuarantineState::mime($d['policy'],$parts[1])===null||++$count>$d['maximumFiles'])){self::corrupt();}
            $path=$d['directory'].'/'.$name;clearstatcache(true,$path);$before=@lstat($path);if(!is_array($before)){self::corrupt();}$this->regular($before,$lock);
            $total+=$before['size'];if($total>$d['maximumBytes']){self::corrupt();}$handle=@fopen($path,'rb');if($handle===false){self::corrupt();}
            try{
                $opened=fstat($handle);if(!is_array($opened)){self::corrupt();}$this->regular($opened,$lock);
                if($opened['dev']!==$before['dev']||$opened['ino']!==$before['ino']||$opened['size']!==$before['size']){self::corrupt();}
                $hash=hash_init('sha256');$read=0;
                while($read<$opened['size']){$deadline->check('account.snapshot_timeout');$chunk=@stream_get_contents($handle,min(8192,$opened['size']-$read));if(!is_string($chunk)||$chunk===''){self::corrupt();}$read+=strlen($chunk);hash_update($hash,$chunk);}
                if(@stream_get_contents($handle,1)!==''){self::corrupt();}$deadline->check('account.snapshot_timeout');$after=fstat($handle);clearstatcache(true,$path);$named=@lstat($path);if(!is_array($after)||!is_array($named)){self::corrupt();}
                foreach([$after,$named] as $s){$this->regular($s,$lock);foreach(['dev','ino','size','mtime','ctime'] as $field){if($s[$field]!==$opened[$field]){self::corrupt();}}}
                $rows[$name]=[$read,hash_final($hash),$lock?[$opened['dev'],$opened['ino']]:null];
            }finally{fclose($handle);}
        }
        $this->directory();ksort($rows,SORT_STRING);return ['files'=>$rows,'bytes'=>$total,'count'=>$count];
    }
    private function observe():array
    {
        $deadline=new Deadline($this->d()['milliseconds']);$one=$this->scan($deadline);$two=$this->scan($deadline);if($one!==$two){self::corrupt();}return $one;
    }
    public function connection():PDO{return $this->d()['pdo'];}
    public function fingerprint():string{return $this->fingerprint;}
    public function storageDomains():array{$this->directory();$d=$this->d();return [StateStorageDomain::directory($d['directory'],$d['stat'])];}
    public function matches(QuarantineFiles $files,Policy $policy,int $maximumFiles,int $maximumBytes):bool
    {
        $d=$this->d();return $files->binding()===$d['binding']&&$policy->options()===$d['policy']->options()&&$maximumFiles===$d['maximumFiles']&&$maximumBytes===$d['maximumBytes'];
    }
    public function canAdd(int $bytes):bool
    {
        $d=$this->d();if($bytes<1||$bytes>$d['policy']->maximumBytes()){return false;}$v=$this->observe();return $v['count']<$d['maximumFiles']&&$bytes<=$d['maximumBytes']-$v['bytes'];
    }
    public function digest():string{return hash('sha256','SoSecurity.QuarantineSnapshot.1.'.$this->fingerprint.json_encode($this->observe()));}
    /** Bind all existing/new SDK writers on this exact physical directory; never initialize or authorize business work. */
    public function protect(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,string $name):void
    {
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->coversSnapshot($source)||!$source->contains($name,$this)||!$witness->usesConnection($this->connection())){self::invalid();}
        $this->directory();FileStateBoundary::bind($this->d()['domain'],$boundary->sqlGuard($this->connection()));
    }
    public function __debugInfo():array{return ['quarantine_state_snapshot'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
