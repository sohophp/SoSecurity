<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;

/** Candidate: complete raw FileStore state. All writers must share the outer witness lock. */
final class FileStateSnapshot implements StateStoreSource
{
    private $dependencies;
    private $fingerprint;
    private $maximumFiles;
    private $milliseconds;
    private $busy=false;

    public function __construct(PDO $pdo,string $profile,string $directory,string $scratch,int $maximumFiles=100000,int $milliseconds=10000)
    {
        Guard::label($profile);new Deadline($milliseconds);
        if(preg_match('//u',$profile)!==1||$maximumFiles<1||$maximumFiles>1000000){self::configuration();}
        $source=self::directory($directory);$temporary=self::directory($scratch);
        if($source['uid']!==$temporary['uid']||$directory===$scratch||strpos($scratch,$directory.'/')===0||strpos($directory,$scratch.'/')===0){self::configuration();}
        $this->dependencies=static function()use($pdo,$directory,$scratch,$source,$temporary):array{return [$pdo,$directory,$scratch,$source,$temporary];};
        $this->maximumFiles=$maximumFiles;$this->milliseconds=$milliseconds;
        $this->fingerprint=hash('sha256','SoSecurity.State.FileSnapshot.Profile.2.'.json_encode([$profile,base64_encode($directory),$source['dev'],$source['ino'],$source['uid'],$maximumFiles],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    }
    /** @return never */
    private static function configuration():void{throw new ConfigurationException('Use distinct canonical private state and scratch directories with bounded capacity.','configuration.state_snapshot');}
    private static function directory(string $path):array
    {
        clearstatcache(true,$path);$s=@lstat($path);
        if(realpath($path)!==$path||!is_array($s)||($s['mode']&0177777)!==0040700){self::configuration();}return $s;
    }
    private function directories():array
    {
        $d=($this->dependencies)();foreach([[1,3],[2,4]] as $pair){$s=self::directory($d[$pair[0]]);$before=$d[$pair[1]];if($s['dev']!==$before['dev']||$s['ino']!==$before['ino']||$s['uid']!==$before['uid']){self::corrupt();}}return $d;
    }
    /** @return never */
    private static function corrupt():void{throw new StorageException('Physical state differs from its exact private FileStore contract.','account.snapshot_corrupt');}
    public function storageDomains():array{$d=$this->directories();return [StateStorageDomain::directory($d[1],$d[3]),StateStorageDomain::directory($d[2],$d[4])];}
    public function connection():PDO{return (($this->dependencies)())[0];}
    public function fingerprint():string{return $this->fingerprint;}
    public function coversStore(\SoSecurity\Storage\AtomicStore $store):bool
    {
        for($i=0;$store instanceof \SoSecurity\Storage\NamespacedStore&&$i<16;++$i){$store=$store->underlying();}
        $d=($this->dependencies)();$s=$d[3];$binding=hash('sha256','SoSecurity.FileStore.Directory.1.'.base64_encode($d[1]).':'.$s['dev'].':'.$s['ino'].':'.$s['uid']);
        return $store instanceof \SoSecurity\Storage\FileStore&&$store->snapshotBinding()===$binding;
    }
    public function coversReference(array $reference):bool{$d=($this->dependencies)();$s=$d[3];return array_keys($reference)===['directory','file']&&is_string($reference['directory'])&&is_string($reference['file'])&&preg_match('/\A[a-f0-9]{64}\.json\z/D',$reference['file'])===1&&$reference['directory']===hash('sha256','SoSecurity.FileStore.Directory.1.'.base64_encode($d[1]).':'.$s['dev'].':'.$s['ino'].':'.$s['uid']);}
    private function regular(string $path,int $owner,int $maximum):array
    {
        clearstatcache(true,$path);$s=@lstat($path);
        if(!is_array($s)||($s['mode']&0177777)!==0100600||$s['uid']!==$owner||$s['nlink']!==1||$s['size']<0||$s['size']>$maximum){self::corrupt();}return $s;
    }
    private function same(array $a,array $b):bool
    {
        foreach(['dev','ino','mode','uid','nlink','size','mtime','ctime'] as $key){if($a[$key]!==$b[$key]){return false;}}return true;
    }
    private function file(string $path,int $owner,Deadline $deadline,bool $capture):array
    {
        // r+b never creates or writes. On local Unix it also avoids waiting for a
        // writer if a racing replacement is a FIFO; fstat must pass before reading.
        $before=$this->regular($path,$owner,65536);$h=@fopen($path,'r+b');if($h===false){self::corrupt();}
        try{
            $opened=fstat($h);if(!is_array($opened)||!$this->same($before,$opened)){self::corrupt();}
            $raw=stream_get_contents($h,min(65537,$before['size']+1));$after=fstat($h);$pathStat=$this->regular($path,$owner,65536);
            if(!is_string($raw)||strlen($raw)!==$before['size']||!is_array($after)||!$this->same($before,$after)||!$this->same($before,$pathStat)){self::corrupt();}
            $deadline->check('account.snapshot_timeout');return [hash('sha256',$raw,true),$capture?$raw:null];
        }finally{fclose($h);}
    }
    /** @return resource */
    private function create(string $directory,array &$owned,string &$path)
    {
        $path=$directory.'/'.bin2hex(random_bytes(16)).'.run';$h=@fopen($path,'x+b');if($h===false){self::corrupt();}$owned[$path]=true;
        if(!@chmod($path,0600)){fclose($h);self::corrupt();}return $h;
    }
    /** @param resource $handle */
    private function write($handle,string $record):void
    {
        if(strlen($record)!==96||fwrite($handle,$record)!==96){self::corrupt();}
    }
    /** @param resource $handle */
    private function read($handle):?string
    {
        $raw=stream_get_contents($handle,96);if($raw===false){self::corrupt();}if($raw===''&&feof($handle)){return null;}
        if(strlen($raw)!==96||!preg_match('/\A[a-f0-9]{64}\z/D',substr($raw,0,64))){self::corrupt();}return $raw;
    }
    private function unlink(string $path,array &$owned):void
    {
        if(!isset($owned[$path])||!@unlink($path)){self::corrupt();}unset($owned[$path]);
    }
    private function merge(array $runs,string $directory,array &$owned,Deadline $deadline):string
    {
        $out='';$target=$this->create($directory,$owned,$out);$handles=[];$heads=[];$previous=null;
        try{
            foreach($runs as $i=>$path){$h=@fopen($path,'rb');if($h===false){self::corrupt();}$handles[$i]=$h;$heads[$i]=$this->read($h);}
            while(true){
                $minimum=null;foreach($heads as $i=>$head){if($head!==null&&($minimum===null||strcmp(substr($head,0,64),substr($heads[$minimum],0,64))<0)){$minimum=$i;}}
                if($minimum===null){break;}$record=$heads[$minimum];$key=substr($record,0,64);
                if($previous!==null&&strcmp($previous,$key)>=0){self::corrupt();}$previous=$key;$this->write($target,$record);$heads[$minimum]=$this->read($handles[$minimum]);$deadline->check('account.snapshot_timeout');
            }
        }finally{foreach($handles as $h){fclose($h);}fclose($target);}
        foreach($runs as $path){$this->unlink($path,$owned);}return $out;
    }
    private function add(string $run,int $level,array &$levels,string $directory,array &$owned,Deadline $deadline):void
    {
        if(!isset($levels[$level])){$levels[$level]=[];}$levels[$level][]=$run;
        if(count($levels[$level])===16){$combined=$this->merge($levels[$level],$directory,$owned,$deadline);$levels[$level]=[];$this->add($combined,$level+1,$levels,$directory,$owned,$deadline);}
    }
    private function chunk(array &$chunk,array &$levels,string $directory,array &$owned,Deadline $deadline):void
    {
        if(!$chunk){return;}ksort($chunk,SORT_STRING);$path='';$h=$this->create($directory,$owned,$path);
        try{foreach($chunk as $key=>$digest){$this->write($h,$key.$digest);}}finally{fclose($h);}$chunk=[];$this->add($path,0,$levels,$directory,$owned,$deadline);
    }
    private function scan(array $selectors):array
    {
        if($this->busy){throw new StorageException('State snapshot is already active.','account.snapshot_busy');}$d=$this->directories();$deadline=new Deadline($this->milliseconds);$work=$d[2].'/snapshot-'.bin2hex(random_bytes(16));
        if(!@mkdir($work,0700)){self::corrupt();}$this->busy=true;$owned=[];$iterator=null;$captured=array_fill_keys(array_keys($selectors),null);$requested=array_fill_keys(array_values($selectors),true);
        try{
            $iterator=@opendir($d[1]);if($iterator===false){self::corrupt();}$chunk=[];$levels=[];$count=0;
            while(($name=readdir($iterator))!==false){
                $deadline->check('account.snapshot_timeout');if($name==='.'||$name==='..'){continue;}$path=$d[1].'/'.$name;
                if(preg_match('/\Alock-(?:[0-9]|[1-5][0-9]|6[0-3])\z/D',$name)){$this->regular($path,$d[3]['uid'],0);continue;}
                if(!preg_match('/\A([a-f0-9]{64})\.json\z/D',$name,$m)){self::corrupt();}
                if(++$count>$this->maximumFiles){throw new StorageException('Physical snapshot capacity exceeded.','account.snapshot_capacity');}
                if(isset($chunk[$m[1]])){self::corrupt();}$read=$this->file($path,$d[3]['uid'],$deadline,isset($requested[$name]));$chunk[$m[1]]=$read[0];
                if(isset($requested[$name])){foreach($selectors as $alias=>$filename){if($filename===$name){if($captured[$alias]!==null){self::corrupt();}$captured[$alias]=$read[1];}}}
                if(count($chunk)===256){$this->chunk($chunk,$levels,$work,$owned,$deadline);}
            }
            closedir($iterator);$iterator=null;$this->chunk($chunk,$levels,$work,$owned,$deadline);$runs=[];
            foreach($levels as $parts){foreach($parts as $path){$runs[]=$path;}}
            while(count($runs)>1){$next=[];foreach(array_chunk($runs,16) as $parts){$next[]=count($parts)===1?$parts[0]:$this->merge($parts,$work,$owned,$deadline);}$runs=$next;}
            $hash=hash_init('sha256');hash_update($hash,'SoSecurity.State.FileSnapshot.1.'.$this->fingerprint);$observed=0;
            if($runs){$h=@fopen($runs[0],'rb');if($h===false){self::corrupt();}try{while(($record=$this->read($h))!==null){hash_update($hash,$record);++$observed;$deadline->check('account.snapshot_timeout');}}finally{fclose($h);}}
            if($observed!==$count){self::corrupt();}$this->directories();$deadline->check('account.snapshot_timeout');hash_update($hash,':'.$count);return [hash_final($hash),$captured];
        }finally{
            if(is_resource($iterator)){closedir($iterator);}$clean=true;foreach($owned as $path=>$unused){if(!@unlink($path)){$clean=false;}}if(!@rmdir($work)){$clean=false;}$this->busy=false;
            if(!$clean){throw new StorageException('Physical snapshot scratch cleanup was not confirmed.','account.snapshot_cleanup');}
        }
    }
    /** Pure normalization: no directory reads, file opens or scratch creation. */
    public function selections(array $selectors):array
    {
        if(count($selectors)<1||count($selectors)>4){self::configuration();}$copy=[];
        foreach($selectors as $alias=>$filename){if(!is_string($alias)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$alias)||!is_string($filename)||!preg_match('/\A[a-f0-9]{64}\.json\z/D',$filename)){self::configuration();}$copy[$alias]=$filename;}return $copy;
    }
    /** Copy only the bytes actually hashed during this complete physical scan. */
    public function capture(array $selectors):FileStateCapture{$result=$this->scan($this->selections($selectors));return new FileStateCapture($this,$result[0],$result[1]);}
    public function digest():string{return $this->scan([])[0];}
    public function __debugInfo():array{return ['file_state_snapshot'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload explicit state snapshot declarations.','configuration.state_snapshot');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize physical state sources.','configuration.state_snapshot');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State sources are immutable.','configuration.immutable');}
}
