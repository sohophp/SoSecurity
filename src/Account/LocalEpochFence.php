<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;

/** Candidate: one local lock authority, independent of business backups. Never unlink/rename/reopen an epoch. */
final class LocalEpochFence
{
    private $directory;
    private $directoryStat;
    private $path;
    private $context;
    private $keys;
    private $persist;
    private $milliseconds;
    private $busy=false;
    private $inode;
    private $working=false;
    private $closedHandle;
    private $lockOwner;
    private $workOwner;
    private $workHandle;
    private $closedOwner;

    /** persist(resource): true MUST synchronously flush this exact inode to stable storage. */
    public function __construct(string $directory,string $site,string $scope,string $epoch,HmacKeys $keys,callable $persist,int $milliseconds=1000)
    {
        Guard::label($site);Guard::label($scope);
        if(preg_match('//u',$site)!==1||preg_match('//u',$scope)!==1){throw new ConfigurationException('Use UTF-8 fence context labels.','configuration.factor_fence');}
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new ConfigurationException('Use a trusted epoch.','configuration.factor_fence');}
        new Deadline($milliseconds);
        $real=realpath($directory);$stat=@lstat($directory);
        if($real===false||$real!==$directory||!is_array($stat)||($stat['mode']&0170000)!==0040000||($stat['mode']&0077)!==0){throw new ConfigurationException('Use a canonical private local authority directory.','configuration.factor_fence');}
        $this->directory=$real;$this->directoryStat=$stat;$this->context=json_encode(['SoSecurity.Account.LocalEpochFence.1',$site,$scope,$epoch]);
        $this->path=$real.'/'.hash('sha256',$this->context).'.fence';$this->keys=$keys;
        $this->persist=static function($handle)use($persist){return $persist($handle);};$this->milliseconds=$milliseconds;
    }

    /** Trusted first provisioning only. Never call to repair a missing deployed authority or reuse an old epoch. */
    public function initialize():void
    {
        if($this->busy){throw new StorageException('Nested fence operation.','factor.fence_nested');}
        $this->checkDirectory();$owner=self::owner();$this->busy=true;$this->lockOwner=$owner;$handle=false;
        try{
            $handle=@fopen($this->path,'x+b');
            if($handle===false){throw new StorageException('Epoch authority already exists or cannot be created.','factor.fence_exists');}
            if(!@chmod($this->path,0600)){throw new StorageException('Cannot secure epoch authority.','factor.fence_io');}
            $this->validateHandle($handle);$this->acquire($handle,LOCK_EX);
            $this->write($handle,'open');
        }finally{$this->release($handle,$owner);}
    }

    /** Hold across the COMPLETE SQL/external-store operation, including callbacks and finally cleanup. */
    public function work(callable $operation)
    {
        if($this->working){$this->assertContext($this->workOwner);if(!is_resource($this->workHandle)){throw new StorageException('Active fence handle has expired.','factor.fence_context');}$this->validateHandle($this->workHandle);if($this->read($this->workHandle)!=='open'){throw new StorageException('Epoch changed during nested work.','factor.fence_corrupt');}return $operation();}
        return $this->locked(LOCK_SH,function($handle)use($operation){
            if($this->read($handle)!=='open'){throw new StorageException('Epoch is permanently drained.','factor.fence_closed');}
            $this->workOwner=$this->lockOwner;$this->workHandle=$handle;$this->working=true;
            try{$result=$operation();}finally{$this->working=false;$this->workOwner=null;$this->workHandle=null;}
            $this->validateHandle($handle);
            if($this->read($handle)!=='open'){throw new StorageException('Epoch changed during work.','factor.fence_corrupt');}
            return $result;
        });
    }

    /** Permanent close before cleanup. An exception never reopens the epoch; repeated cleanup must be idempotent. */
    public function drain(callable $cleanup,?callable $authorize=null)
    {
        return $this->locked(LOCK_EX,function($handle)use($cleanup,$authorize){
            $state=$this->read($handle);
            if($authorize!==null&&$authorize()!==true){throw new StorageException('Current drain authority required.','factor.fence_denied');}
            $this->validateHandle($handle);
            if($this->read($handle)!==$state){throw new StorageException('Authority changed during drain approval.','factor.fence_corrupt');}
            if($state==='open'){$this->write($handle,'closed');}
            else{$this->sync($handle);}
            $this->validateHandle($handle);
            if($this->read($handle)!=='closed'){throw new StorageException('Closed authority did not persist.','factor.fence_corrupt');}
            $this->closedHandle=$handle;$this->closedOwner=$this->lockOwner;try{$result=$cleanup();}finally{$this->closedHandle=null;$this->closedOwner=null;}$this->validateHandle($handle);
            if($this->read($handle)!=='closed'){throw new StorageException('Cleanup changed authority.','factor.fence_corrupt');}
            return $result;
        });
    }

    /** Only the active, durably closed EX drain callback can lend this context. Never opens or closes an authority. */
    public function closedWork(callable $operation)
    {
        $handle=$this->closedHandle;
        if(!$this->busy||!is_resource($handle)||$this->working){throw new StorageException('An active closed drain context is required.','factor.fence_closed_context');}
        $this->assertContext($this->closedOwner);$this->validateHandle($handle);if($this->read($handle)!=='closed'){throw new StorageException('Closed authority changed.','factor.fence_corrupt');}
        try{return $operation();}finally{$this->validateHandle($handle);if($this->read($handle)!=='closed'){throw new StorageException('Closed authority changed during cleanup.','factor.fence_corrupt');}}
    }

    public function matches(string $site,string $scope,string $epoch):bool {return $this->context===json_encode(['SoSecurity.Account.LocalEpochFence.1',$site,$scope,$epoch]);}
    public function binding():string {return hash('sha256','SoSecurity.Account.LocalEpochFence.Authority.1.'.$this->context.$this->directory.':'.$this->directoryStat['dev'].':'.$this->directoryStat['ino']);}

    private function locked(int $mode,callable $operation)
    {
        if($this->busy){throw new StorageException('Nested fence operation.','factor.fence_nested');}
        $owner=self::owner();$this->busy=true;$this->lockOwner=$owner;$handle=false;
        try{
            $this->checkDirectory();$before=@lstat($this->path);
            if(!is_array($before)){throw new StorageException('Epoch authority is missing.','factor.fence_missing');}
            $this->validateStat($before);$handle=@fopen($this->path,'r+b');
            if($handle===false){throw new StorageException('Cannot open epoch authority.','factor.fence_io');}
            $this->validateHandle($handle,$before);$this->acquire($handle,$mode);$this->validateHandle($handle);
            return $operation($handle);
        }finally{$this->release($handle,$owner);}
    }

    private static function owner():array
    {
        $pid=getmypid();if(!is_int($pid)||$pid<1){throw new StorageException('Cannot identify the fence execution context.','factor.fence_context');}
        $fiber=PHP_VERSION_ID>=80100&&class_exists('Fiber',false)?\Fiber::getCurrent():null;return [$pid,$fiber===null?null:spl_object_id($fiber)];
    }
    private function assertContext(?array $owner):void
    {
        if(!$this->busy||$owner===null||$owner!==self::owner()){throw new StorageException('Fence authority belongs to another execution context.','factor.fence_context');}
    }
    private function release($handle,array $owner):void
    {
        // A fork inherits the open file description. LOCK_UN in the child would also
        // release the parent's lock; closing only this process's descriptor is safe.
        try{if(is_resource($handle)&&$owner===self::owner()){@flock($handle,LOCK_UN);}}
        finally{if(is_resource($handle)){fclose($handle);}$this->lockOwner=null;$this->busy=false;}
    }

    private function acquire($handle,int $mode):void
    {
        $deadline=new Deadline($this->milliseconds);
        while(true){
            $this->assertContext($this->lockOwner);if(@flock($handle,$mode|LOCK_NB,$blocked)){break;}
            if(!$blocked){throw new StorageException('Cannot acquire epoch lock.','factor.fence_io');}
            $deadline->check('factor.fence_timeout');usleep(1000);
        }
        $deadline->check('factor.fence_timeout');
    }

    private function checkDirectory():void
    {
        clearstatcache(true,$this->directory);$stat=@lstat($this->directory);
        if(!is_array($stat)||$stat['dev']!==$this->directoryStat['dev']||$stat['ino']!==$this->directoryStat['ino']||$stat['uid']!==$this->directoryStat['uid']||($stat['mode']&0170077)!==0040000){throw new StorageException('Epoch directory changed.','factor.fence_corrupt');}
    }

    private function validateStat(array $stat):void
    {
        if(($stat['mode']&0170777)!==0100600||$stat['nlink']!==1||$stat['uid']!==$this->directoryStat['uid']||$stat['size']>1024){throw new StorageException('Invalid epoch authority file.','factor.fence_corrupt');}
        $id=$stat['dev'].':'.$stat['ino'];
        if($this->inode!==null&&$this->inode!==$id){throw new StorageException('Epoch authority was replaced.','factor.fence_corrupt');}
    }

    private function validateHandle($handle,?array $before=null):void
    {
        $this->assertContext($this->lockOwner);
        $this->checkDirectory();clearstatcache(true,$this->path);$named=@lstat($this->path);$opened=fstat($handle);
        if(!is_array($named)||!is_array($opened)){throw new StorageException('Epoch authority disappeared.','factor.fence_corrupt');}
        $this->validateStat($named);$this->validateStat($opened);
        foreach([$named,$before ?? $named] as $stat){if($stat['dev']!==$opened['dev']||$stat['ino']!==$opened['ino']){throw new StorageException('Epoch authority inode changed.','factor.fence_corrupt');}}
        $this->inode=$opened['dev'].':'.$opened['ino'];
    }

    private function read($handle):string
    {
        $this->assertContext($this->lockOwner);
        if(!rewind($handle)){throw new StorageException('Cannot seek epoch authority.','factor.fence_io');}
        $raw=stream_get_contents($handle,1025);
        if(!is_string($raw)||strlen($raw)>1024){throw new StorageException('Invalid epoch authority size.','factor.fence_corrupt');}
        $parts=explode("\n",$raw);
        if(count($parts)!==4||$parts[3]!==''||!in_array($parts[0],['open','closed'],true)||!preg_match('/\A[a-f0-9]{64}\z/D',$parts[2])||!$this->keys->verify($parts[1],$this->context."\n".$parts[0],hex2bin($parts[2]))){throw new StorageException('Invalid epoch authority seal.','factor.fence_corrupt');}
        return $parts[0];
    }

    private function write($handle,string $state):void
    {
        $this->assertContext($this->lockOwner);
        $raw=$state."\n".$this->keys->currentId()."\n".bin2hex($this->keys->sign($this->context."\n".$state))."\n";
        if(!rewind($handle)||!ftruncate($handle,0)||fwrite($handle,$raw)!==strlen($raw)||!fflush($handle)){throw new StorageException('Cannot commit epoch authority.','factor.fence_io');}
        $this->sync($handle);
    }

    private function sync($handle):void
    {
        $this->assertContext($this->lockOwner);
        if(($this->persist)($handle)!==true){throw new StorageException('Epoch persistence was not confirmed.','factor.fence_durability');}
        $this->validateHandle($handle);
    }

    public function __debugInfo():array{return ['authority'=>'[private]','epoch'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Reload epoch authority.','configuration.factor_fence');}
    public function __wakeup():void{throw new ConfigurationException('Reload epoch authority.','configuration.factor_fence');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Epoch authority is immutable.','configuration.immutable');}
}
