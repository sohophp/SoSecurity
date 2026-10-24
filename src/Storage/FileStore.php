<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SystemClock;

/** Local filesystem only. Private directory must be owned by the application, outside web root. */
final class FileStore implements AtomicStore
{
    private $directory;
    private $namespace;
    private $snapshotBinding;
    private $clock;
    private $lockTimeoutMs;
    private $pruneIterator;

    public function __construct(string $directory, string $namespace, ?Clock $clock = null, int $lockTimeoutMs = 1000)
    {
        Guard::label($namespace);
        new Deadline($lockTimeoutMs);
        $this->lockTimeoutMs = $lockTimeoutMs;
        $real = realpath($directory);
        if ($real === false || !is_dir($real) || !is_writable($real) || (fileperms($real) & 0077) !== 0) {
            throw new StorageException('Use an existing writable private directory (0700).');
        }
        $stat=@lstat($real);if(!is_array($stat)||($stat['mode']&0170000)!==0040000){throw new StorageException('Cannot bind security state directory.','storage.io');}$this->snapshotBinding=hash('sha256','SoSecurity.FileStore.Directory.1.'.base64_encode($real).':'.$stat['dev'].':'.$stat['ino'].':'.$stat['uid']);
        $this->directory = $real;
        $this->namespace = $namespace;
        $this->clock = $clock ?? new SystemClock();
    }

    /** Pure physical metadata: directory identity alone does not bind the store namespace. */
    public function snapshotFile(string $key):string{Guard::label($key);return hash('sha256',$this->namespace."\0".$key).'.json';}
    public function snapshotReference(string $key):array{return ['directory'=>$this->snapshotBinding(),'file'=>$this->snapshotFile($key)];}
    public function snapshotBinding():string{return $this->snapshotBinding;}
    /** Pure clock agreement for native declarations; no state access. */
    public function usesClock(Clock $clock):bool{return $this->clock===$clock||($this->clock instanceof SystemClock&&$clock instanceof SystemClock);}

    /** Bind the original instance as well as wrappers; an existing binding cannot be removed. */
    public function bindStateBoundary(\SoSecurity\Account\StateBoundary $boundary):void
    {
        $boundary->bindFileStore($this);
    }
    private function assertStateActive():void{FileStateBoundary::assertActive($this->snapshotBinding);}

    public function transact(string $key, callable $callback)
    {
        $this->assertStateActive();
        Guard::label($key);
        $hash = hash('sha256', $this->namespace . "\0" . $key);
        return $this->locked($hash, function () use ($hash, $callback) {
            $path = $this->directory . '/' . $hash . '.json';
            $value = null;
            $raw = $this->readFile($path);
            if ($raw !== null) {
                $value = Codec::decode($raw, $this->clock->now());
            }
            $change = $callback($value);
            if (!$change instanceof Change) {
                throw new StorageException('Callback must return Change.');
            }
            $this->assertStateActive();
            if ($change->value() === null) {
                if (file_exists($path) && !@unlink($path)) {
                    throw new StorageException('Cannot delete security state.', 'storage.io');
                }
            } else {
                $json = Codec::encode($change);
                $temporary = FileStateBoundary::bound($this->snapshotBinding) ? $this->containmentStagePath($hash) : @tempnam($this->directory, '.write-');
                if ($temporary === false || dirname($temporary) !== $this->directory) {
                    if ($temporary !== false) { @unlink($temporary); }
                    throw new StorageException('Cannot allocate private security state.', 'storage.io');
                }
                try {
                    if (!@chmod($temporary, 0600) || @file_put_contents($temporary, $json) !== strlen($json)
                        || !@rename($temporary, $path)) {
                        throw new StorageException('Cannot commit security state.', 'storage.io');
                    }
                } finally {
                    if (file_exists($temporary)) {
                        @unlink($temporary);
                    }
                }
            }
            return $change->result();
        });
    }

    /** @internal Fixed durable raw-byte CAS. It never treats an expired container as an absent file. */
    public function containState(string $key,\SoSecurity\Account\StateFactorContainment $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    { $this->writeContainment($key,$plan,$witness,$operation); }
    /** @internal Only a fresh exact resolution capability can converge a sealed physical effect. */
    public function resolveState(string $key,\SoSecurity\Account\StateFactorResolution $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    { $this->writeContainment($key,$plan,$witness,$operation); }
    public function installCredentialState(string $key,\SoSecurity\Account\StateCredentialInstallation $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    {$this->writeContainment($key,$plan,$witness,$operation);}
    public function retireApiKeyState(string $key,\SoSecurity\Account\StateApiKeyRetirement $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void{$this->writeContainment($key,$plan,$witness,$operation);}
    public function retireProofState(string $key,\SoSecurity\Account\StateProofRetirement $plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void{$this->writeContainment($key,$plan,$witness,$operation);}
    /** @param \SoSecurity\Account\StateProofRetirement|\SoSecurity\Account\StateApiKeyRetirement|\SoSecurity\Account\StateFactorContainment|\SoSecurity\Account\StateFactorResolution|\SoSecurity\Account\StateCredentialInstallation $plan */
    private function writeContainment(string $key,$plan,\SoSecurity\Account\LocalStateWitness $witness,string $operation):void
    {
        Guard::label($key);$plan->guard($witness,$operation);$this->containmentDirectory();$hash=hash('sha256',$this->namespace."\0".$key);$path=$this->directory.'/'.$hash.'.json';$lock=$this->directory.'/lock-'.(hexdec(substr($hash,0,2))%64);$owner=self::containmentOwner();$handle=null;$temporary=null;$file=null;
        $handle=$this->containmentOpenLock($lock);
        try{
            $this->containmentNode($handle,$lock);$deadline=new Deadline($this->lockTimeoutMs);
            while(!@flock($handle,LOCK_EX|LOCK_NB,$blocked)){if(!$blocked){throw new StorageException('Cannot acquire containment lock.','storage.io');}$deadline->check('storage.lock_timeout');usleep(1000);}
            $check=function()use($owner,$handle,$lock,$plan,$witness,$operation):void{if(self::containmentOwner()!==$owner){throw new StorageException('Containment file owner changed.','account.factor_context');}$this->containmentDirectory();$this->containmentNode($handle,$lock);$plan->guard($witness,$operation);};$check();$raw=$this->containmentRead($path);$next=$plan->replacement($witness,$operation,$this,$key,$raw);
            $temporary=$this->containmentStagePath($hash);$file=@fopen($temporary,'r+b');$this->containmentNode($file,$temporary);
            if(!@ftruncate($file,0)||!rewind($file)||fwrite($file,$next)!==strlen($next)||!fflush($file)){throw new StorageException('Cannot write containment file.','storage.io');}
            $plan->persist($witness,$operation,$this,$key,$file);$check();$this->containmentNode($file,$temporary);if($this->containmentRead($temporary)!==$next||$this->containmentRead($path)!==$raw){throw new StorageException('Factor or temporary bytes changed before rename.','account.factor_cas');}
            if(!@rename($temporary,$path)){throw new StorageException('Cannot commit containment file.','storage.io');}$temporary=null;$this->containmentNode($file,$path);$plan->persist($witness,$operation,$this,$key,$file);$check();$this->containmentNode($file,$path);
            if($this->containmentRead($path)!==$next){throw new StorageException('Contained factor changed during persistence.','account.factor_cas');}
        }finally{
            $same=self::containmentOwner()===$owner;if($same&&is_string($temporary)&&dirname($temporary)===$this->directory){@unlink($temporary);}if(is_resource($file)&&($same||getmypid()!==$owner[0])){fclose($file);}if(is_resource($handle)){if($same){@flock($handle,LOCK_UN);}if($same||getmypid()!==$owner[0]){fclose($handle);}}
        }
    }
    private function containmentOpenLock(string $path)
    {
        $this->containmentDirectory();clearstatcache(true,$path);
        if(@lstat($path)===false){
            // No temporary seed: death between creation and return leaves only a permanent empty stripe.
            $mask=umask(0077);try{$h=@fopen($path,'x+b');}finally{umask($mask);}
            if(is_resource($h)){try{$this->containmentNode($h,$path);return $h;}catch(\Throwable $e){fclose($h);throw $e;}}
        }
        $h=@fopen($path,'r+b');try{$this->containmentNode($h,$path);return $h;}catch(\Throwable $e){if(is_resource($h)){fclose($h);}throw $e;}
    }
    /** One bounded uncommitted slot per permanent stripe. It is never decoded or adopted as state. */
    private function containmentStagePath(string $hash):string
    {
        $this->containmentDirectory();$path=$this->directory.'/stage-'.(hexdec(substr($hash,0,2))%64);$h=$this->containmentOpenLock($path);
        try{$s=fstat($h);if(!is_array($s)||$s['size']<0||$s['size']>65536){throw new StorageException('Uncommitted state exceeds its fixed slot bound.','storage.capacity');}$this->containmentNode($h,$path);return $path;}finally{fclose($h);}
    }
    private static function containmentOwner():array{$pid=getmypid();if(!is_int($pid)||$pid<1){throw new StorageException('Cannot identify containment process.','account.factor_context');}return [$pid,PHP_VERSION_ID>=80100&&class_exists('Fiber',false)?\Fiber::getCurrent():null];}
    private function containmentDirectory():void
    {
        clearstatcache(true,$this->directory);$stat=@lstat($this->directory);if(realpath($this->directory)!==$this->directory||!is_array($stat)||($stat['mode']&0170777)!==0040700||!is_readable($this->directory)||!is_writable($this->directory)||hash('sha256','SoSecurity.FileStore.Directory.1.'.base64_encode($this->directory).':'.$stat['dev'].':'.$stat['ino'].':'.$stat['uid'])!==$this->snapshotBinding){throw new StorageException('Containment directory changed.','storage.corrupt');}
    }
    private function containmentNode($handle,string $path):void
    {
        clearstatcache(true,$path);$a=is_resource($handle)?@fstat($handle):false;$b=@lstat($path);$directory=@lstat($this->directory);if(!is_array($a)||!is_array($b)||!is_array($directory)||($a['mode']&0170777)!==0100600||($b['mode']&0170777)!==0100600||$a['nlink']!==1||$b['nlink']!==1||$a['uid']!==$directory['uid']||$a['dev']!==$b['dev']||$a['ino']!==$b['ino']||$a['uid']!==$b['uid']){throw new StorageException('Containment file descriptor/path changed.','storage.corrupt');}
    }
    private function containmentRead(string $path):?string
    {
        clearstatcache(true,$path);$stat=@lstat($path);if($stat===false){return null;}$file=@fopen($path,'rb');if(!is_resource($file)){throw new StorageException('Cannot read containment bytes.','storage.io');}
        try{$this->containmentNode($file,$path);$raw=stream_get_contents($file,65537);$this->containmentNode($file,$path);$after=fstat($file);if(!is_string($raw)||strlen($raw)>65536||$after['size']!==strlen($raw)){throw new StorageException('Containment bytes exceed their bound or changed.','storage.capacity');}return $raw;}finally{fclose($file);}
    }

    /** Compatibility helper: one bounded batch, not an unbounded directory walk. */
    public function prune(int $limit = 1000): int
    {
        return $this->pruneBatch($limit)->removed();
    }

    /** Repeat on the SAME instance until complete(); no global cursor file or lock-file deletion. */
    public function pruneBatch(int $limit = 1000): PruneResult
    {
        $this->assertStateActive();
        if ($limit < 1 || $limit > 10000) {
            throw new \SoSecurity\Exception\ConfigurationException('Prune batch must contain 1-10000 directory entries.');
        }
        if ($this->pruneIterator === null) {
            try { $this->pruneIterator = new \DirectoryIterator($this->directory); }
            catch (\UnexpectedValueException $e) { throw new StorageException('Cannot scan security storage.', 'storage.io', $e); }
        }
        $removed = 0;
        $scanned = 0;
        while ($this->pruneIterator->valid() && $scanned < $limit) {
            $filename = $this->pruneIterator->getFilename();
            $path = $this->pruneIterator->getPathname();
            $this->pruneIterator->next();
            ++$scanned;
            if (!preg_match('/^([a-f0-9]{64})\.json$/D', $filename, $matches)) { continue; }
            $removed += $this->locked($matches[1], function () use ($path) {
                $raw = $this->readFile($path);
                if ($raw === null) { return 0; }
                if (Codec::decode($raw, $this->clock->now()) === null) {
                    if (!@unlink($path)) { throw new StorageException('Cannot prune security state.', 'storage.io'); }
                    return 1;
                }
                return 0;
            });
        }
        $complete = !$this->pruneIterator->valid();
        if ($complete) { $this->pruneIterator = null; }
        return new PruneResult($removed, $scanned, $complete);
    }

    private function sameNode(array $a,array $b,bool $stable=true):bool
    {
        $keys=$stable?['dev','ino','mode','uid','nlink','size','mtime','ctime']:['dev','ino','uid','nlink','size'];
        foreach($keys as $key){if($a[$key]!==$b[$key]){return false;}}return true;
    }
    private function regularNode($handle,string $path,int $maximum,bool $stable=true):array
    {
        clearstatcache(true,$path);$opened=is_resource($handle)?@fstat($handle):false;$named=@lstat($path);
        if(!is_array($opened)||!is_array($named)||($opened['mode']&0170000)!==0100000||($named['mode']&0170000)!==0100000||!$this->sameNode($opened,$named,$stable)){
            throw new StorageException('Security storage node is not a stable regular file.','storage.corrupt');
        }
        if($opened['size']<0||$opened['size']>$maximum){throw new StorageException('Security storage node exceeds its byte bound.','storage.capacity');}
        return $opened;
    }
    private function readFile(string $path):?string
    {
        clearstatcache(true,$path);$before=@lstat($path);if($before===false){return null;}
        if(($before['mode']&0170000)!==0100000){throw new StorageException('Security state must be a regular file.','storage.corrupt');}
        if($before['size']<0||$before['size']>65536){throw new StorageException('State exceeds 64 KiB.','storage.capacity');}
        // n requests O_NONBLOCK on supported local Unix streams, including the open itself.
        // Keep read-only access: opening a node replaced by a FIFO must not wait for a writer.
        $handle=@fopen($path,'rbn');if(!is_resource($handle)){throw new StorageException('Cannot read security state.','storage.io');}
        try{
            $opened=$this->regularNode($handle,$path,65536);if(!$this->sameNode($before,$opened)){throw new StorageException('Security state changed before reading.','storage.corrupt');}
            $raw=@stream_get_contents($handle,65537);if(!is_string($raw)){throw new StorageException('Cannot read security state.','storage.io');}$after=$this->regularNode($handle,$path,65536);
            if(strlen($raw)!==$before['size']||!$this->sameNode($before,$after)){throw new StorageException('Security state changed while reading.','storage.corrupt');}
            return $raw;
        }finally{fclose($handle);}
    }

    private function locked(string $hash, callable $operation)
    {
        $guarded=FileStateBoundary::bound($this->snapshotBinding);$owner=$guarded?self::containmentOwner():null;
        // 64 permanent lock stripes bound lock-file growth, even with attacker-chosen keys.
        $path = $this->directory . '/lock-' . (hexdec(substr($hash, 0, 2)) % 64);
        if (is_link($path)) {
            throw new StorageException('Symlinks are forbidden in security storage.');
        }
        clearstatcache(true,$path);$node=@lstat($path);
        if(is_array($node)&&($node['mode']&0170000)!==0100000){throw new StorageException('Security locks must be regular files.','storage.corrupt');}
        $handle = @fopen($path, 'cn');
        if ($handle === false) {
            throw new StorageException('Cannot open security lock.', 'storage.io');
        }
        try {
            // Other valid waiters chmod this same empty stripe before acquiring it.
            // Keep exact identity and size checks without treating that metadata refresh as replacement.
            $this->regularNode($handle,$path,0,false);
            if (!@chmod($path, 0600)) { throw new StorageException('Cannot secure lock permissions.', 'storage.io'); }
            $deadline = new Deadline($this->lockTimeoutMs);
            while (!@flock($handle, LOCK_EX | LOCK_NB, $wouldBlock)) {
                if (!$wouldBlock) { throw new StorageException('Cannot acquire security lock.', 'storage.io'); }
                $deadline->check('storage.lock_timeout');
                usleep((int) min(1000, max(1, $deadline->remaining() * 1000000)));
            }
            $deadline->check('storage.lock_timeout');
            $this->regularNode($handle,$path,0,false);
            return $operation();
        } finally {
            $same=!$guarded||self::containmentOwner()===$owner;
            if($same){@flock($handle, LOCK_UN);}
            if($same||getmypid()!==$owner[0]){fclose($handle);}
        }
    }
}
