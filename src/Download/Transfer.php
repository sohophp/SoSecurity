<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SystemClock;

/** Immediate private response. Host owns headers/output; never log/copy/cache this as future authorization. */
final class Transfer
{
    private $file;
    private $request;
    private $grant;
    private $policy;
    private $reader;
    private $closer;
    private $reload;
    private $clock;
    private $seen;
    private $deadline;
    private $selection;
    private $read=0;
    private $closed=false;
    private $complete=false;
    private $busy=false;
    private $failed=false;
    /** Trusted transport adapter construction; normally obtained only through Downloads::prepare(). */
    public function __construct(File $file,Request $request,Grant $grant,Policy $policy,callable $reader,callable $closer,callable $reload,?Clock $clock=null)
    {
        $this->file=$file;$this->request=$request;$this->grant=$grant;$this->policy=$policy;$this->reader=$reader;$this->closer=$closer;$this->reload=$reload;$this->clock=$clock ?? new SystemClock();$this->seen=Time::now($this->clock);$this->deadline=new Deadline($policy->sendMilliseconds());$this->selection=Selection::choose($file,$request,$grant,$policy);
    }
    /** A callback cannot consume this response again, even if it catches the refusal. */
    private function operation(callable $body)
    {
        if($this->busy){$this->failed=true;$this->complete=false;$this->close();throw new StorageException('Download transfer cannot be reentered.','download.reentrant');}
        $this->assertUsable();
        $this->busy=true;
        try{return $body();}finally{$this->busy=false;}
    }
    private function assertUsable():void
    {if($this->failed){throw new StorageException('Download transfer has failed.','download.closed');}}
    private function check():void
    {
        if($this->closed){throw new StorageException('Download transfer is closed.','download.closed');}$this->checkAuthority();
    }
    /** Also valid after closing the private snapshot; closing does not freeze host authority. */
    private function checkAuthority():void
    {
        $this->assertUsable();
        $this->deadline->check('download.timeout');$now=Time::advance($this->clock,$this->seen);
        try{$file=($this->reload)();}catch(SecurityException $error){throw $error;}catch(\Throwable $error){throw new DependencyException('Download metadata authority unavailable.','download.metadata_unavailable');}
        if(!$file instanceof File||!hash_equals($this->file->fingerprint(),$file->fingerprint())||!$this->grant->check($file,$now)){throw new SecurityException('Download authority or version changed.','download.denied');}
        $this->assertUsable();
        $this->deadline->check('download.timeout');$now=Time::advance($this->clock,$this->seen);if($now>=$this->grant->expiresAt()){throw new SecurityException('Download authorization expired during I/O.','download.expired');}
    }
    private function guardedCheck():void {try{$this->check();}catch(\Throwable $error){$this->close();throw $error;}}
    public function status():int {return $this->operation(function():int{if(!$this->complete){$this->guardedCheck();}return $this->selection['status'];});}
    public function headers():array {return $this->operation(function():array{if(!$this->complete){$this->guardedCheck();}return $this->selection['headers'];});}
    public function bytesRead():int {return $this->read;}
    public function complete():bool {return $this->complete;}
    public function read(int $maximum=65536):string
    {return $this->operation(function()use($maximum):string{return $this->readInternal($maximum);});}
    private function readInternal(int $maximum=65536):string
    {
        if($maximum<1||$maximum>262144){throw new ValidationException('Invalid download read length.','download.read');}if($this->complete){return '';}
        try{
            $this->check();$remaining=$this->request->method()==='HEAD'?0:$this->selection['length']-$this->read;
            if($remaining===0){$this->close();$this->checkAuthority();$this->complete=true;return '';}$limit=min($remaining,$maximum,$this->policy->chunkBytes());
            try{$chunk=($this->reader)($limit);}catch(\Throwable $error){throw new StorageException('Private download snapshot unavailable.','download.io');}
            if(!is_string($chunk)||strlen($chunk)<1||strlen($chunk)>$limit){throw new StorageException('Private snapshot returned an invalid byte count.','download.io');}
            // Re-read authority after snapshot I/O: absolute expiry alone does not cover idle expiry,
            // account revocation, policy changes or a resource version changing while the read blocks.
            $this->check();
            $this->read+=strlen($chunk);if($this->read===$this->selection['length']){$this->close();$this->checkAuthority();$this->complete=true;}return $chunk;
        }catch(\Throwable $error){$this->complete=false;$this->close();throw $error;}
    }
    /** Writer returns the exact accepted byte count. Unknown/partial writes abort; never retry ambiguous output. */
    public function send(callable $writer):int
    {return $this->operation(function()use($writer):int{return $this->sendInternal($writer);});}
    private function sendInternal(callable $writer):int
    {
        $written=0;try{
            while(($chunk=$this->readInternal())!==''){
                $this->checkAuthority();
                try{$count=$writer($chunk);}catch(\Throwable $error){throw new StorageException('Download output writer failed.','download.output');}
                if(!is_int($count)||$count!==strlen($chunk)){throw new StorageException('Download output was partial or unacknowledged.','download.output');}
                // The final read has closed its snapshot; EOF alone must not turn a late writer into success.
                $this->checkAuthority();$written+=$count;
            }
            return $written;
        }catch(\Throwable $error){$this->complete=false;$this->close();throw $error;}
    }
    public function close():void {if(!$this->closed){$this->closed=true;try{($this->closer)();}catch(\Throwable $error){throw new StorageException('Cannot close private transfer.','download.cleanup');}}}
    public function __destruct(){try{$this->close();}catch(\Throwable $error){}}
    public function __debugInfo():array {return ['bytes_read'=>$this->read,'complete'=>$this->complete,'private_transfer'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize prepared downloads.','configuration.download_serialization');}
}
