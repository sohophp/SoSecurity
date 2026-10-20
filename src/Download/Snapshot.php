<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** Internal unlinked POSIX file descriptor. Never expose/reopen a pathname after verification. */
final class Snapshot
{
    private $handle;
    public function __construct($handle){if(!is_resource($handle)||get_resource_type($handle)!=='stream'){throw new ConfigurationException('Expected a private download stream.','configuration.download_snapshot');}$this->handle=$handle;}
    public function write(string $bytes):void
    {
        $position=0;$length=strlen($bytes);while($position<$length){$written=@fwrite($this->handle,substr($bytes,$position));if($written===false||$written===0){throw new StorageException('Cannot complete private snapshot write.','download.io');}$position+=$written;}
    }
    public function rewind(int $offset=0):void {if(!@fflush($this->handle)||@fseek($this->handle,$offset,SEEK_SET)!==0){throw new StorageException('Cannot position private snapshot.','download.io');}}
    public function read(int $length):string {$value=@stream_get_contents($this->handle,$length);if($value===false){throw new StorageException('Cannot read private snapshot.','download.io');}return $value;}
    public function close():void {if(is_resource($this->handle)){$handle=$this->handle;$this->handle=null;if(!@fclose($handle)){throw new StorageException('Cannot close private snapshot.','download.cleanup');}}}
    public function __destruct(){try{$this->close();}catch(\Throwable $error){}}
    public function __debugInfo():array {return ['download_snapshot'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize private streams.','configuration.download_serialization');}
}
