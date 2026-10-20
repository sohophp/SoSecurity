<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SystemClock;

/** Auth -> fresh metadata -> verified anonymous snapshot -> fresh authority -> bounded immediate transfer. */
final class Downloads
{
    private $reader;
    private $policy;
    private $clock;
    public function __construct(string $directory,string $temporaryDirectory,string $documentRoot,?Policy $policy=null,?Clock $clock=null)
    {
        $this->policy=$policy ?? new Policy();$this->clock=$clock ?? new SystemClock();$this->reader=new LocalReader($directory,$temporaryDirectory,$documentRoot,$this->policy);
    }
    public function policy():Policy {return $this->policy;}
    /** reload(scope,type,id): File|null from the authoritative host index; never accept client metadata. */
    public function prepare(File $file,Request $request,Access $access,callable $reload):Transfer
    {
        $deadline=new Deadline($this->policy->ioMilliseconds());$seen=Time::now($this->clock);
        try{$grant=$access->authorize($file,$request);}catch(ConfigurationException $error){throw $error;}catch(SecurityException $error){throw $error;}catch(\Throwable $error){throw new DependencyException('Download access authority unavailable.','download.authorization_unavailable');}
        if($grant===null){throw new SecurityException('Current download authorization required.','download.denied');}$deadline->check('download.timeout');
        $current=function()use($file,$reload):File{
            $source=$file->sourceResource();try{$fresh=$reload($source->scope(),$source->type(),$source->id());}catch(\Throwable $error){throw new DependencyException('Download metadata source unavailable.','download.metadata_unavailable');}
            if($fresh===null){throw new SecurityException('Download resource no longer available.','download.changed');}
            if(!$fresh instanceof File||$fresh->sourceResource()->scope()!==$source->scope()||$fresh->sourceResource()->type()!==$source->type()||$fresh->sourceResource()->id()!==$source->id()){throw new ConfigurationException('Download metadata source returned another resource.','configuration.download_metadata');}
            if(!hash_equals($file->fingerprint(),$fresh->fingerprint())){throw new SecurityException('Download content/index version changed.','download.changed');}return $fresh;
        };
        $fresh=$current();$now=Time::advance($this->clock,$seen);if(!$grant->check($fresh,$now)){throw new SecurityException('Download authorization changed before reading.','download.denied');}
        if($file->bytes()>$this->policy->maximumBytes()){throw new ValidationException('File exceeds the verified-read budget.','download.too_large');}$selection=Selection::choose($file,$request,$grant,$this->policy);$snapshot=$this->reader->snapshot($file,$deadline);$complete=false;
        try{
            $deadline->check('download.timeout');$fresh=$current();$now=Time::advance($this->clock,$seen);if(!$grant->check($fresh,$now)){throw new SecurityException('Download authorization changed during verification.','download.denied');}
            $deadline->check('download.timeout');$now=Time::advance($this->clock,$seen);if($now>=$grant->expiresAt()){throw new SecurityException('Download expired before transfer creation.','download.expired');}$snapshot->rewind($selection['offset']);
            $transfer=new Transfer($file,$request,$grant,$this->policy,static function(int $length)use($snapshot):string{return $snapshot->read($length);},static function()use($snapshot):void{$snapshot->close();},$current,$this->clock);$complete=true;return $transfer;
        }finally{if(!$complete){$snapshot->close();}}
    }
    public function __debugInfo():array {return ['private_downloads'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild downloads from private deployment configuration.','configuration.download_serialization');}
}
