<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;

/** Trusted private-file index record. The derived authorization version binds the expected actual bytes. */
final class File
{
    private $source;
    private $resource;
    private $path;
    private $name;
    private $bytes;
    private $digest;
    public function __construct(Resource $sourceResource,string $relativePath,string $filename,int $bytes,string $sha256)
    {
        if($bytes<0||$bytes>536870912||!preg_match('/\A[a-f0-9]{64}\z/D',$sha256)||$relativePath===''||strlen($relativePath)>1024||$relativePath[0]==='/'||!preg_match('//u',$relativePath)||preg_match('/[\\\\:%?#\x00-\x1f\x7f]/',$relativePath)){
            throw new ConfigurationException('Invalid bounded private-file index.','configuration.download_file');
        }
        $segments=explode('/',$relativePath);if(count($segments)>16){throw new ConfigurationException('Private-file path is too deep.','configuration.download_file');}
        foreach($segments as $segment){if($segment===''||strlen($segment)>255||in_array($segment,['.','..'],true)){throw new ConfigurationException('Private-file path must contain ordinary relative segments.','configuration.download_file');}}
        if($filename===''||strlen($filename)>255||!preg_match('//u',$filename)||preg_match('/[\\\\\/:\x00-\x1f\x7f]|[\x{0080}-\x{009f}\x{202a}-\x{202e}\x{2066}-\x{2069}]/u',$filename)||trim($filename," .")!==$filename){throw new ConfigurationException('Invalid bounded download filename.','configuration.download_file');}
        $version=hash('sha256',json_encode(['download-v1',$sourceResource->fingerprint(),$relativePath,$filename,$bytes,$sha256]));
        $this->source=$sourceResource;$this->resource=new Resource($sourceResource->scope(),$sourceResource->type(),$sourceResource->id(),$version,$sourceResource->attributes());
        $this->path=$relativePath;$this->name=$filename;$this->bytes=$bytes;$this->digest=$sha256;
    }
    public function sourceResource():Resource {return $this->source;}
    public function resource():Resource {return $this->resource;}
    public function relativePath():string {return $this->path;}
    public function filename():string {return $this->name;}
    public function bytes():int {return $this->bytes;}
    public function sha256():string {return $this->digest;}
    public function fingerprint():string {return $this->resource->fingerprint();}
    public function __debugInfo():array {return ['private_file'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current download metadata.','configuration.download_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Download files are immutable.','configuration.immutable');}
}
