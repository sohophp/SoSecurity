<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Link\Links;
use SoSecurity\Link\Target;

/** Actual signed-link verification, never a caller-supplied VerifiedLink. One-use ranges refuse without consuming. */
final class LinkAccess implements Access
{
    private $links;
    private $target;
    private $read;
    public function __construct(Links $links,callable $targetFactory,string $url,string $binding=''){$this->links=$links;$this->target=$targetFactory;$this->read=static function()use($url,$binding):array{return [$url,$binding];};}
    private function data():array {if(!($this->read instanceof \Closure)){throw new ConfigurationException('Rebuild request-bound signed download access.','configuration.download_serialization');}return ($this->read)();}
    private function target(File $file):Target
    {
        try{$target=($this->target)($file);}catch(\Throwable $error){throw new DependencyException('Download link metadata unavailable.','download.link_unavailable');}
        if(!$target instanceof Target||!hash_equals($target->resource()->fingerprint(),$file->resource()->fingerprint())){throw new ConfigurationException('Signed downloads must bind the derived content resource.','configuration.download_link');}return $target;
    }
    public function authorize(File $file,Request $request):?Grant
    {
        $target=$this->target($file);$data=$this->data();$parts=\SoSecurity\Link\Encoding::parse($data[0],$this->links->policy(),$target);
        // Unauthenticated envelope inspection can only refuse, never authorize or disclose file metadata.
        if($request->header('range')!==null&&$parts!==null&&$parts['mode']==='o'){return null;}
        $proof=$this->links->verify($target,$data[0],$request->method(),$data[1]);if($proof===null){return null;}
        return new Grant($file->fingerprint(),$proof->expiresAt(),function(File $current)use($proof,$request):bool{
            $target=$this->target($current);$data=$this->data();return $proof->oneTime()||$this->links->verify($target,$data[0],$request->method(),$data[1])!==null;
        },$proof->oneTime());
    }
    public function __debugInfo():array {return ['signed_download_access'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild request-bound signed download access.','configuration.download_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Rebuild request-bound signed download access.','configuration.download_serialization');}
}
