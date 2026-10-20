<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\VerifiedSession;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Support\Guard;

/** Request-bound live registry identity plus current object policy. Host request guard includes required CSRF/budgets. */
final class SessionAccess implements Access
{
    private $sessions;
    private $authorizer;
    private $scope;
    private $subject;
    private $token;
    private $guard;
    private $action;
    public function __construct(SessionRegistry $sessions,Authorizer $authorizer,string $scope,?string $subject,?string $sessionToken,callable $requestGuard,string $action='file.download')
    {
        Guard::label($scope);\SoSecurity\Authorization\Shape::name($action);$this->sessions=$sessions;$this->authorizer=$authorizer;$this->scope=$scope;$this->subject=$subject;$this->token=$sessionToken===null?null:static function()use($sessionToken):string{return $sessionToken;};$this->guard=$requestGuard;$this->action=$action;
    }
    public function authorize(File $file,Request $request):?Grant
    {
        try{$allowed=($this->guard)($file,$request);}catch(\Throwable $error){throw new DependencyException('Download request protection unavailable.','download.request_unavailable');}
        if($allowed!==true){return null;}$identity=$this->identity($file);if($identity===null){return null;}
        return new Grant($file->fingerprint(),$identity->expiresAt(),function(File $current)use($identity):bool{
            $now=$this->identity($current);return $now!==null&&$now->id()===$identity->id()&&hash_equals($identity->account()->fingerprint(),$now->account()->fingerprint());
        });
    }
    private function identity(File $file):?VerifiedSession
    {
        if($file->resource()->scope()!==$this->scope||$this->subject===null||$this->token===null){return null;}
        try{
            if(!$this->token instanceof \Closure){throw new DependencyException('Download identity/authorization unavailable.','download.authentication_unavailable');}
            $session=$this->sessions->verify($this->scope,$this->subject,($this->token)());if($session===null){return null;}
            return $this->authorizer->decide($this->scope,$session->account(),$this->action,$file->resource())->allowed()?$session:null;
        }catch(\Throwable $error){throw new DependencyException('Download identity/authorization unavailable.','download.authentication_unavailable');}
    }
    public function __debugInfo():array {return ['session_download_access'=>'[redacted]'];}
    public function __sleep():array {throw new \SoSecurity\Exception\ConfigurationException('Rebuild request-bound download access.','configuration.download_serialization');}
    public function __wakeup():void {throw new \SoSecurity\Exception\ConfigurationException('Rebuild request-bound download access.','configuration.download_serialization');}
}
