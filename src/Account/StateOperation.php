<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Immutable description, never permission or an approval capability. */
final class StateOperation
{
    private $data;
    private function __construct(array $data){if(!self::valid($data)){self::invalid();}$this->data=static function()use($data):array{return $data;};}
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use an exact bounded state operation description.','configuration.state_operation');}
    private static function hash(array $parts):string{return hash('sha256',json_encode($parts,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));}
    public static function scope(string $scope):string{Guard::label($scope);if(preg_match('//u',$scope)!==1){self::invalid();}return self::hash(['SoSecurity.Account.StateOperation.Scope.1',$scope]);}
    private static function plain(string $kind,string $action,string $scope):array{return ['kind'=>$kind,'action'=>$action,'scope'=>self::scope($scope),'actor'=>null,'target'=>null,'permission'=>null,'policy'=>null,'authorized_at'=>null];}
    public static function initial(string $scope):self{return new self(self::plain('initial','state.initialize',$scope));}
    public static function internal(string $action,string $scope):self{return new self(self::plain('internal',$action,$scope));}
    public static function authorized(StatePermission $permission,string $policy,int $now):self
    {
        $r=$permission->definition();$v=self::plain('authorized',$r['action'],$r['scope']);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$r['scope'],$r['actor']]);$v['target']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$r['scope'],$r['target']]);$v['permission']=$permission->binding();$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only. The native API service must first prove its actual read-only admission. */
    public static function credential(string $action,string $scope,string $actor,string $target,string $request,string $policy,int $now):self
    {
        if(!preg_match('/\Aapi\.credentials\.(?:issue|rotate|replace|all|revoke|revoke_all|authenticate|execute)\z/D',$action)||!self::digest($request)||!self::digest($policy)){self::invalid();}
        foreach([$actor,$target] as $subject){Guard::label($subject);if(preg_match('//u',$subject)!==1){self::invalid();}}
        $v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$scope,$actor]);$v['target']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$scope,$target]);$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; address admission must prove the current session, object and one-use authority. */
    public static function address(string $action,string $scope,string $subject,string $request,string $policy,int $now):self
    {
        if(!preg_match('/\Aaccount\.address_change\.(?:proposal|completion_proposal|request|complete)\z/D',$action)||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($subject);if(preg_match('//u',$subject)!==1){self::invalid();}
        $v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$scope,$subject]);$v['target']=$v['actor'];$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; native one-use admission must prove the actual current session and bound intent. */
    public static function operation(string $action,string $scope,string $subject,string $request,string $policy,int $now):self
    {
        if(!preg_match('/\Aoperations\.(?:begin|confirm|consume|revoke|revoke_all|execute)\z/D',$action)||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($subject);if(preg_match('//u',$subject)!==1){self::invalid();}
        $v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$scope,$subject]);$v['target']=$v['actor'];$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only. Bearer actors are explicit proof references, never invented account identities. */
    public static function link(string $action,string $scope,?string $actor,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\Alinks\.(?:issue|verify|all|revoke|revoke_all|execute)\z/D',$action)!==1||!self::digest($target)||!self::digest($request)||!self::digest($policy)){self::invalid();}
        if($actor!==null){Guard::label($actor);if(preg_match('//u',$actor)!==1){self::invalid();}}$v=self::plain('authorized',$action,$scope);$v['actor']=$actor===null?self::hash(['SoSecurity.Account.StateOperation.LinkBearer.1',$scope,$request]):self::hash(['SoSecurity.Account.StateOperation.Subject.1',$scope,$actor]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only. Reset request authority is explicit host policy, not an invented login. */
    public static function reset(string $action,string $scope,string $subject,string $request,string $policy,int $now):self
    {
        if(preg_match('/\Apassword\.reset\.(?:issue|consume|revoke|execute)\z/D',$action)!==1||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($subject);if(preg_match('//u',$subject)!==1){self::invalid();}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.ResetRequest.1',$scope,$request]);$v['target']=self::hash(['SoSecurity.Account.StateOperation.Subject.1',$scope,$subject]);$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; service-key identities are never invented account sessions. */
    public static function signature(string $action,string $scope,string $identity,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\Ahmac\.(?:verify|execute)\z/D',$action)!==1){self::invalid();}foreach([$identity,$target,$request,$policy] as $value){if(!self::digest($value)){self::invalid();}}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.SigningIdentity.1',$scope,$identity]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; exact native Webhook admission establishes current authority. */
    public static function webhook(string $scope,string $endpoint,string $target,string $request,string $policy,int $now):self
    {
        foreach([$endpoint,$target,$request,$policy] as $value){if(!self::digest($value)){self::invalid();}}$v=self::plain('authorized','webhook.receive',$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.Webhook.1',$scope,$endpoint]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; native processing checks the current worker or management authority. */
    public static function webhookProcessing(string $action,string $scope,string $worker,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\Awebhook\.processing\.(?:claim|execute|fail|retry)\z/D',$action)!==1){self::invalid();}foreach([$worker,$target,$request,$policy] as $value){if(!self::digest($value)){self::invalid();}}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.WebhookWorker.1',$scope,$worker]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Explicit legacy caller authority, separate from account sessions and managed credentials. */
    public static function legacyApi(string $action,string $scope,string $actor,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\Aapi\.keys\.(?:issue|rotate|revoke)\z/D',$action)!==1||!self::digest($target)||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($actor);if(preg_match('//u',$actor)!==1){self::invalid();}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.LegacyCaller.1',$scope,$actor]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; exact native request admission proves the actual current caller. */
    public static function proof(string $action,string $scope,string $actor,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\\Aproof\\.(?:csrf|captcha)\\.(?:issue|verify|revoke)\\z/D',$action)!==1||!self::digest($target)||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($actor);if(preg_match('//u',$actor)!==1){self::invalid();}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.ProofCaller.1',$scope,$actor]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; exact native request admission proves the actual current caller. */
    public static function lease(string $action,string $scope,string $actor,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\\Aleases\\.(?:initialize|acquire|renew|verify|release|inspect|remove)\\z/D',$action)!==1||!self::digest($target)||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($actor);if(preg_match('//u',$actor)!==1){self::invalid();}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.LeaseCaller.1',$scope,$actor]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    /** Description only; exact native request admission proves the actual current caller. */
    public static function quarantine(string $action,string $scope,string $actor,string $target,string $request,string $policy,int $now):self
    {
        if(preg_match('/\\Aquarantine\\.(?:enqueue|inspect|items|process|rescan|reject|read|remove)\\z/D',$action)!==1||!self::digest($target)||!self::digest($request)||!self::digest($policy)){self::invalid();}Guard::label($actor);if(preg_match('//u',$actor)!==1){self::invalid();}$v=self::plain('authorized',$action,$scope);$v['actor']=self::hash(['SoSecurity.Account.StateOperation.QuarantineCaller.1',$scope,$actor]);$v['target']=$target;$v['permission']=$request;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    public static function recovery(string $scope,string $actor,string $target,string $permission,string $policy,int $now):self
    {
        $v=self::plain('recovery','state.successor.stage',$scope);$v['actor']=$actor;$v['target']=$target;$v['permission']=$permission;$v['policy']=$policy;$v['authorized_at']=$now;return new self($v);
    }
    public static function valid($v):bool
    {
        if(!is_array($v)||array_keys($v)!==['kind','action','scope','actor','target','permission','policy','authorized_at']||!in_array($v['kind'],['initial','internal','authorized','recovery'],true)||!is_string($v['action'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_.:-]{0,127}\z/D',$v['action'])||!self::digest($v['scope'])){return false;}
        if($v['kind']==='recovery'&&$v['action']!=='state.successor.stage'){return false;}
        if(in_array($v['kind'],['authorized','recovery'],true)){foreach(['actor','target','permission','policy'] as $k){if(!self::digest($v[$k])){return false;}}return is_int($v['authorized_at'])&&$v['authorized_at']>0&&$v['authorized_at']<=PHP_INT_MAX-31536001;}
        foreach(['actor','target','permission','policy','authorized_at'] as $k){if($v[$k]!==null){return false;}}return $v['kind']!=='initial'||$v['action']==='state.initialize';
    }
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public function metadata():array{return ($this->data)();}
    public function binding():string{return self::hash(['SoSecurity.Account.StateOperation.1',$this->metadata()]);}
    public static function digestOf(array $metadata):string{if(!self::valid($metadata)){self::invalid();}return self::hash(['SoSecurity.Account.StateOperation.1',$metadata]);}
    public function __debugInfo():array{return ['state_operation'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
