<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** @internal Shared bounded public input checks. No clocks, callbacks, hashing or SQL. */
final class StateLifecycleInput
{
    public static function id(string $value):void{if(!preg_match('/\A[a-f0-9]{64}\z/D',$value)){throw new ValidationException('Invalid account proof.','account.proof');}}
    public static function source(string $source):void{Guard::label($source);if(preg_match('//u',$source)!==1){throw new ValidationException('Use a bounded server-derived request source.','account.source');}}
    public static function password(string $password,int $maximum):void
    {
        if($password===''||strlen($password)>$maximum||strpos($password,"\0")!==false){throw new ValidationException('Password exceeds its encoding/length budget.','password.encoding');}
    }
    /** Copy scalar fields so reference-backed caller arrays cannot change after preflight. */
    public static function proof(array $proof,bool $approvalOnly=false):array
    {
        if($proof===[]&&!$approvalOnly){return [];}$names=array_keys($proof);sort($names);
        if($names!==['code','type']||!is_string($proof['type'])||!in_array($proof['type'],$approvalOnly?['approved']:['recovery','approved'],true)||!is_string($proof['code'])||$proof['code']===''||strlen($proof['code'])>512||preg_match('/[\x00-\x1f\x7f]/',$proof['code'])){throw new ValidationException('Use a bounded explicit recovery proof.','account.recovery_proof');}
        $type=$proof['type'];$code=$proof['code'];return ['type'=>$type,'code'=>$code];
    }
}
