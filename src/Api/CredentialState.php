<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** Internal single-account ledger. Permanent epoch/seen survive empty lists; no multi-key transaction claims. */
final class CredentialState
{
    public static function hex($value,int $length):bool {return is_string($value)&&strlen($value)===$length&&preg_match('/\A[a-f0-9]+\z/D',$value)===1;}
    public static function fields(array $value,array $fields):bool {if(count($value)!==count($fields)){return false;}$keys=array_keys($value);sort($keys);sort($fields);return $keys===$fields;}
    public static function root(string $site,string $scope,string $subject):string
    {
        foreach([$site,$scope,$subject] as $label){Guard::label($label);if(!preg_match('//u',$label)){throw new \SoSecurity\Exception\ConfigurationException('Credential labels must be UTF-8.','configuration.api_credentials');}}
        return hash('sha256',json_encode(['api-credential-root-v1',$site,$scope,$subject]));
    }
    public static function key(string $site,string $root):string {return Guard::key('api-credentials',$site,$root);}
    public static function empty(string $scope,string $subject,string $fingerprint,CredentialPolicy $policy,int $now,string $epoch):array
    {
        return ['v'=>1,'scope'=>$scope,'subject'=>$subject,'identity'=>$fingerprint,'policy'=>$policy->fingerprint(),'epoch'=>$epoch,'seen'=>$now,'entries'=>[]];
    }
    public static function claims(string $site,string $scope,string $subject,string $root,string $epoch,string $id,array $record):string
    {
        return hash('sha256',json_encode(['api-credential-claims-v1',$site,$scope,$subject,$root,$epoch,$id,$record['generation'],$record['created'],$record['issued'],$record['expires'],$record['name'],$record['scopes'],$record['identity'],$record['key_id'],$record['policy'],$record['creator'],$record['issuer']]));
    }
    public static function read($state,CredentialPolicy $policy,string $site,string $scope,string $root,int $now,bool $checkPolicy=true):?array
    {
        if($state===null){return null;}
        if(!is_array($state)||!self::fields($state,['v','scope','subject','identity','policy','epoch','seen','entries'])||$state['v']!==1||$state['scope']!==$scope||!is_string($state['subject'])||!self::hex($state['identity'],64)||!self::hex($state['policy'],64)||!self::hex($state['epoch'],32)||!is_int($state['seen'])||$state['seen']<0||$state['seen']>PHP_INT_MAX-31536000||!is_array($state['entries'])||count($state['entries'])>16){throw new StorageException('Corrupt API credential ledger.','storage.corrupt');}
        try{$expected=self::root($site,$scope,$state['subject']);}catch(\Throwable $error){throw new StorageException('Corrupt credential owner.','storage.corrupt');}
        if(!hash_equals($root,$expected)){throw new StorageException('Credential ledger owner mismatch.','storage.corrupt');}
        if($state['seen']>$now){throw new StorageException('Credential clock moved backwards.','api_credentials.clock');}
        if($checkPolicy&&!hash_equals($policy->fingerprint(),$state['policy'])){throw new StorageException('Explicitly revoke all credentials before changing active policy.','api_credentials.policy_changed');}
        if($checkPolicy&&count($state['entries'])>$policy->capacity()){throw new StorageException('Credential ledger exceeds configured capacity.','storage.corrupt');}
        foreach($state['entries'] as $id=>$record){
            if(!self::hex($id,32)||!is_array($record)||!self::fields($record,['name','scopes','created','issued','expires','generation','key_id','identity','policy','digest','claims','last_used','creator','issuer'])||!is_string($record['name'])||!is_array($record['scopes'])||!self::hex($record['identity'],64)||!hash_equals($state['identity'],$record['identity'])||!self::hex($record['policy'],64)||!hash_equals($state['policy'],$record['policy'])||!self::hex($record['digest'],64)||!self::hex($record['claims'],64)||!self::hex($record['creator'],64)||!self::hex($record['issuer'],64)||!is_string($record['key_id'])||!is_int($record['created'])||!is_int($record['issued'])||!is_int($record['expires'])||!is_int($record['generation'])||($record['last_used']!==null&&!is_int($record['last_used']))){throw new StorageException('Corrupt API credential entry.','storage.corrupt');}
            try{$info=self::info($id,$record);}catch(\Throwable $error){throw new StorageException('Corrupt API credential metadata.','storage.corrupt');}
            if($record['scopes']!==$info->scopes()||$record['issued']>$state['seen']||($record['last_used']!==null&&$record['last_used']>$state['seen'])||!hash_equals($record['claims'],self::claims($site,$scope,$state['subject'],$root,$state['epoch'],$id,$record))||($checkPolicy&&($record['expires']>$record['created']+$policy->maximumTtl()||array_diff($record['scopes'],$policy->allowedScopes())))){throw new StorageException('Credential claims disagree with the signed context.','storage.corrupt');}
        }
        return $state;
    }
    public static function prune(array $state,int $now):array {foreach($state['entries'] as $id=>$record){if($record['expires']<=$now){unset($state['entries'][$id]);}}$state['seen']=$now;return $state;}
    public static function matches(array $state,array $parts):bool
    {
        $record=$state['entries'][$parts['id']] ?? null;
        return $record!==null&&hash_equals($state['epoch'],$parts['epoch'])&&hash_equals($record['digest'],$parts['digest'])&&hash_equals($record['claims'],$parts['claims'])&&$record['generation']===$parts['generation']&&$record['issued']===$parts['issued']&&$record['expires']===$parts['expires']&&$record['key_id']===$parts['key_id'];
    }
    public static function info(string $id,array $record):CredentialInfo {return new CredentialInfo($id,$record['name'],$record['scopes'],$record['created'],$record['issued'],$record['expires'],$record['generation'],$record['key_id'],$record['last_used'],$record['creator'],$record['issuer']);}
}
