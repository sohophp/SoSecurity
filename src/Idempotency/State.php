<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;

/** Internal versioned root, permanent key history and authenticated response metadata. */
final class State
{
    public static function group(string $scope,string $subject,string $operation):void
    {
        foreach([$scope,$subject] as $label){Guard::label($label);if(!preg_match('//u',$label)){throw new ConfigurationException('Use UTF-8 server identities.','configuration.idempotency');}}
        if(!preg_match('/\A[a-z][a-z0-9_.:-]{0,63}\z/D',$operation)){throw new ConfigurationException('Use a fixed server operation identifier.','configuration.idempotency');}
    }
    public static function namespace(string $site,string $scope,string $subject,string $operation):string
    {
        self::group($scope,$subject,$operation);return hash('sha256',json_encode(['idempotency-v1',$site,$scope,$subject,$operation]));
    }
    public static function rootFields():array {return ['namespace','format','epoch','policy','entries','history_digest','revision','created_at','observed_at','seal_key','seal'];}
    public static function historyPrefix(string $namespace):string {return 'SoSecurity.Idempotency.History.1.'.$namespace;}
    public static function recordFields():array {return ['namespace','key_hash','format','epoch','policy','execution_id','fingerprint','status','status_code','response_bytes','response_digest','created_at','expires_at','updated_at','seal_key','seal'];}
    private static function hex($value,int $length=64):bool {return is_string($value)&&strlen($value)===$length&&preg_match('/\A[a-f0-9]+\z/D',$value)===1;}
    private static function message(array $row,bool $root):string
    {
        $values=[];foreach($root?self::rootFields():self::recordFields() as $field){if($field!=='seal'){$values[$field]=$row[$field];}}
        return ($root?'SoSecurity.Idempotency.Root.2.':'SoSecurity.Idempotency.Record.1.').json_encode($values);
    }
    public static function seal(array $row,HmacKeys $keys,bool $root):array
    {
        $row['seal_key']=$keys->currentId();$row['seal']=bin2hex($keys->sign(self::message($row,$root)));return $row;
    }
    private static function read(array $row,HmacKeys $keys,bool $root):array
    {
        $fields=$root?self::rootFields():self::recordFields();$extra=$root?[]:['body_length'];
        if(count($row)!==count($fields)+count($extra)||array_diff(array_keys($row),array_merge($fields,$extra))){throw new StorageException('Security record shape differs.','idempotency.corrupt');}
        foreach($root?['format','entries','revision','created_at','observed_at']:['format','status_code','response_bytes','created_at','expires_at','updated_at','body_length'] as $name){$row[$name]=SqlSchema::integer($row[$name]);}
        foreach($root?['namespace','epoch','policy','history_digest','seal']:['namespace','key_hash','epoch','policy','fingerprint','response_digest','seal'] as $name){if(!self::hex($row[$name])){throw new StorageException('Invalid security record digest.','idempotency.corrupt');}}
        if($row['format']!==($root?2:1)||!is_string($row['seal_key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||(!$root&&!self::hex($row['execution_id'],32))||!$keys->verify($row['seal_key'],self::message($row,$root),hex2bin($row['seal']))){throw new StorageException('Idempotency state cannot be authenticated.','idempotency.corrupt');}
        return $row;
    }
    public static function root(array $row,HmacKeys $keys,Policy $policy,string $namespace,string $epoch,int $now):array
    {
        $row=self::read($row,$keys,true);
        if($row['namespace']!==$namespace||$row['epoch']!==$epoch||$row['policy']!==$policy->fingerprint()){throw new ConfigurationException('Explicitly reconcile idempotency identity, epoch or policy changes.','configuration.idempotency_state');}
        if($row['entries']>$policy->maximumEntries()||$row['revision']<1||$row['revision']>=PHP_INT_MAX||$row['created_at']>$row['observed_at']){throw new StorageException('Invalid idempotency root state.','idempotency.corrupt');}
        if($row['observed_at']>$now){throw new StorageException('Idempotency clock moved backwards.','idempotency.clock');}return $row;
    }
    public static function record(array $row,HmacKeys $keys,Policy $policy,string $namespace,string $epoch,int $now):array
    {
        $row=self::read($row,$keys,false);
        if($row['namespace']!==$namespace||$row['epoch']!==$epoch||$row['policy']!==$policy->fingerprint()||!is_string($row['status'])||!in_array($row['status'],['running','done','expired'],true)||$row['created_at']>PHP_INT_MAX-$policy->ttl()||$row['expires_at']!==$row['created_at']+$policy->ttl()||$row['created_at']>$row['updated_at']||$row['updated_at']>$now||$row['response_bytes']>$policy->maximumResponseBytes()||$row['response_bytes']!==$row['body_length']){throw new StorageException('Invalid idempotency execution state.','idempotency.corrupt');}
        if($row['status']==='done'){$valid=$row['status_code']>=200&&$row['status_code']<=599;}
        else{$valid=$row['status_code']===0&&$row['response_bytes']===0&&$row['response_digest']===hash('sha256','')&&($row['status']!=='expired'||$row['updated_at']>=$row['expires_at']);}
        if(!$valid){throw new StorageException('Inconsistent idempotency response state.','idempotency.corrupt');}return $row;
    }
}
