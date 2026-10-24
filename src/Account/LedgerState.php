<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlSchema;

/** Internal pure codec shared by actual ledger reads and future captured permission views. */
final class LedgerState
{
    /** @return never */
    private static function corrupt():void {throw new StorageException('Account ledger state cannot be authenticated.','account.corrupt');}
    public static function encoded(array $row,bool $root):string
    {
        $result=[];foreach(array_keys($root?Ledger::rootTypes():Ledger::recordTypes()) as $field){if($field!=='seal'&&$field!=='payload'){$result[$field]=$row[$field];}}
        return ($root?'SoSecurity.Account.Root.1.':'SoSecurity.Account.Record.1.').json_encode($result,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    }
    /** Shape and signature validation occurs before the live ledger observes its clock. */
    public static function metadata(array $row,bool $root,string $namespace,HmacKeys $keys):array
    {
        $types=$root?Ledger::rootTypes():Ledger::recordTypes();unset($types['payload']);$expected=array_keys($types);if(!$root){$expected[]='body_length';}
        if(count($row)!==count($expected)||array_diff(array_keys($row),$expected)){self::corrupt();}
        foreach($types as $field=>$type){
            if($type==='int'){$row[$field]=SqlSchema::integer($row[$field]);}
            elseif(!is_string($row[$field])||($type==='digest'&&!preg_match('/\A[a-f0-9]{64}\z/D',$row[$field]))||(strpos($type,'bytes:')===0&&strlen($row[$field])>(int)substr($type,6))){self::corrupt();}
        }
        if(!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$row['seal_key'])||$row['namespace']!==$namespace||!$keys->verify($row['seal_key'],self::encoded($row,$root),hex2bin($row['seal']))){self::corrupt();}
        if($row['revision']<1||$row['revision']>=PHP_INT_MAX||$row['created_at']>($root?$row['observed_at']:$row['updated_at'])){self::corrupt();}
        return $row;
    }
    /** Receives a metadata-authenticated row; never reads a clock, connection or store. */
    public static function observe(array $row,bool $root,string $epoch,string $policyDigest,int $format,int $maximumEntries,int $now):array
    {
        if(($root?$row['observed_at']:$row['updated_at'])>$now){throw new StorageException('Account ledger clock moved backwards.','account.clock');}
        if($root){
            if($row['format']!==$format||$row['epoch']!==$epoch||$row['policy']!==$policyDigest){throw new ConfigurationException('Reconcile account ledger policy/epoch changes explicitly.','configuration.account_state');}
            if($row['entries']>$maximumEntries){self::corrupt();}
        }else{
            $length=SqlSchema::integer($row['body_length']);
            if(!in_array($row['kind'],['register','change','recover','notice','budget'],true)||$row['payload_bytes']>16384||$length!==$row['payload_bytes']||$row['retire_at']<$row['created_at']||$row['retire_at']-($row['kind']==='budget'?$row['updated_at']:$row['created_at'])>1209600){self::corrupt();}unset($row['body_length']);
        }
        return $row;
    }
    public static function authenticate(array $row,bool $root,string $namespace,string $epoch,string $policyDigest,int $format,int $maximumEntries,HmacKeys $keys,int $now):array
    {
        return self::observe(self::metadata($row,$root,$namespace,$keys),$root,$epoch,$policyDigest,$format,$maximumEntries,$now);
    }
    public static function payload(array $row,$payload):string
    {
        if(!is_string($payload)||strlen($payload)!==$row['payload_bytes']||!hash_equals($row['payload_digest'],hash('sha256',$payload))){self::corrupt();}return $payload;
    }
    public static function single(array $root,array $record,int $count):void
    {
        if($count!==1||$root['entries']!==1||$root['namespace']!==$record['namespace']||!hash_equals($root['history_digest'],hash('sha256','SoSecurity.Account.History.1.'.$root['namespace'].$record['record_id'].$record['seal']))){self::corrupt();}
    }
}
