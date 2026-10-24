<?php
declare(strict_types=1);
namespace SoSecurity\Mfa;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
/** Internal pure authenticated envelope codec. No authority callbacks or store transactions. */
final class ManagedFactorFrame
{
    private static function tree($value,int $depth,int &$nodes,int &$bytes):void
    {
        if(++$nodes>256||$depth>8){throw new StorageException('Managed factor state complexity exceeds its bound.','mfa.managed_corrupt');}
        if(is_array($value)){
            foreach($value as $key=>$item){if(is_string($key)){if(strlen($key)>64){throw new StorageException('Managed factor field exceeds its bound.','mfa.managed_corrupt');}$bytes+=strlen($key);}self::tree($item,$depth+1,$nodes,$bytes);}
        }elseif(is_string($value)){$bytes+=strlen($value);}
        elseif(!is_null($value)&&!is_int($value)&&!is_bool($value)){throw new StorageException('Managed factor state contains an invalid type.','mfa.managed_corrupt');}
        if($bytes>16384){throw new StorageException('Managed factor state bytes exceed their bound.','mfa.managed_corrupt');}
    }
    public static function encode(array $value):string
    {
        $nodes=0;$bytes=0;self::tree($value,0,$nodes,$bytes);$encoded=json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        if(!is_string($encoded)||strlen($encoded)>15000){throw new StorageException('Managed factor state cannot be encoded.','mfa.managed_corrupt');}return $encoded;
    }
    /** Authenticated envelope only; pending frames are exposed solely to migration capabilities. */
    public static function read(string $context,HmacKeys $keys,string $key,$value):array
    {
        if($value===null){throw new StorageException('Managed factor state is missing; explicit migration is required.','mfa.managed_missing');}
        $fields=is_array($value)&&($value['v']??null)===3?['v','context','key','payload','migration','seal']:['v','context','key','payload','seal'];
        if(!is_array($value)||array_keys($value)!==$fields||!in_array($value['v'],[2,3],true)||$value['context']!==$context||!is_string($value['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$value['key'])||(!is_array($value['payload'])&&$value['payload']!==null)||!is_string($value['seal'])||!preg_match('/\A[a-f0-9]{64}\z/D',$value['seal'])){throw new StorageException('Managed factor envelope is invalid.','mfa.managed_corrupt');}
        $migration=$value['v']===3?$value['migration']:null;
        if($value['v']===3&&(!is_array($migration)||array_keys($migration)!==['operation','digest','state']||!is_string($migration['operation'])||!preg_match('/\A[a-f0-9]{64}\z/D',$migration['operation'])||!is_string($migration['digest'])||!preg_match('/\A[a-f0-9]{64}\z/D',$migration['digest'])||!in_array($migration['state'],['prepared','committed'],true))){throw new StorageException('Invalid permanent migration receipt.','mfa.managed_corrupt');}
        $seal=$value['seal'];unset($value['seal']);
        if(!$keys->verify($value['key'],'SoSecurity.Mfa.ManagedFactor.1.'.$key.':'.self::encode($value),hex2bin($seal))){throw new StorageException('Managed factor envelope cannot be authenticated.','mfa.managed_corrupt');}
        return ['payload'=>$value['payload'],'migration'=>$migration];
    }
}
