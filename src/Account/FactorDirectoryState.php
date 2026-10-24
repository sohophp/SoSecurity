<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
/** Internal pure directory decoder shared by managed reads and witnessed permission evaluation. */
final class FactorDirectoryState
{
    public static function read(string $site,string $scope,string $epoch,array $row,string $subject):array
    {
        foreach(['kind','record_id','owner','payload'] as $field){if(!isset($row[$field])||!is_string($row[$field])){self::corrupt();}}

        if(strlen($row['payload'])>16384){self::corrupt();}
        $f=json_decode($row['payload'],true,3);$fields=['format','purpose','subject','origin','slot_scope','slot_subject','factor_id','generation'];if(in_array($f['format']??null,[4,5],true)){$fields[]='migration';}if(($f['format']??null)===6){$fields[]='revocation';}if(($f['format']??null)===7){$fields[]='restoration';}
        if($row['kind']!=='budget'||$row['record_id']!==hash('sha256','SoSecurity.Account.FactorRegistry.Pointer.1.'.$subject)||$row['owner']!==hash('sha256',$subject)||!is_array($f)||array_keys($f)!==$fields||!in_array($f['format'],[1,2,3,4,5,6,7],true)||$f['purpose']!=='managed_factor'||$f['subject']!==$subject){self::corrupt();}
        foreach(['origin','slot_scope','slot_subject','factor_id','generation'] as $key){if(!is_string($f[$key])){self::corrupt();}}
        if(($f['format']===1?!in_array($f['origin'],['none','legacy','recovery'],true):($f['format']===2?$f['origin']!=='retired':($f['format']===3?!in_array($f['origin'],['disabled','enrolled'],true):($f['format']===7?$f['origin']!=='restored':($f['format']===6?$f['origin']!=='revoked':($f['origin']!==($f['format']===4?'migrating':'migrated')||!is_string($f['migration'])||!preg_match('/\A[a-f0-9]{64}\z/D',$f['migration'])))))))||!preg_match('/\A[a-f0-9]{32}\z/D',$f['generation'])){self::corrupt();}
        if($f['format']===6){$v=$f['revocation'];if(!is_array($v)||array_keys($v)!==['operation','context','revoked_at']||!is_string($v['operation'])||!preg_match('/\A[a-f0-9]{64}\z/D',$v['operation'])||!is_string($v['context'])||!preg_match('/\A[a-f0-9]{64}\z/D',$v['context'])||!is_int($v['revoked_at'])||$v['revoked_at']<0||$f['factor_id']===''){self::corrupt();}}
        if($f['format']===7){$v=$f['restoration'];if(!is_array($v)||array_keys($v)!==['operation','context','restored_at']||!is_string($v['operation'])||!preg_match('/\A[a-f0-9]{64}\z/D',$v['operation'])||!is_string($v['context'])||!preg_match('/\A[a-f0-9]{64}\z/D',$v['context'])||!is_int($v['restored_at'])||$v['restored_at']<0||$f['factor_id']===''){self::corrupt();}}
        try{new FactorSlot($subject,self::binding($site,$scope,$epoch,$f),$f['slot_scope'],$f['slot_subject'],$f['factor_id']);}catch(ConfigurationException $error){self::corrupt();}
        if((($f['format']===1&&(($f['origin']==='none')!==($f['factor_id']==='')))||($f['format']===3&&(($f['origin']==='disabled')!==($f['factor_id']===''))))||json_encode($f,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)!==$row['payload']){self::corrupt();}return $f;
    }
    public static function binding(string $site,string $scope,string $epoch,array $data):string{return hash('sha256',json_encode(['SoSecurity.Account.FactorRegistry.Binding.1',$site,$scope,$epoch,$data],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    /** @return never */
    private static function corrupt():void{throw new StorageException('Managed factor pointer cannot be authenticated.','account.factor_corrupt');}
}
