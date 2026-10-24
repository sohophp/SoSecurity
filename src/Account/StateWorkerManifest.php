<?php
declare(strict_types=1);
namespace SoSecurity\Account;
/** @internal Exact bounded worker authority and root images; contains no private key. */
final class StateWorkerManifest
{
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public static function valid($v):bool
    {
        if(!is_array($v)||array_keys($v)!==['format','context','generation','source','sql','sql_name','from','to','namespace','old_root','next_root','old_frame','closed_frame','next_frame','authority','observed']||$v['format']!==1){return false;}
        foreach(['context','generation','source','sql','from','to','namespace','authority','observed'] as $k){if(!self::digest($v[$k])){return false;}}
        if($v['from']===$v['to']||!is_string($v['sql_name'])||preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D',$v['sql_name'])!==1){return false;}
        foreach(['old_root','next_root'] as $k){$r=$v[$k];if(!is_array($r)||array_keys($r)!==array_keys(Ledger::rootTypes())||$r['namespace']!==$v['namespace']||$r['format']!==2){return false;}foreach(Ledger::rootTypes() as $field=>$type){if($type==='int'){if(!is_int($r[$field])||$r[$field]<0||$r[$field]>=PHP_INT_MAX){return false;}}elseif($type==='digest'){if(!self::digest($r[$field])){return false;}}elseif(!is_string($r[$field])||preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$r[$field])!==1){return false;}}}
        if($v['old_root']['revision']<1||$v['old_root']['revision']>=PHP_INT_MAX-1||$v['next_root']['revision']!==$v['old_root']['revision']+1){return false;}
        foreach(['old_frame','closed_frame','next_frame'] as $k){if(!is_string($v[$k])||strlen($v[$k])>128||preg_match('/\A(?:open|closed)\n[A-Za-z][A-Za-z0-9_-]{0,31}\n[a-f0-9]{64}\n\z/D',$v[$k])!==1){return false;}}
        return strpos($v['closed_frame'],"closed\n")===0&&strpos($v['next_frame'],"open\n")===0;
    }
    public static function fingerprint(array $v):string{return hash('sha256',json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
}
