<?php
declare(strict_types=1);
namespace SoSecurity\Account;

/** @internal Bounded row hashes only; original account secrets never enter a durable effect description. */
final class StateAccountManifest
{
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public static function valid($v):bool
    {
        if(!is_array($v)||array_keys($v)!==['format','source','sql','plan','operation','observed','rows']||$v['format']!==1){return false;}
        foreach(['source','sql','plan','operation','observed'] as $key){if(!self::digest($v[$key])){return false;}}
        if(!is_array($v['rows'])||count($v['rows'])<1||count($v['rows'])>8||array_keys($v['rows'])!==range(0,count($v['rows'])-1)){return false;}
        foreach($v['rows'] as $row){if(!is_array($row)||array_keys($row)!==['before','after']||!self::digest($row['before'])||!self::digest($row['after'])||$row['before']===$row['after']){return false;}}return true;
    }
}
