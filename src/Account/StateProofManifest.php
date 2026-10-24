<?php
declare(strict_types=1);
namespace SoSecurity\Account;
/** @internal Fixed bounded proof epoch effects; never arbitrary files or payloads. */
final class StateProofManifest
{
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public static function valid($v):bool
    {
        if(!is_array($v)||array_keys($v)!==['format','context','generation','source','files','file_name','nonce','authority','observed','entries']||$v['format']!==1){return false;}
        foreach(['context','generation','source','files','nonce','authority','observed'] as $k){if(!self::digest($v[$k])){return false;}}
        if(!is_string($v['file_name'])||preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D',$v['file_name'])!==1||!is_array($v['entries'])||count($v['entries'])<1||count($v['entries'])>4||array_keys($v['entries'])!==range(0,count($v['entries'])-1)){return false;}$seen=[];
        foreach($v['entries'] as $e){if(!is_array($e)||array_keys($e)!==['kind','scope','component','key','reference','before','after']||!in_array($e['kind'],['operations','links','password-reset'],true)||!is_string($e['scope'])||($e['kind']==='password-reset'?$e['scope']!=='':(strlen($e['scope'])<1||strlen($e['scope'])>256||preg_match('//u',$e['scope'])!==1||preg_match('/[\x00-\x1f\x7f]/',$e['scope'])))||!self::digest($e['component'])||!is_string($e['key'])||preg_match('/\Aproof-epoch:[a-f0-9]{64}\z/D',$e['key'])!==1||!is_array($e['reference'])||array_keys($e['reference'])!==['directory','file']||!self::digest($e['reference']['directory'])||!is_string($e['reference']['file'])||preg_match('/\A[a-f0-9]{64}\.json\z/D',$e['reference']['file'])!==1||isset($seen[$e['reference']['file']])||($e['before']!==null&&!self::digest($e['before']))||!is_string($e['after'])||strlen($e['after'])>512){return false;}$seen[$e['reference']['file']]=true;
            $a=json_decode($e['after'],true,4);if(!is_array($a)||array_keys($a)!==['expires','value']||$a['expires']!==0||!is_array($a['value'])||array_keys($a['value'])!==['v','context','epoch']||$a['value']['v']!==1||!self::digest($a['value']['context'])||!self::digest($a['value']['epoch'])||$e['key']!=='proof-epoch:'.$a['value']['context']){return false;}
        }return true;
    }
    public static function fingerprint(array $v):string{if(!self::valid($v)){throw new \SoSecurity\Exception\ConfigurationException('Use an exact proof epoch retirement manifest.','configuration.proof_retirement');}return hash('sha256','SoSecurity.Account.StateProofManifest.1.'.json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
}
