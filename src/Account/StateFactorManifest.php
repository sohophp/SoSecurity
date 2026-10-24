<?php
declare(strict_types=1);
namespace SoSecurity\Account;

/** Bounded non-secret physical effect description. Original factor material is never persisted here. */
final class StateFactorManifest
{
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public static function valid($v):bool
    {
        if(!is_array($v)||array_keys($v)!==['format','source','files','name','factor','context','entries']||$v['format']!==1||!self::digest($v['source'])||!self::digest($v['files'])||!is_string($v['name'])||preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D',$v['name'])!==1||!self::digest($v['context'])||!is_array($v['factor'])||array_keys($v['factor'])!==['directory','file']||!self::digest($v['factor']['directory'])||!is_string($v['factor']['file'])||preg_match('/\A[a-f0-9]{64}\.json\z/D',$v['factor']['file'])!==1||!is_array($v['entries'])||count($v['entries'])<1||count($v['entries'])>4||array_keys($v['entries'])!==range(0,count($v['entries'])-1)){return false;}
        $keys=[];$files=[];
        foreach($v['entries'] as $entry){
            if(!is_array($entry)||array_keys($entry)!==['key','file','before','after']||!is_string($entry['key'])||preg_match('/\Amfa-totp:[a-f0-9]{64}\z/D',$entry['key'])!==1||!is_string($entry['file'])||preg_match('/\A[a-f0-9]{64}\.json\z/D',$entry['file'])!==1||($entry['before']!==null&&!self::digest($entry['before']))||!is_string($entry['after'])||strlen($entry['after'])>1024||isset($keys[$entry['key']])||isset($files[$entry['file']])){return false;}
            $outer=json_decode($entry['after'],true,12);if(!is_array($outer)||array_keys($outer)!==['expires','value']||$outer['expires']!==0||!is_array($outer['value'])||!array_key_exists('payload',$outer['value'])||$outer['value']['payload']!==null){return false;}
            $keys[$entry['key']]=true;$files[$entry['file']]=true;
        }
        return true;
    }
    public static function fingerprint(array $v):string{if(!self::valid($v)){throw new \SoSecurity\Exception\ConfigurationException('Use a bounded physical effect manifest.','configuration.factor_resolution');}return hash('sha256','SoSecurity.Account.StateFactorManifest.1.'.json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
}
