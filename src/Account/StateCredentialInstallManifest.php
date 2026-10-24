<?php
declare(strict_types=1);
namespace SoSecurity\Account;
/** @internal Strict bounded encrypted fixed-effect image. Row bytes are never normalized as UTF-8. */
final class StateCredentialInstallManifest
{
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public static function valid($v):bool
    {
        if(!is_array($v)||!in_array($v['format']??null,[2,3,4,5],true)){return false;}$fields=['format','context','generation','source','sql','files','sql_name','file_name','account_plan','subject','candidate','material','nonce','observed','packet','before','after','factor','prior','expires'];if(in_array($v['format'],[3,5],true)){$fields[]='session';}if($v['format']>=4){$fields[]='retirement';}if(array_keys($v)!==$fields){return false;}
        if(in_array($v['format'],[3,5],true)){$s=$v['session'];if(!is_array($s)||array_keys($s)!==['key','reference','policy','before','after']||!is_string($s['key'])||preg_match('/\Aauth-sessions:[a-f0-9]{64}\z/D',$s['key'])!==1||!is_array($s['reference'])||array_keys($s['reference'])!==['directory','file']||!self::digest($s['reference']['directory'])||!is_string($s['reference']['file'])||preg_match('/\A[a-f0-9]{64}\.json\z/D',$s['reference']['file'])!==1||!self::digest($s['policy'])||($s['before']!==null&&!self::digest($s['before']))||!is_string($s['after'])||strlen($s['after'])>1024){return false;}}
        if($v['format']>=4){$r=$v['retirement'];if(!is_array($r)||array_keys($r)!==['before','after']||($r['before']!==null&&!self::digest($r['before']))||!is_string($r['after'])||strlen($r['after'])>2048){return false;}}
        foreach(['context','generation','source','sql','files','account_plan','material','nonce','observed'] as $key){if(!self::digest($v[$key])){return false;}}
        foreach(['sql_name','file_name'] as $key){if(!is_string($v[$key])||preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D',$v[$key])!==1){return false;}}
        if(!is_string($v['subject'])||strlen($v['subject'])<1||strlen($v['subject'])>256||preg_match('//u',$v['subject'])!==1||!is_string($v['candidate'])||preg_match('/\A[a-f0-9]{32}\z/D',$v['candidate'])!==1||!is_string($v['packet'])||strlen($v['packet'])<60||strlen($v['packet'])>12000||!is_int($v['expires'])||$v['expires']<1||$v['expires']>PHP_INT_MAX-86400){return false;}
        foreach(['before','after'] as $key){if(!is_array($v[$key])||array_keys($v[$key])!==[0,1,2]){return false;}foreach($v[$key] as $hash){if(!self::digest($hash)){return false;}}}
        $f=$v['factor'];$p=$v['prior'];if(!is_array($f)||array_keys($f)!==['key','file','after']||!is_string($f['key'])||preg_match('/\Amfa-totp:[a-f0-9]{64}\z/D',$f['key'])!==1||!is_string($f['file'])||preg_match('/\A[a-f0-9]{64}\.json\z/D',$f['file'])!==1||!self::digest($f['after'])||!is_array($p)||array_keys($p)!==['scope','subject','factor_id']){return false;}
        foreach(['scope','subject'] as $key){if(!is_string($p[$key])||strlen($p[$key])<1||strlen($p[$key])>256||preg_match('//u',$p[$key])!==1){return false;}}return is_string($p['factor_id'])&&($p['factor_id']===''||preg_match('/\A[a-f0-9]{32}\z/D',$p['factor_id'])===1);
    }
    public static function pack(array $row):array{ksort($row);$v=[];foreach($row as $key=>$value){if(!is_string($key)||preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$key)!==1||(!is_string($value)&&!is_int($value)&&$value!==null)){self::invalid();}$v[$key]=is_string($value)?['bytes64'=>base64_encode($value)]:$value;}return $v;}
    public static function unpack(array $row):array{$v=[];foreach($row as $key=>$value){if(is_array($value)){if(array_keys($value)!==['bytes64']||!is_string($value['bytes64'])||strlen($value['bytes64'])>21848||!is_string(base64_decode($value['bytes64'],true))||base64_encode(base64_decode($value['bytes64'],true))!==$value['bytes64']){self::invalid();}$value=base64_decode($value['bytes64'],true);}$v[$key]=$value;}self::pack($v);return $v;}
    public static function hash(array $row):string{return hash('sha256','SoSecurity.Account.StateCredentialRow.2.'.json_encode(self::pack($row),JSON_UNESCAPED_SLASHES));}
    public static function fingerprint(array $v):string{if(!self::valid($v)){self::invalid();}return hash('sha256','SoSecurity.Account.StateCredentialInstallManifest.'.$v['format'].'.'.json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    /** @return never */
    private static function invalid():void{throw new \SoSecurity\Exception\ConfigurationException('Use an exact bounded credential installation image.','configuration.credential_installation');}
}
