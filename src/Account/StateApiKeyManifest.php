<?php
declare(strict_types=1);
namespace SoSecurity\Account;
/** @internal Fixed permanent subject epoch; no bearer secrets or arbitrary file payloads. */
final class StateApiKeyManifest
{
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public static function valid($v):bool
    {
        if(!is_array($v)||!in_array($v['format']??null,[1,2],true)){return false;}$fields=['format','context','generation','source','files','file_name','api','subject','nonce','authority','observed','key','reference','before','after'];if($v['format']===2){$fields=array_merge($fields,['kind','scope','stamp']);if($v['kind']!=='account_credentials'||!is_string($v['scope'])||strlen($v['scope'])<1||strlen($v['scope'])>256||preg_match('//u',$v['scope'])!==1||preg_match('/[\x00-\x1f\x7f]/',$v['scope'])||!is_int($v['stamp'])||$v['stamp']<0||$v['stamp']>PHP_INT_MAX-31536001){return false;}}if(array_keys($v)!==$fields){return false;}
        foreach(['context','generation','source','files','api','nonce','authority','observed'] as $k){if(!self::digest($v[$k])){return false;}}
        if(!is_string($v['file_name'])||preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D',$v['file_name'])!==1||!is_string($v['subject'])||strlen($v['subject'])<1||strlen($v['subject'])>256||preg_match('//u',$v['subject'])!==1||preg_match('/[\x00-\x1f\x7f]/',$v['subject'])||!is_string($v['key'])||($v['format']===1?$v['key']!=='api-key-epoch:'.hash('sha256',$v['subject']):preg_match('/\Aapi-credentials:[a-f0-9]{64}\z/D',$v['key'])!==1)||!is_array($v['reference'])||array_keys($v['reference'])!==['directory','file']||!self::digest($v['reference']['directory'])||!is_string($v['reference']['file'])||preg_match('/\A[a-f0-9]{64}\.json\z/D',$v['reference']['file'])!==1||($v['before']!==null&&!self::digest($v['before']))||!is_string($v['after'])||strlen($v['after'])>($v['format']===1?1024:4096)){return false;}
        $a=json_decode($v['after'],true,4);if(!is_array($a)||array_keys($a)!==['expires','value']||$a['expires']!==0||!is_array($a['value'])){return false;}$p=$a['value'];
        if($v['format']===1){return array_keys($p)===['v','subject','epoch']&&$p['v']===1&&$p['subject']===$v['subject']&&self::digest($p['epoch']);}
        return array_keys($p)===['v','scope','subject','identity','policy','epoch','seen','entries']&&$p['v']===1&&$p['scope']===$v['scope']&&$p['subject']===$v['subject']&&self::digest($p['identity'])&&self::digest($p['policy'])&&is_string($p['epoch'])&&preg_match('/\A[a-f0-9]{32}\z/D',$p['epoch'])===1&&$p['seen']===$v['stamp']&&$p['entries']===[];

    }
    public static function fingerprint(array $v):string{if(!self::valid($v)){throw new \SoSecurity\Exception\ConfigurationException('Use an exact API key epoch manifest.','configuration.api_key_retirement');}return hash('sha256','SoSecurity.Account.StateApiKeyManifest.'.$v['format'].'.'.json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
}
