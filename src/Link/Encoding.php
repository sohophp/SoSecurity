<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Exception\ConfigurationException;

/** Internal fixed sl1 envelope; canonical decimal/base64url, no untrusted PHP query parsing. */
final class Encoding
{
    public static function binding(string $binding):string
    {
        if (strlen($binding)>1024) {throw new ConfigurationException('Signed-link binding exceeds 1 KiB.','configuration.link_binding');}
        return hash('sha256',($binding===''?'bearer':'bound')."\0".$binding);
    }
    public static function base64(string $bytes):string {return rtrim(strtr(base64_encode($bytes),'+/','-_'),'=');}
    public static function message(string $site,Policy $policy,Target $target,array $parts,string $binding):string
    {
        return json_encode(['signed-link-v1',$site,$policy->origin(),$target->fingerprint(),$parts['key_id'],$parts['id'],$parts['issued'],$parts['expires'],$parts['mode'],$binding]);
    }
    public static function prefix(Policy $policy,Target $target):string {return $policy->origin().$target->relativeUrl().($target->parameters()?'&':'?').'_ss=';}
    public static function parse(string $url,Policy $policy,Target $target):?array
    {
        $prefix=self::prefix($policy,$target);
        if (strlen($url)>2048 || substr($url,0,strlen($prefix))!==$prefix) {return null;}
        $token=substr($url,strlen($prefix));
        if (!preg_match('/\Asl1\.([A-Za-z][A-Za-z0-9_-]{0,31})\.([a-f0-9]{32})\.(0|[1-9][0-9]{0,18})\.(0|[1-9][0-9]{0,18})\.([or])\.([A-Za-z0-9_-]{43})\z/D',$token,$match)) {return null;}
        $issued=(int)$match[3];$expires=(int)$match[4];$mac=base64_decode(strtr($match[6],'-_','+/').'=',true);
        if ((string)$issued!==$match[3] || (string)$expires!==$match[4] || $issued<0 || $issued>PHP_INT_MAX-86400 || $expires<=$issued || $expires>$issued+$policy->maximumTtl()
            || !is_string($mac) || strlen($mac)!==32 || self::base64($mac)!==$match[6]) {return null;}
        return ['key_id'=>$match[1],'id'=>$match[2],'issued'=>$issued,'expires'=>$expires,'mode'=>$match[5],'mac'=>$mac,'digest'=>hash('sha256',$token)];
    }
}
