<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\HmacKeys;

/** Internal opaque bearer envelope. Signature prefilter bounds unknown-key state allocation; ledger still authorizes. */
final class CredentialEncoding
{
    public static function scopes(array $scopes,bool $empty=false):array
    {
        if(count($scopes)>32||(!$empty&&!$scopes)||array_values($scopes)!==$scopes){throw new ValidationException('Expected a bounded credential-scope list.','api_credentials.scopes');}
        try{$copy=Identity::validateScopes($scopes);}catch(\InvalidArgumentException $error){throw new ValidationException('Invalid credential scope.','api_credentials.scopes');}
        if(count($copy)!==count($scopes)){throw new ValidationException('Duplicate credential scopes.','api_credentials.scopes');}sort($copy);return $copy;
    }
    public static function name(string $name):string
    {
        if($name===''||strlen($name)>128||trim($name)!==$name||!preg_match('//u',$name)||preg_match('/[\x00-\x1f\x7f]|[\x{0080}-\x{009f}\x{202a}-\x{202e}\x{2066}-\x{2069}]/u',$name)){throw new ValidationException('Invalid bounded credential name.','api_credentials.name');}return $name;
    }
    public static function base64(string $bytes):string {return rtrim(strtr(base64_encode($bytes),'+/','-_'),'=');}
    public static function message(string $site,string $scope,array $parts):string
    {
        return json_encode(['api-credential-v1',$site,$scope,$parts['key_id'],$parts['root'],$parts['epoch'],$parts['id'],$parts['generation'],$parts['issued'],$parts['expires'],$parts['claims'],$parts['secret']]);
    }
    public static function create(HmacKeys $keys,string $site,string $scope,string $root,string $epoch,string $id,array $record,string $secret):string
    {
        $parts=['key_id'=>$record['key_id'],'root'=>$root,'epoch'=>$epoch,'id'=>$id,'generation'=>$record['generation'],'issued'=>$record['issued'],'expires'=>$record['expires'],'claims'=>$record['claims'],'secret'=>$secret];
        return implode('.',['ac1',$keys->currentId(),$root,$epoch,$id,$parts['generation'],$parts['issued'],$parts['expires'],$parts['claims'],$secret,self::base64($keys->sign(self::message($site,$scope,$parts)))]);
    }
    public static function parse($token):?array
    {
        if(!is_string($token)||strlen($token)>512||!preg_match('/\Aac1\.([A-Za-z][A-Za-z0-9_-]{0,31})\.([a-f0-9]{64})\.([a-f0-9]{32})\.([a-f0-9]{32})\.([1-9][0-9]{0,18})\.(0|[1-9][0-9]{0,18})\.([1-9][0-9]{0,18})\.([a-f0-9]{64})\.([a-f0-9]{64})\.([A-Za-z0-9_-]{43})\z/D',$token,$m)){return null;}
        $generation=(int)$m[5];$issued=(int)$m[6];$expires=(int)$m[7];$mac=base64_decode(strtr($m[10],'-_','+/').'=',true);
        if((string)$generation!==$m[5]||(string)$issued!==$m[6]||(string)$expires!==$m[7]||$generation<1||$issued<0||$issued>PHP_INT_MAX-31536000||$expires<=$issued||$expires>$issued+31536000||!is_string($mac)||strlen($mac)!==32||self::base64($mac)!==$m[10]){return null;}
        return ['key_id'=>$m[1],'root'=>$m[2],'epoch'=>$m[3],'id'=>$m[4],'generation'=>$generation,'issued'=>$issued,'expires'=>$expires,'claims'=>$m[8],'secret'=>$m[9],'mac'=>$mac,'digest'=>hash('sha256',$token)];
    }
    public static function version(int $generation):void {if($generation<1){throw new ValidationException('Invalid credential generation.','api_credentials.generation');}}
    public static function id(string $id):void {if(!CredentialState::hex($id,32)){throw new ValidationException('Invalid credential identifier.','api_credentials.id');}}
    public static function immutable():void {throw new ConfigurationException('Managed credential values are immutable.','configuration.immutable');}
}
