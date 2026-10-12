<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ValidationException;

/** Bounded RFC 9421/9530 profile. Fixed component/parameter order, one label, one algorithm/tag. */
final class SignatureProfile
{
    private const COMPONENTS='("@method" "@target-uri" "content-digest" "content-type")';
    public static function digest(string $body): string { return 'sha-256=:'.base64_encode(hash('sha256',$body,true)).':'; }
    public static function contentType(string $type): string
    {
        $type=trim($type,' ');
        if ($type==='' || strlen($type)>256 || preg_match('/[^\x20-\x7e]/',$type)) { throw new ValidationException('Use a bounded ASCII Content-Type.','api.headers'); }
        return $type;
    }
    public static function parameters(int $created,int $expires,string $nonce,string $id): string
    {
        if ($created<0 || $expires<0 || strlen((string)$created)>10 || strlen((string)$expires)>10 || !preg_match('/\A[A-Za-z0-9_-]{16,128}\z/D',$nonce) || !preg_match('/\A[A-Za-z0-9._:-]{1,64}\z/D',$id)) { throw new ValidationException('Invalid signature parameters.','api.parameters'); }
        return self::COMPONENTS.';created='.$created.';expires='.$expires.';nonce="'.$nonce.'";keyid="'.$id.'";alg="hmac-sha256";tag="sosecurity-v1"';
    }
    public static function base(string $method,string $target,string $digest,string $type,string $parameters): string
    {
        return '"@method": '.$method."\n".'"@target-uri": '.$target."\n".'"content-digest": '.$digest."\n".'"content-type": '.$type."\n".'"@signature-params": '.$parameters;
    }
    public static function parse(array $headers): array
    {
        if (count($headers)>64) { throw new ValidationException('Too many request headers.','api.headers'); }
        $required=[]; $bytes=0;
        foreach ($headers as $name=>$value) {
            if (!is_string($name)) { throw new ValidationException('Invalid header map.','api.headers'); }
            $name=strtolower($name);
            if (!in_array($name,['signature-input','signature','content-digest','content-type'],true)) { continue; }
            if (!is_string($value) || isset($required[$name]) || preg_match('/[\x00-\x1f\x7f]/',$value)) { throw new ValidationException('Duplicate or invalid signed header.','api.headers'); }
            $bytes+=strlen($value);
            if ($bytes>4096) { throw new ValidationException('Signature headers are too large.','api.headers'); }
            $required[$name]=trim($value,' ');
        }
        if (count($required)!==4) { throw new ValidationException('Required signature headers are missing.','api.headers'); }
        $pattern='/\Asig1=\("@method" "@target-uri" "content-digest" "content-type"\);created=(0|[1-9][0-9]{0,9});expires=(0|[1-9][0-9]{0,9});nonce="([A-Za-z0-9_-]{16,128})";keyid="([A-Za-z0-9._:-]{1,64})";alg="hmac-sha256";tag="sosecurity-v1"\z/D';
        if (!preg_match($pattern,$required['signature-input'],$parts) || (string)(int)$parts[1]!==$parts[1] || (string)(int)$parts[2]!==$parts[2]
            || !preg_match('/\Asig1=:([A-Za-z0-9+\/]{43}=):\z/D',$required['signature'],$signature)) { throw new ValidationException('Signature profile is invalid.','api.profile'); }
        $raw=base64_decode($signature[1],true);
        if (!is_string($raw) || strlen($raw)!==32 || base64_encode($raw)!==$signature[1]) { throw new ValidationException('Signature encoding is invalid.','api.signature'); }
        return ['created'=>(int)$parts[1],'expires'=>(int)$parts[2],'nonce'=>$parts[3],'keyid'=>$parts[4],
            'parameters'=>substr($required['signature-input'],5),'mac'=>$raw,'digest'=>$required['content-digest'],'type'=>self::contentType($required['content-type'])];
    }
}
