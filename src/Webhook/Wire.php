<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;

/** Internal fixed protocol parsers. Unknown signature versions never change the server-selected algorithm. */
final class Wire
{
    private static function integer(string $value):?int
    {
        if(!preg_match('/\A(?:0|[1-9][0-9]{0,18})\z/D',$value)){return null;}$number=(int)$value;return (string)$number===$value?$number:null;
    }
    public static function parse(Endpoint $endpoint,Request $request):?array
    {
        $body=$request->body();$protocol=$endpoint->protocol();
        if($protocol==='github-sha256'){
            $header=$request->header('x-hub-signature-256');if($header===null||!preg_match('/\Asha256=([a-f0-9]{64})\z/D',$header,$match)){return null;}
            return ['message'=>$body,'signatures'=>[hex2bin($match[1])],'id'=>null,'timestamp'=>null];
        }
        if($protocol==='stripe-v1'){
            $header=$request->header('stripe-signature');if($header===null){return null;}$fields=explode(',',$header);if(count($fields)>16){return null;}$timestamp=null;$signatures=[];
            foreach($fields as $field){$parts=explode('=',trim($field),2);if(count($parts)!==2||!preg_match('/\A[a-z][a-z0-9]{0,15}\z/D',$parts[0])||strlen($parts[1])>128){return null;}
                if($parts[0]==='t'){if($timestamp!==null||($timestamp=self::integer($parts[1]))===null){return null;}}
                elseif($parts[0]==='v1'){if(!preg_match('/\A[a-f0-9]{64}\z/D',$parts[1])){return null;}$signatures[]=hex2bin($parts[1]);}
            }
            if($timestamp===null||!$signatures||count($signatures)>8){return null;}
            return ['message'=>$timestamp.'.'.$body,'signatures'=>$signatures,'id'=>null,'timestamp'=>$timestamp];
        }
        $id=$request->header('webhook-id');$time=$request->header('webhook-timestamp');$header=$request->header('webhook-signature');
        if($id===null||!preg_match('/\A[!-~]{1,256}\z/D',$id)||strpos($id,'.')!==false||$time===null||($timestamp=self::integer($time))===null||$header===null){return null;}
        $fields=explode(' ',trim($header));if(count($fields)>16){return null;}$signatures=[];$version=$protocol==='standard-hmac'?'v1':'v1a';$bytes=$protocol==='standard-hmac'?32:64;
        foreach($fields as $field){if($field===''){continue;}$parts=explode(',',$field,2);if(count($parts)!==2||!preg_match('/\Av[1-9][0-9]{0,2}[a-z]?\z/D',$parts[0])||strlen($parts[1])>128){return null;}
            if($parts[0]!==$version){continue;}$raw=base64_decode($parts[1],true);if(!is_string($raw)||strlen($raw)!==$bytes||base64_encode($raw)!==$parts[1]){return null;}$signatures[]=$raw;
        }
        if(!$signatures||count($signatures)>8){return null;}
        return ['message'=>$id.'.'.$time.'.'.$body,'signatures'=>$signatures,'id'=>$id,'timestamp'=>$timestamp];
    }
}
