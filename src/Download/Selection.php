<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ValidationException;

/** Internal integer-safe single-range selection. Conditional cache headers never bypass authorization or content checks. */
final class Selection
{
    private static function number(string $value):string {$value=ltrim($value,'0');return $value===''?'0':$value;}
    private static function greater(string $value,int $than):bool {$other=(string)$than;return strlen($value)>strlen($other)||(strlen($value)===strlen($other)&&strcmp($value,$other)>0);}
    public static function choose(File $file,Request $request,Grant $grant,Policy $policy):array
    {
        $total=$file->bytes();$offset=0;$length=$total;$status=200;$etag='"sha256-'.$file->sha256().'"';$range=$request->header('range');
        if($grant->oneTime()&&($request->method()==='HEAD'||$range!==null)){throw new ValidationException('One-use downloads do not support HEAD/ranges.','download.denied');}
        if($range!==null&&$request->method()==='GET'){
            if(!$policy->ranges()){throw new RangeException($total);}
            $condition=$request->header('if-range');
            if($condition===null||$condition===$etag){
                preg_match('/\Abytes=([0-9]{0,20})-([0-9]{0,20})\z/iD',$range,$parts);
                if($total===0){throw new RangeException($total);}
                if($parts[1]===''){$suffix=self::number($parts[2]);if($suffix==='0'){throw new RangeException($total);}$length=self::greater($suffix,$total)?$total:(int)$suffix;$offset=$total-$length;}
                else{$start=self::number($parts[1]);if(self::greater($start,$total-1)){throw new RangeException($total);}$offset=(int)$start;$end=$parts[2]===''?(string)($total-1):self::number($parts[2]);if(!self::greater($end,$total-1)&&(int)$end<$offset){throw new RangeException($total);}$length=(self::greater($end,$total-1)?$total-1:(int)$end)-$offset+1;}
                $status=206;
            }
        }
        if($length>$policy->maximumResponseBytes()){throw new ValidationException('Download response exceeds its byte budget.','download.too_large');}
        $fallback=preg_replace('/[^A-Za-z0-9._ -]/','_',$file->filename());$fallback=trim($fallback," .");if($fallback===''){$fallback='download';}
        $headers=['Content-Type'=>'application/octet-stream','Content-Disposition'=>'attachment; filename="'.$fallback.'"; filename*=UTF-8\'\''.rawurlencode($file->filename()),
            'Content-Length'=>(string)$length,'Accept-Ranges'=>$policy->ranges()&&!$grant->oneTime()?'bytes':'none','ETag'=>$etag,'Cache-Control'=>'no-store, private','Referrer-Policy'=>'no-referrer',
            'X-Content-Type-Options'=>'nosniff','Content-Security-Policy'=>"sandbox; default-src 'none'; base-uri 'none'",'X-Frame-Options'=>'DENY','Cross-Origin-Resource-Policy'=>'same-origin'];
        if($status===206){$headers['Content-Range']='bytes '.$offset.'-'.($offset+$length-1).'/'.$total;}
        return ['offset'=>$offset,'length'=>$length,'status'=>$status,'headers'=>$headers];
    }
}
