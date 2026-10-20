<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
$raw=file_get_contents('php://stdin',false,null,0,1048577);if(!is_string($raw)||strlen($raw)>1048576){throw new RuntimeException('Invalid vector input budget.');}$vectors=json_decode($raw,true);$result=[];
foreach($vectors as $vector){
    try{
        $file=new SoSecurity\Download\File(new SoSecurity\Authorization\Resource('range-vector','file','a','1'),'a.bin','a.bin',$vector['size'],hash('sha256','independent-range-vector'));
        $request=new SoSecurity\Download\Request('GET',['Range'=>$vector['range']]);$grant=new SoSecurity\Download\Grant($file->fingerprint(),time()+300,static function(){return true;});
        $transfer=new SoSecurity\Download\Transfer($file,$request,$grant,new SoSecurity\Download\Policy(),static function(){return '';},static function(){},static function()use($file){return $file;});
        try{$headers=$transfer->headers();$result[]=['status'=>$transfer->status(),'length'=>(int)$headers['Content-Length'],'range'=>$headers['Content-Range'] ?? null];}finally{$transfer->close();}
    }catch(SoSecurity\Download\RangeException $error){$result[]=['status'=>'range','total'=>$error->totalBytes()];}
}
echo json_encode($result);
