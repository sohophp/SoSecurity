<?php
declare(strict_types=1);
$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[NativeAuditTimingStatement::class,[]]);$issued=null;
$operations=[
 'issue'=>static function()use($api,$token,&$issued):void{$issued=$api->issue('tenant','audit-owner',$token,'Owned diagnostic credential',['records:read']);},
 'all'=>static function()use($api,$token):void{$api->all('tenant','audit-owner',$token);},
 'rotate'=>static function()use($api,$token,&$issued):void{$issued=$api->rotate('tenant','audit-owner',$token,$issued->metadata()->id(),1);}
];
foreach($operations as $name=>$operation){
 $nativeFinalHook=static function():void{NativeAuditTiming::mark('witness','final');};NativeAuditTiming::begin();$failure=null;
 try{$operation();}catch(Throwable $error){$failure=['class'=>get_class($error),'reason'=>$error instanceof SoSecurity\Exception\SecurityException?$error->reason():'diagnostic.unexpected'];}
 $result=NativeAuditTiming::finish();$result['operation']=$name;$result['failure']=$failure;$result['acceptance']=false;
 $result['witness']=$witness->inspect(static function():bool{return true;})['status'];echo 'AUDIT_TIMING '.json_encode($result).PHP_EOL;
 if($failure!==null){break;}
}
