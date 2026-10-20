<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-resolution-support.php';
use SoSecurity\Examples\Outbox as Resolution;
try{
    if(!in_array(count($argv),[4,5],true)||(count($argv)===5&&$argv[4]!=='archive')||!in_array($argv[3],['before-commit','after-commit'],true)){throw new RuntimeException('Invalid owned child stage.');}$settings=nativeResolutionSettings($argv[1]);$proof=Resolution\resolutionInputFile($settings,$argv[2],4096);$envelope=json_decode($proof,true);$value=json_decode(base64_decode($envelope['payload'],true),true);
    $fault=new InboxTestConnection('sqlite:'.$settings['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$fault->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$fault]]);$settings['pdo']=$fault;$phase=$argv[3];
    $stop=static function()use($phase):void{echo json_encode(['phase'=>$phase,'pid'=>getmypid()])."\n";fflush(STDOUT);$until=microtime(true)+20;while(microtime(true)<$until){usleep(10000);}throw new RuntimeException('Parent did not terminate its live child.');};
    if($phase==='before-commit'){$fault->beforeCommit=$stop;}else{$fault->afterCommit=$stop;}if(count($argv)===5){Resolution\resolutionArchive($settings);}else{Resolution\resolutionImport($settings,$value['event_id'],$proof);}throw new RuntimeException('Missing child stage.');
}catch(Throwable $failure){fwrite(STDERR,"resolution_child.failed\n");exit(1);}
