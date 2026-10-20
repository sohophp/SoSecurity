<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-recovery-support.php';
use SoSecurity\Examples\Outbox as Receiver;
try{
    if(!in_array(count($argv),[4,5],true)||(count($argv)===5&&$argv[4]!=='cancel')||!in_array($argv[2],['prepared','business-uncommitted','business-committed','witness-committed'],true)){throw new RuntimeException('Invalid test child stage.');}$cancel=count($argv)===5;
    $settings=recoverySettings($argv[1]);$phase=$argv[2];$body=file_get_contents(Receiver\privateFile($argv[3]),false,null,0,8193);Receiver\event($body);
    $stop=static function(string $stage)use($phase):void{if($phase!==$stage){return;}echo json_encode(['phase'=>$stage,'pid'=>getmypid()])."\n";fflush(STDOUT);$until=microtime(true)+20;while(microtime(true)<$until){usleep(10000);}throw new RuntimeException('Parent did not terminate the live child.');};
    Receiver\receiverLocked($settings,static function()use($settings,$body,$stop,$cancel):void{
        $plan=Receiver\receiverPlan($settings,Receiver\receiverCurrent($settings),$body,$cancel?Receiver\resolutionDelivery(Receiver\event($body)['event_id']):hash('sha256','recovery-delivery.'.$body),$cancel?'cancelled':'received');
        Receiver\receiverSaveWitness($settings,$plan,'prepared');$stop('prepared');
        Receiver\receiverTransaction($settings['pdo'],static function()use($settings,$plan,$stop):void{Receiver\receiverApplyPlan($settings,$plan);$stop('business-uncommitted');});$stop('business-committed');
        Receiver\receiverSaveWitness($settings,$plan,'committed');$stop('witness-committed');
    });
    throw new RuntimeException('Missing test stage.');
}catch(Throwable $failure){fwrite(STDERR,'recovery_child.failed: '.$failure->getMessage()."\n");exit(1);}
