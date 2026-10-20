<?php
declare(strict_types=1);
namespace SoSecurity\Examples\OutboxAdmin;
if(realpath($_SERVER['SCRIPT_FILENAME'] ?? '')!==__FILE__){return;}
if(PHP_SAPI!=='cli'){http_response_code(404);return;}
ini_set('display_errors','0');$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;require __DIR__.'/outbox-business.php';
try{
    $settings=\SoSecurity\Examples\Outbox\settings('sender');if(!\SoSecurity\Examples\Outbox\principal($settings,'outbox_admin')){throw new \RuntimeException('Current management authority required.');}
    $queue=\SoSecurity\Examples\Outbox\outbox($settings);$result=null;
    if(count($argv)===2&&preg_match('/\A--initialize=([A-Za-z0-9_-]{1,64})\z/D',$argv[1],$target)){
        if(!\SoSecurity\Examples\Outbox\principal($settings,'orders_writer',$target[1])){throw new \RuntimeException('Current producer identity required.');}
        $result=['queue_created'=>$queue->initialize(\SoSecurity\Examples\Outbox\SCOPE,\SoSecurity\Examples\Outbox\PRODUCER,$settings['actor']),'writer_created'=>\SoSecurity\Examples\Outbox\idempotency($settings)->initialize(\SoSecurity\Examples\Outbox\SCOPE,$target[1],'orders.create')];
    }elseif(count($argv)===2&&$argv[1]==='--initialize-resolution'){$result=['initialized'=>\SoSecurity\Examples\Outbox\resolutionInitialize($settings)];}
    elseif(count($argv)===2&&preg_match('/\A--initialize-resolution-archive=([a-f0-9]{64})\z/D',$argv[1],$baseline)){$result=['initialized'=>\SoSecurity\Examples\Outbox\resolutionArchiveInitialize($settings,$baseline[1])];}
    elseif(count($argv)===2&&$argv[1]==='--resolution-audit-status'){$result=\SoSecurity\Examples\Outbox\resolutionAuditStatus($settings);}
    elseif(count($argv)>=2&&count($argv)<=3&&in_array($argv[1],['--resolution-audit-list=active','--resolution-audit-list=archived'],true)&&(!isset($argv[2])||strpos($argv[2],'--after=')===0)){$result=\SoSecurity\Examples\Outbox\resolutionAuditList($settings,$argv[1]==='--resolution-audit-list=archived',20,isset($argv[2])?substr($argv[2],8):'');}
    elseif(count($argv)>=2&&count($argv)<=3&&$argv[1]==='--archive-resolution'&&(!isset($argv[2])||strpos($argv[2],'--after=')===0)){$result=\SoSecurity\Examples\Outbox\resolutionArchive($settings,20,isset($argv[2])?substr($argv[2],8):'');}
    elseif(count($argv)>=2&&count($argv)<=3&&in_array($argv[1],['--rekey-resolution=active','--rekey-resolution=archived'],true)&&(!isset($argv[2])||strpos($argv[2],'--after=')===0)){$result=\SoSecurity\Examples\Outbox\resolutionRekey($settings,$argv[1]==='--rekey-resolution=archived',20,isset($argv[2])?substr($argv[2],8):'');}
    elseif(count($argv)===2&&strpos($argv[1],'--export-resolution-audit=')===0){$result=\SoSecurity\Examples\Outbox\resolutionAuditExport($settings,substr($argv[1],26));}
    elseif(count($argv)===2&&strpos($argv[1],'--export-resolution=')===0){$result=\SoSecurity\Examples\Outbox\resolutionExport($settings,substr($argv[1],20));}
    elseif(count($argv)===3&&strpos($argv[1],'--import-resolution=')===0){$result=\SoSecurity\Examples\Outbox\resolutionImport($settings,substr($argv[1],20),\SoSecurity\Examples\Outbox\resolutionInputFile($settings,$argv[2],4096));}
    elseif(count($argv)===2&&strpos($argv[1],'--resolution-status=')===0){$result=\SoSecurity\Examples\Outbox\resolutionStatus($settings,substr($argv[1],20));}
    elseif(count($argv)===2&&strpos($argv[1],'--retry=')===0){$result=['retried'=>$queue->retry(\SoSecurity\Examples\Outbox\SCOPE,\SoSecurity\Examples\Outbox\PRODUCER,substr($argv[1],8),$settings['actor'])];}
    elseif(count($argv)>=2&&count($argv)<=3&&$argv[1]==='--maintain'&&(!isset($argv[2])||preg_match('/\A--after=([a-f0-9]{64})\z/D',$argv[2],$cursor))){$result=$queue->maintain(\SoSecurity\Examples\Outbox\SCOPE,\SoSecurity\Examples\Outbox\PRODUCER,$settings['actor'],20,isset($cursor)?$cursor[1]:'');}
    else{throw new \RuntimeException('Use an explicit management action.');}
    echo (is_string($result)?$result:json_encode($result))."\n";
}catch(\Throwable $failure){fwrite(STDERR,"outbox_admin.unavailable\n");exit(1);}
