<?php
declare(strict_types=1);
namespace SoSecurity\Examples\OutboxReceiverAdmin;
if(realpath($_SERVER['SCRIPT_FILENAME'] ?? '')!==__FILE__){return;}
if(PHP_SAPI!=='cli'){http_response_code(404);return;}
ini_set('display_errors','0');$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;require __DIR__.'/outbox-business.php';
try{
    if(count($argv)!==2){throw new \RuntimeException('Use a fixed receiver management action.');}$settings=\SoSecurity\Examples\Outbox\settings('receiver');
    if($argv[1]==='--initialize'){$result=['initialized'=>\SoSecurity\Examples\Outbox\receiverInitialize($settings)];}
    elseif($argv[1]==='--recover'){$result=['recovered'=>\SoSecurity\Examples\Outbox\receiverRecover($settings)];}
    elseif($argv[1]==='--status'){$result=\SoSecurity\Examples\Outbox\receiverInspect($settings);}
    elseif($argv[1]==='--public-keys'){$result=\SoSecurity\Examples\Outbox\resolutionPublicKeys($settings);}
    elseif(strpos($argv[1],'--attest=')===0){$result=\SoSecurity\Examples\Outbox\resolutionTerminal($settings,\SoSecurity\Examples\Outbox\resolutionInputFile($settings,substr($argv[1],9),12000));}
    elseif(strpos($argv[1],'--cancel=')===0){$result=\SoSecurity\Examples\Outbox\resolutionTerminal($settings,\SoSecurity\Examples\Outbox\resolutionInputFile($settings,substr($argv[1],9),12000),true);}
    elseif(preg_match('/\A--rotate-epoch=([a-f0-9]{64}):([a-f0-9]{64})\z/D',$argv[1],$match)){$result=['rotated'=>\SoSecurity\Examples\Outbox\receiverRotateEpoch($settings,$match[1],$match[2])];}
    else{throw new \RuntimeException('Use an explicit receiver management action.');}
    echo (is_string($result)?$result:json_encode($result))."\n";
}catch(\Throwable $failure){fwrite(STDERR,"outbox_receiver_admin.unavailable\n");exit(1);}
