<?php
declare(strict_types=1);
namespace SoSecurity\Examples\OutboxProducer;
if(realpath($_SERVER['SCRIPT_FILENAME'] ?? '')!==__FILE__){return;}
if(PHP_SAPI!=='cli'){http_response_code(404);return;}
ini_set('display_errors','0');$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;require __DIR__.'/outbox-business.php';
try{
    if(count($argv)!==4||!preg_match('/\A--key=([A-Za-z0-9][A-Za-z0-9_.:-]{15,127})\z/D',$argv[1],$key)||!preg_match('/\A--reference=([A-Za-z0-9_-]{1,64})\z/D',$argv[2],$reference)||!preg_match('/\A--amount=([1-9][0-9]{0,6})\z/D',$argv[3],$amount)||(int)$amount[1]>1000000){throw new \RuntimeException('Use fixed bounded command arguments.');}
    $settings=\SoSecurity\Examples\Outbox\settings('sender');$result=\SoSecurity\Examples\Outbox\produce($settings,$key[1],$reference[1],(int)$amount[1]);echo json_encode($result)."\n";
}catch(\Throwable $failure){fwrite(STDERR,"outbox_producer.unavailable\n");exit(1);}
