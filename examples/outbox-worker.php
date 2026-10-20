<?php
declare(strict_types=1);
namespace SoSecurity\Examples\OutboxWorker;
if(realpath($_SERVER['SCRIPT_FILENAME'] ?? '')!==__FILE__){return;}
if(PHP_SAPI!=='cli'){http_response_code(404);return;}
ini_set('display_errors','0');$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;require __DIR__.'/outbox-business.php';
try{
    if(count($argv)<2||count($argv)>3||$argv[1]!=='--once'||(isset($argv[2])&&(!preg_match('/\A--after=(0|[1-9][0-9]{0,17})\z/D',$argv[2],$cursor)))){throw new \RuntimeException('Use an explicit bounded worker invocation.');}
    $result=\SoSecurity\Examples\Outbox\sendOnce(\SoSecurity\Examples\Outbox\settings('sender'),isset($cursor)?(int)$cursor[1]:0);echo json_encode($result)."\n";if($result['failed']>0){exit(2);}
}catch(\Throwable $failure){fwrite(STDERR,"outbox_worker.unavailable\n");exit(1);}
