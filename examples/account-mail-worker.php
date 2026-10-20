<?php
declare(strict_types=1);
namespace SoSecurity\Examples\AccountMail;
// Importing the example never reads configuration or starts work.
if(realpath($_SERVER['SCRIPT_FILENAME'] ?? '')!==__FILE__){return;}
if(PHP_SAPI!=='cli'){http_response_code(404);return;}
ini_set('display_errors','0');
try{
    if(count($argv)<2||count($argv)>3||$argv[1]!=='--once'||(isset($argv[2])&&!preg_match('/\A--after=(0|[1-9][0-9]{0,17})\z/D',$argv[2],$cursor))){throw new \RuntimeException('Explicit single-step invocation required.');}
    $path=getenv('SOSECURITY_ACCOUNT_MAIL_BOOTSTRAP');$real=is_string($path)?realpath($path):false;
    if($real===false||$real!==$path||is_link($path)||!is_file($path)||!is_dir(dirname($path))||(fileperms($path)&0077)!==0||(fileperms(dirname($path))&0077)!==0||filesize($path)>65536){throw new \RuntimeException('Use an existing canonical private worker bootstrap.');}
    $autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;
    // Trusted host code explicitly builds one service dispatcher; it must not initialize schemas or producers.
    $worker=require $path;if(!$worker instanceof \SoSecurity\Account\Dispatcher){throw new \RuntimeException('Current account dispatcher required.');}
    $result=$worker->sendNext(isset($cursor)?(int)$cursor[1]:0);echo json_encode($result)."\n";
    if(in_array($result['state'],['rejected','unknown'],true)){exit(2);}
}catch(\Throwable $error){fwrite(STDERR,"account_mail_worker.unavailable\n");exit(1);}
