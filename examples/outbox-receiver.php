<?php
declare(strict_types=1);
namespace SoSecurity\Examples\OutboxReceiver;
if(PHP_SAPI==='cli'){return;}
ini_set('display_errors','0');$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;require __DIR__.'/outbox-business.php';
function response(int $status,array $data):void
{
    http_response_code($status);header('Content-Type: application/json');header('Cache-Control: no-store, private');header('X-Content-Type-Options: nosniff');header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'");echo json_encode($data);
}
try{
    if(($_SERVER['REQUEST_METHOD'] ?? '')!=='POST'){header('Allow: POST');response(405,['error'=>'outbox_receiver.method']);return;}
    if(($_SERVER['SOSECURITY_OUTBOX_HEADERS_VALIDATED'] ?? '')!=='1'||!in_array(strtolower($_SERVER['HTTPS'] ?? ''),['on','1'],true)){throw new \RuntimeException('A trusted duplicate-rejecting HTTPS ingress is required.');}
    if(isset($_SERVER['HTTP_TRANSFER_ENCODING'])||isset($_SERVER['TRANSFER_ENCODING'])||isset($_SERVER['HTTP_CONTENT_ENCODING'])||($_SERVER['CONTENT_TYPE'] ?? '')!=='application/json'||!is_string($_SERVER['CONTENT_LENGTH'] ?? null)||!preg_match('/\A(?:0|[1-9][0-9]{0,3})\z/D',$_SERVER['CONTENT_LENGTH'])||(int)$_SERVER['CONTENT_LENGTH']>8192){throw new \SoSecurity\Exception\ValidationException('Use bounded unambiguous JSON framing.','outbox_example.input');}
    $settings=\SoSecurity\Examples\Outbox\settings('receiver',$_SERVER['DOCUMENT_ROOT'] ?? '');$uri=\SoSecurity\Http\Uri::parse($settings['url']);
    if(($_SERVER['HTTP_HOST'] ?? '')!==substr($uri->origin(),8)||($_SERVER['REQUEST_URI'] ?? '')!==$uri->target()){throw new \RuntimeException('Actual Host and target differ from configured receiver.');}
    $ip=(new \SoSecurity\Http\ClientIp())->resolve($_SERVER);if(!\SoSecurity\Examples\Outbox\budget($settings,'outbox.entry',$ip,240)){response(429,['error'=>'outbox_receiver.rate']);return;}
    $body=file_get_contents('php://input',false,null,0,8193);if(!is_string($body)||strlen($body)!==(int)$_SERVER['CONTENT_LENGTH']){throw new \SoSecurity\Exception\ValidationException('Body length mismatch.','outbox_example.input');}
    $headers=[];foreach(['Webhook-Id'=>'HTTP_WEBHOOK_ID','Webhook-Timestamp'=>'HTTP_WEBHOOK_TIMESTAMP','Webhook-Signature'=>'HTTP_WEBHOOK_SIGNATURE'] as $name=>$server){if(isset($_SERVER[$server])){$headers[$name]=$_SERVER[$server];}}
    $guard=static function($endpoint,$request)use($uri):bool{return ($_SERVER['SOSECURITY_OUTBOX_HEADERS_VALIDATED'] ?? '')==='1'&&in_array(strtolower($_SERVER['HTTPS'] ?? ''),['on','1'],true)&&($_SERVER['HTTP_HOST'] ?? '')===substr($uri->origin(),8)&&($_SERVER['REQUEST_URI'] ?? '')===$uri->target()&&($_SERVER['REQUEST_METHOD'] ?? '')==='POST';};
    $request=new \SoSecurity\Webhook\Request('POST',$settings['url'],$body,$headers);response(200,\SoSecurity\Examples\Outbox\receive($settings,$request,$guard));
}catch(\SoSecurity\Exception\ValidationException $failure){response(400,['error'=>'outbox_receiver.input']);}
catch(\SoSecurity\Exception\SecurityException $failure){$reason=$failure->reason();$status=$reason==='outbox_example.denied'?403:($reason==='outbox_example.rate'?429:(in_array($reason,['webhook.inbox_conflict','outbox_example.conflict'],true)?409:503));response($status,['error'=>$status===403?'outbox_receiver.denied':($status===409?'outbox_receiver.conflict':'outbox_receiver.unavailable')]);}
catch(\Throwable $failure){response(503,['error'=>'outbox_receiver.unavailable']);}
