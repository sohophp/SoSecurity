<?php
declare(strict_types=1);
namespace SoSecurity\Examples\WebhookWorker;

use PDO;
use SoSecurity\Security;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\Message;

// Inclusion is inert; serving this CLI entry point over HTTP never runs a worker.
if(PHP_SAPI!=='cli'){http_response_code(404);return;}
if(realpath($_SERVER['SCRIPT_FILENAME'] ?? '')!==__FILE__){return;}
ini_set('display_errors','0');
$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;
require __DIR__.'/webhook-business.php';

function privateFile(string $name,string $web):string
{
    $value=getenv($name);$path=$value?realpath($value):false;
    if($path===false||$path!==$value||!is_file($path)||is_link($value)||(fileperms($path)&0077)!==0||$path===$web||strpos($path,rtrim($web,'/').'/')===0){throw new \RuntimeException('Private canonical file required.');}
    $parent=dirname($path);if((fileperms($parent)&0077)!==0){throw new \RuntimeException('Private parent directory required.');}
    return $path;
}

try{
    $arguments=$argv;array_shift($arguments);$cursor='';
    if(count($arguments)<1||count($arguments)>2||$arguments[0]!=='--once'||(isset($arguments[1])&&!preg_match('/\A--after=([a-f0-9]{32})\z/D',$arguments[1],$match))){throw new \RuntimeException('Explicit bounded worker invocation required.');}
    if(isset($arguments[1])){$cursor=$match[1];}
    $root=getenv('SOSECURITY_WEBHOOK_EXAMPLE_DOCUMENT_ROOT');$web=$root?realpath($root):false;
    $origin=getenv('SOSECURITY_WEBHOOK_EXAMPLE_ORIGIN');$path=getenv('SOSECURITY_WEBHOOK_EXAMPLE_PATH') ?: '/webhooks.php';$secure=getenv('SOSECURITY_WEBHOOK_EXAMPLE_HTTPS')!=='0';
    $worker=getenv('SOSECURITY_WEBHOOK_EXAMPLE_WORKER');
    if(getenv('SOSECURITY_WEBHOOK_EXAMPLE_PROCESSING')!=='1'||$web===false||$web!==$root||!is_dir($web)||!is_string($worker)||!preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,63}\z/D',$worker)||!is_string($origin)||!is_string($path)||!preg_match('/\A\/[A-Za-z0-9_\/-]+\.php\z/D',$path)){throw new \RuntimeException('Explicit trusted worker configuration required.');}
    new \SoSecurity\Link\Policy($origin,300,86400,32,!$secure);
    if(($secure&&strpos($origin,'https://')!==0)||(!$secure&&strpos($origin,'http://')!==0)){throw new \RuntimeException('Origin transport mismatch.');}
    $pdo=new PDO('sqlite:'.privateFile('SOSECURITY_WEBHOOK_EXAMPLE_DATABASE',$web),null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
    $raw=file_get_contents(privateFile('SOSECURITY_WEBHOOK_EXAMPLE_SEAL_KEYS',$web),false,null,0,16385);
    $input=is_string($raw)&&strlen($raw)<=16384?json_decode($raw,true,4):null;
    if(!is_array($input)||count($input)!==2||!is_string($input['current'] ?? null)||!is_array($input['keys'] ?? null)||!isset($input['keys'][$input['current']])||count($input['keys'])<1||count($input['keys'])>8){throw new \RuntimeException('Invalid receipt sealing keys.');}
    $keys=[];foreach($input['keys'] as $id=>$encoded){$key=is_string($encoded)?base64_decode($encoded,true):false;if(!is_string($key)||strlen($key)!==32||base64_encode($key)!==$encoded){throw new \RuntimeException('Invalid receipt sealing key.');}$keys[$id]=$key;}
    $security=Security::fromArray(['site'=>\SoSecurity\Examples\WebhookBusiness\SCOPE,'webhooks'=>['events'=>[
        'scope'=>\SoSecurity\Examples\WebhookBusiness\SCOPE,'account'=>\SoSecurity\Examples\WebhookBusiness\ACCOUNT,'url'=>$origin.$path.'?receive=1','protocol'=>'standard-hmac','policy'=>['allow_http'=>!$secure],
        'processing'=>['connection'=>'business_db','integrity_keys'=>'receipt_keys','mapper'=>'body_mapper','association_guard'=>'current_business','worker_guard'=>'trusted_process'],
    ]]],['business_db'=>$pdo,'receipt_keys'=>new HmacKeys($input['current'],$keys),
        'body_mapper'=>static function(string $body,Endpoint $endpoint,string $receipt,array $metadata):?Message{return \SoSecurity\Examples\WebhookBusiness\map($body,$endpoint,$metadata['message_id']);},
        'current_business'=>static function(Endpoint $endpoint,Message $message)use($pdo):bool{return \SoSecurity\Examples\WebhookBusiness\associated($pdo,$endpoint,$message);},
        // The CLI account and its access to private configuration establish authority. A label alone is not authentication.
        'trusted_process'=>static function(string $operation,Endpoint $endpoint,string $receipt,string $label)use($worker):bool{return $label===$worker;},
    ]);
    $processor=$security->webhookProcessor('events');$page=$processor->pending($worker,20,$cursor);$claimed=0;$succeeded=0;$failed=0;
    foreach($page['receipt_ids'] as $receipt){
        $claim=$processor->claim($receipt,$worker);if($claim===null){continue;}++$claimed;
        try{
            $status=$processor->execute($worker,$claim->token(),static function(PDO $connection,Message $message,string $body,\SoSecurity\Webhook\ProcessingStatus $state):bool{
                if(!\SoSecurity\Examples\WebhookBusiness\apply($connection,$message,$body,$state)){throw new \RuntimeException('Business SQL did not complete.');}return true;
            });
        }catch(\SoSecurity\Exception\DependencyException $error){
            if($error->reason()!=='webhook.processing_handler'){throw $error;}
            // Only a handler failure whose transaction cleanup succeeded reaches this branch.
            // fail rechecks the live claim; it cannot reset an expired or already completed record.
            $processor->fail($worker,$claim->token(),'example.business_failed');++$failed;continue;
        }
        if($status!==null&&$status->status()==='succeeded'){++$succeeded;}
    }
    // Commit/cleanup/source uncertainty still exits through the outer refusal. Never invoke a handler again here.
    echo json_encode(['claimed'=>$claimed,'succeeded'=>$succeeded,'failed'=>$failed,'next_cursor'=>$page['next_cursor'],'complete'=>$page['complete']])."\n";
    if($failed>0){exit(2);}
}catch(\Throwable $error){fwrite(STDERR,"webhook_worker.unavailable\n");exit(1);}
