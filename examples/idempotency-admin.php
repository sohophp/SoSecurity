<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Idempotency;
if(PHP_SAPI!=='cli'){http_response_code(404);header('Cache-Control: no-store, private');header('X-Content-Type-Options: nosniff');header('Content-Type: text/plain; charset=utf-8');return;}
ini_set('display_errors','0');$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;require __DIR__.'/idempotency-business.php';
try{
    $command=$argv[1] ?? '--help';if($command==='--help'){echo "Usage: php idempotency-admin.php initialize SUBJECT | maintain SUBJECT [CURSOR] | issue SUBJECT [TTL] | revoke CREDENTIAL_ID\n";return;}
    if(!in_array($command,['initialize','maintain','issue','revoke'],true)||count($argv)<3||count($argv)>4){throw new \RuntimeException('Invalid command.');}
    $web=getenv('SOSECURITY_IDEMPOTENCY_EXAMPLE_DOCUMENT_ROOT');if(!is_string($web)||$web===''){throw new \RuntimeException('Explicit actual web root required.');}$config=settings($web);$api=new \SoSecurity\Api\ApiKeys($config['store']);
    if($command==='revoke'){if(count($argv)!==3||!preg_match('/\A[a-f0-9]{32}\z/D',$argv[2])){throw new \RuntimeException('Invalid credential ID.');}$result=['revoked'=>$api->revoke($argv[2])];}
    else{
        $subject=identifier($argv[2]);$actor=$command==='maintain'?null:account($config['pdo'],SCOPE,$subject);
        if($command!=='maintain'&&($actor===null||!$actor->enabled()||!in_array('orders_writer',$actor->roles(),true))){throw new \RuntimeException('Current writer account required.');}
        if($command==='issue'){$ttl=$argv[3] ?? '86400';if(!preg_match('/\A[1-9][0-9]{0,7}\z/D',$ttl)||(int)$ttl>31536000){throw new \RuntimeException('Invalid lifetime.');}$credential=$api->issue($subject.'@'.$actor->version(),['orders:create'],(int)$ttl);$result=['id'=>$credential->identity()->id(),'token'=>$credential->token(),'expires_at'=>$credential->expiresAt()];}
        else{
            // Private CLI access is the management boundary. It grants no HTTP management capability.
            $management=static function(string $operation,string $scope,string $owner,string $action)use($subject):bool{return in_array($operation,['initialize','maintain'],true)&&$scope===SCOPE&&$owner===$subject&&$action==='orders.create';};
            $executor=factory($config,null,$management)->idempotency();if($command==='initialize'){if(count($argv)!==3){throw new \RuntimeException('Unexpected initialize argument.');}$result=['initialized'=>$executor->initialize(SCOPE,$subject,'orders.create')];}else{$result=$executor->maintain(SCOPE,$subject,'orders.create',20,$argv[3] ?? '');}
        }
    }
    echo json_encode($result,JSON_UNESCAPED_SLASHES)."\n";
}catch(\Throwable $error){fwrite(STDERR,"idempotency_admin.unavailable\n");exit(1);}
