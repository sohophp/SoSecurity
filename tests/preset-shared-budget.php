<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Security;
use SoSecurity\Exception\ConfigurationException;

$backend=$argv[1]??'file';
if(!in_array($backend,['file','mysql','redis'],true)){throw new RuntimeException('Explicit preset backend required');}
$directory=privateDirectory();$connections=[];$services=[];$secondServices=[];
try{
    $presets=require dirname(__DIR__).'/examples/configuration-presets.php';
    $config=$presets['login_'.$backend];$config['site']='owned-preset-'.bin2hex(random_bytes(8));$clock=new TestClock();
    // Redis owns a real expiry clock; start this test clock at a real Unix timestamp.
    $clock->time=time();
    if($backend==='file'){$config['storage']['directory']=$directory;}
    else{
        $socket=getenv('SOSECURITY_TEST_'.strtoupper($backend).'_SOCKET');
        $pattern=$backend==='mysql'?'~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D':'~\A/tmp/sosecurity-preset-redis-[A-Za-z0-9_-]+/redis\.sock\z~D';
        $marker=$backend==='mysql'?'account-test-owner':'preset-test-owner';
        if(!is_string($socket)||!preg_match($pattern,$socket)||is_link(dirname($socket))||!is_file(dirname($socket).'/'.$marker)){throw new RuntimeException('Owned local backend required');}
        Check::throws(ConfigurationException::class,static function()use($config,$clock):void{Security::fromArray($config,[],$clock)->rateLimiter('login');});
        for($i=0;$i<2;++$i){
            if($backend==='mysql'){$connection=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);}
            else{$connection=new Redis();if(!$connection->connect($socket,0,2.0)){throw new RuntimeException('Owned Redis connection failed');}}
            $connections[]=$connection;
        }
        $services[$config['storage']['connection']]=$connections[0];$secondServices[$config['storage']['connection']]=$connections[1];
    }
    $first=Security::fromArray($config,$services,$clock);$first->initializeStorage();
    $second=Security::fromArray($config,$secondServices,$clock);
    $login=$first->rateLimiter('login');
    for($i=0;$i<5;++$i){Check::same(true,$login->consume('login-pair','owned-ip-account')->allowed);}
    $denied=$login->consume('login-pair','owned-ip-account');Check::same(false,$denied->allowed);Check::same(true,$denied->retryAfter>0);
    Check::same(false,$second->rateLimiter('login')->consume('login-pair','owned-ip-account')->allowed);
    Check::same(true,$second->rateLimiter('login')->consume('login-pair','other-account')->allowed);
    Check::same(true,$second->rateLimiter('ip')->consume('ip','owned-ip')->allowed);
    $otherConfig=$config;$otherConfig['site'].='-other';$other=Security::fromArray($otherConfig,$secondServices,$clock);$other->initializeStorage();
    Check::same(true,$other->rateLimiter('login')->consume('login-pair','owned-ip-account')->allowed);
    Check::same(false,$login->inspect('login-pair','owned-ip-account')->allowed);
    $second->rateLimiter('login')->reset('login-pair','owned-ip-account');Check::same(true,$login->consume('login-pair','owned-ip-account')->allowed);
    $clock->time+=901;Check::same(true,$second->rateLimiter('login')->consume('login-pair','owned-ip-account')->allowed);
    if($backend==='mysql'){foreach($connections as $connection){Check::same(false,$connection->inTransaction());}}
    echo 'PASS actual login preset '.$backend.' '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}finally{foreach($connections as $connection){if($connection instanceof Redis){$connection->close();}}$connections=[];cleanDirectory($directory);}
