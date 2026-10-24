<?php
declare(strict_types=1);
if($argc!==4){throw new RuntimeException('Expected autoload, owned directory and action.');}
require $argv[1];require dirname(__DIR__,3).'/tests/bootstrap.php';
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\TotpSecondFactor;
use SoSecurity\Crypto\Cipher;
use SoSecurity\Mfa\Totp;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;

final class PausingOidcFactor implements SecondFactor
{
    private $inner;private $directory;private $pause;
    public function __construct(SecondFactor $inner,string $directory,bool $pause){$this->inner=$inner;$this->directory=$directory;$this->pause=$pause;}
    public function binding(string $scope,string $subject):?string{return $this->inner->binding($scope,$subject);}
    public function verify(string $scope,string $subject,string $expectedBinding,$proof):?string{
        $method=$this->inner->verify($scope,$subject,$expectedBinding,$proof);
        if($this->pause){
            $this->pause=false;file_put_contents($this->directory.'/ready','1');$deadline=microtime(true)+10;
            while(!is_file($this->directory.'/go')){if(microtime(true)>=$deadline){throw new RuntimeException('MFA process was not released.');}usleep(10000);}
        }
        return $method;
    }
}
umask(0077);$directory=$argv[2];$action=$argv[3];$clock=new TestClock();$base=$action==='setup'?time():(int)file_get_contents($directory.'/clock');
if($action==='setup'){file_put_contents($directory.'/clock',(string)$base);}
$clock->time=$base+30;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
$redisSocket=getenv('SOSECURITY_TEST_OIDC_REDIS_SOCKET');
if(is_string($redisSocket)&&$redisSocket!==''){
    if(!preg_match('~\A/tmp/sosecurity-oidc-redis-[A-Za-z0-9_-]+/redis\.sock\z~D',$redisSocket)||!is_file(dirname($redisSocket).'/oidc-test-owner')){throw new RuntimeException('Owned no-TCP Redis required.');}
    $redis=new Redis();$redis->connect($redisSocket,0,1.0);$store=new RedisStore($redis,'oidc-mfa-process-'.hash('sha256',$directory),$clock,1000,32);
    if($action==='setup'){$store->initialize();}
}elseif(is_string($socket)&&$socket!==''){
    if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned no-TCP MySQL required.');}
    $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $store=new MySqlStore($pdo,'oidc-mfa-process-'.hash('sha256',$directory),$clock);
}else{$store=new FileStore($directory,'oidc-mfa-process',$clock);}
$account=new Account('tenant','alice','1',true,[],true);
$provider=new CallbackIdentityProvider(static function()use($account){return $account;},static function()use($account){return $account;});
$guard=static function():bool{return true;};$totp=new Totp();
$mfa=new TotpFactors($store,new Cipher('test',['test'=>str_repeat('K',32)],'oidc-mfa-process'),'Test',$clock);
$factor=new PausingOidcFactor(new TotpSecondFactor($mfa),$directory,$action==='complete_pause');
$local=new SessionRegistry($store,$provider,$factor,$clock);$fence=new LogoutFence($store,$clock);$links=new LinkRegistry($store,$provider,$local,$guard,$clock,$fence);
$sessions=new FederatedSessions($store,$provider,$links,$fence,$guard,$factor,$clock);
if($action==='setup'){
    $clock->time=$base;$enrollment=$mfa->begin('tenant','alice','alice@example.test');parse_str(parse_url($enrollment->provisioningUri(),PHP_URL_QUERY),$parts);
    $codes=$mfa->confirm('tenant','alice',$enrollment->id(),$totp->codeAt($parts['secret'],$clock->time));
    $flow=new AuthenticationFlow($store,$provider,$local,$guard,$factor,$clock);$login=$flow->password('tenant','local','alice','synthetic');$clock->time=$base+30;
    $credential=$flow->secondFactor('tenant','local',$login->challenge(),['type'=>'totp','code'=>$totp->codeAt($parts['secret'],$clock->time)])->credential();
    $class=new ReflectionClass(VerifiedSubject::class);$remote=$class->newInstanceWithoutConstructor();$read=$class->getProperty('read');if(PHP_VERSION_ID<80100){$read->setAccessible(true);}
    $read->setValue($remote,static function()use($base):array{return ['https://issuer.example.test','external-alice',$base+30,'sid'];});
    if(!$links->link('tenant','alice',$credential->token(),$remote)){throw new RuntimeException('Link setup failed.');}
    $pending=$sessions->begin('tenant','browser',$remote);
    file_put_contents($directory.'/input',json_encode(['challenge'=>$pending->challenge(),'codes'=>$codes]));echo "ready\n";
}elseif(in_array($action,['complete_pause','compete','replay'],true)){
    $data=json_decode(file_get_contents($directory.'/input'),true);
    $result=$sessions->secondFactor('tenant','browser',$data['challenge'],['type'=>'recovery','code'=>$data['codes'][$action==='complete_pause'?0:1]]);
    if($result->credential()!==null){file_put_contents($directory.'/session',$result->credential()->token());}
    echo $result->status()."\n";
}elseif($action==='verify'){
    $session=$sessions->verify('tenant','alice',file_get_contents($directory.'/session'));
    if($session===null||$session->secondFactorMethod()!=='recovery'||$mfa->status('tenant','alice')['recovery_remaining']!==9){throw new RuntimeException('MFA process consumed a second proof or lost authority.');}
    echo "verified\n";
}else{throw new RuntimeException('Unknown action.');}
