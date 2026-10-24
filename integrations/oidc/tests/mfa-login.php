<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[1])){require $argv[1];}
spl_autoload_register(static function(string $name):void{
    $prefix='SoSecurity\\Oidc\\';if(strpos($name,$prefix)===0){require dirname(__DIR__).'/src/'.substr($name,strlen($prefix)).'.php';}
});
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\TotpSecondFactor;
use SoSecurity\Crypto\Cipher;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Mfa\Totp;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Oidc\VerifiedLogout;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\Change;
use SoSecurity\Support\Guard;

final class OidcTestFactor implements SecondFactor
{
    private $inner;public $after;public $calls=0;
    public function __construct(SecondFactor $inner){$this->inner=$inner;}
    public function binding(string $scope,string $subject):?string{return $this->inner->binding($scope,$subject);}
    public function verify(string $scope,string $subject,string $expectedBinding,$proof):?string{
        ++$this->calls;$method=$this->inner->verify($scope,$subject,$expectedBinding,$proof);
        if($this->after!==null){$after=$this->after;$this->after=null;$after();}return $method;
    }
}
function oidcMfaRemote(int $time,bool $logout=false){
    $class=new ReflectionClass($logout?VerifiedLogout::class:VerifiedSubject::class);$proof=$class->newInstanceWithoutConstructor();
    $read=$class->getProperty('read');if(PHP_VERSION_ID<80100){$read->setAccessible(true);}
    $parts=$logout?['https://issuer.example.test','external-alice','sid','logout-test',$time]:['https://issuer.example.test','external-alice',$time,'sid'];
    $read->setValue($proof,static function()use($parts):array{return $parts;});return $proof;
}
if(!extension_loaded('sodium')){throw new RuntimeException('This real MFA lifecycle requires ext-sodium; do not count a dependency refusal as a pass.');}
$directory=privateDirectory();
try{
    foreach(in_array($argv[2] ?? '',['mysql','redis'],true)?[$argv[2]]:['memory','file'] as $backend){
        foreach(['success','recovery','attempts','expiry','binding','cancel','replaced','relink','logout','factor_changed','account_changed','guard','late_proof','reentrant','fault','guard_after','cancel_during','replaced_during','relink_during','logout_during','account_during'] as $scenario){
            $clock=new TestClock();$namespace='oidc-mfa-'.$scenario.'-'.bin2hex(random_bytes(4));
            if($backend==='redis'){
                $clock->time=time();
                $socket=getenv('SOSECURITY_TEST_OIDC_REDIS_SOCKET');
                if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-oidc-redis-[A-Za-z0-9_-]+/redis\.sock\z~D',$socket)||!is_file(dirname($socket).'/oidc-test-owner')){throw new RuntimeException('Owned no-TCP Redis required.');}
                $redis=new Redis();$redis->connect($socket,0,1.0);$store=new RedisStore($redis,$namespace,$clock,1000,32);$store->initialize();
            }elseif($backend==='mysql'){
                $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
                if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned no-TCP MySQL required.');}
                $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
                $store=new MySqlStore($pdo,$namespace,$clock);
            }else{$store=$backend==='file'?new FileStore($directory,$namespace,$clock):new MemoryStore($clock);}
            $account=new Account('tenant','alice','1',true,[],true);$current=$account;
            $provider=new CallbackIdentityProvider(static function()use(&$current){return $current;},static function()use(&$current){return $current;});
            $totp=new Totp();$mfa=new TotpFactors($store,new Cipher('test',['test'=>str_repeat('K',32)],'oidc-mfa'),'Test',$clock);
            $enrollment=$mfa->begin('tenant','alice','alice@example.test');parse_str(parse_url($enrollment->provisioningUri(),PHP_URL_QUERY),$params);$secret=$params['secret'];
            $codes=$mfa->confirm('tenant','alice',$enrollment->id(),$totp->codeAt($secret,$clock->time));Check::same(10,count($codes));
            $factor=new OidcTestFactor(new TotpSecondFactor($mfa));$allowed=true;
            $guard=static function()use(&$allowed):bool{return $allowed;};
            $localSessions=new SessionRegistry($store,$provider,$factor,$clock);
            $flow=new AuthenticationFlow($store,$provider,$localSessions,$guard,$factor,$clock);
            $localPending=$flow->password('tenant','local-browser','alice','synthetic');$clock->time+=30;
            $local=$flow->secondFactor('tenant','local-browser',$localPending->challenge(),['type'=>'totp','code'=>$totp->codeAt($secret,$clock->time)])->credential();Check::same(true,$local!==null);
            $fence=new LogoutFence($store,$clock);$links=new LinkRegistry($store,$provider,$localSessions,$guard,$clock,$fence);$remote=oidcMfaRemote($clock->time);
            Check::same(true,$links->link('tenant','alice',$local->token(),$remote));
            $sessions=new FederatedSessions($store,$provider,$links,$fence,$guard,$factor,$clock);
            Check::same(null,$sessions->issue('tenant',$remote));
            $pending=$sessions->begin('tenant','oidc-browser',$remote);Check::same('mfa_required',$pending->status());Check::same(null,$pending->credential());
            $factor->calls=0;$clock->time+=30;$proof=['type'=>'totp','code'=>$totp->codeAt($secret,$clock->time)];
            if($scenario==='recovery'||$scenario==='fault'){$proof=['type'=>'recovery','code'=>$codes[0]];}
            if($scenario==='attempts'){
                for($i=0;$i<5;++$i){Check::same('denied',$sessions->secondFactor('tenant','oidc-browser',$pending->challenge(),['type'=>'totp','code'=>'invalid'])->status());}
            }
            if($scenario==='expiry'){$clock->time+=300;}
            if($scenario==='cancel'){$sessions->cancel('tenant','oidc-browser');}
            if($scenario==='replaced'){$sessions->begin('tenant','oidc-browser',$remote);}
            if($scenario==='relink'){$links->unlink('tenant','alice',$local->token(),$remote);$links->link('tenant','alice',$local->token(),$remote);}
            if($scenario==='logout'){$fence->record('tenant',oidcMfaRemote($clock->time,true));}
            if($scenario==='factor_changed'){$mfa->disable('tenant','alice',$codes[1],true);}
            if($scenario==='account_changed'){$current=new Account('tenant','alice','2',true,[],true);}
            if($scenario==='guard'){$allowed=false;Check::throws(SecurityException::class,static function()use($sessions,$pending,$proof):void{$sessions->secondFactor('tenant','oidc-browser',$pending->challenge(),$proof);});Check::same(0,$factor->calls);continue;}
            if($scenario==='late_proof'){$factor->after=static function()use($clock):void{$clock->time+=10;};}
            if($scenario==='cancel_during'){$factor->after=static function()use($sessions):void{$sessions->cancel('tenant','oidc-browser');};}
            if($scenario==='replaced_during'){$factor->after=static function()use($sessions,$remote):void{$sessions->begin('tenant','oidc-browser',$remote);};}
            if($scenario==='relink_during'){$factor->after=static function()use($links,$local,$remote):void{$links->unlink('tenant','alice',$local->token(),$remote);$links->link('tenant','alice',$local->token(),$remote);};}
            if($scenario==='logout_during'){$factor->after=static function()use($fence,$clock):void{$fence->record('tenant',oidcMfaRemote($clock->time,true));};}
            if($scenario==='account_during'){$factor->after=static function()use(&$current):void{$current=new Account('tenant','alice','2',true,[],true);};}
            if($scenario==='guard_after'){
                $factor->after=static function()use(&$allowed):void{$allowed=false;};
                Check::throws(DependencyException::class,static function()use($sessions,$pending,$proof):void{$sessions->secondFactor('tenant','oidc-browser',$pending->challenge(),$proof);});
                Check::same(1,$factor->calls);continue;
            }
            if($scenario==='fault'){
                $factor->after=static function():void{throw new RuntimeException('PRIVATE-FACTOR-ERROR');};
                try{$sessions->secondFactor('tenant','oidc-browser',$pending->challenge(),$proof);throw new LogicException('Expected dependency failure');}
                catch(DependencyException $e){Check::same('federation.factor_unavailable',$e->reason());Check::same(null,$e->getPrevious());}
                Check::same(1,$factor->calls);Check::same(9,$mfa->status('tenant','alice')['recovery_remaining']);continue;
            }
            if($scenario==='reentrant'){$factor->after=static function()use($sessions,$pending,$codes):void{Check::same('denied',$sessions->secondFactor('tenant','oidc-browser',$pending->challenge(),['type'=>'recovery','code'=>$codes[1]])->status());};}
            $result=$sessions->secondFactor('tenant',$scenario==='binding'?'other-browser':'oidc-browser',$pending->challenge(),$proof);
            $success=in_array($scenario,['success','recovery','reentrant'],true);Check::same($success?'authenticated':'denied',$result->status());
            if($success){
                $verified=$sessions->verify('tenant','alice',$result->credential()->token());Check::same('oidc',$verified->method());Check::same($scenario==='recovery'?'recovery':'totp',$verified->secondFactorMethod());
                Check::same(null,$localSessions->verify('tenant','alice',$result->credential()->token()));
                Check::same('denied',$sessions->secondFactor('tenant','oidc-browser',$pending->challenge(),$proof)->status());Check::same(1,$factor->calls);
                $again=$sessions->begin('tenant','oidc-browser',$remote);Check::same('denied',$sessions->secondFactor('tenant','oidc-browser',$again->challenge(),$proof)->status());
            }else{
                Check::same(null,$result->credential());Check::same($scenario==='attempts'?5:($scenario==='late_proof'||strpos($scenario,'_during')!==false?1:0),$factor->calls);
            }
            if($scenario==='factor_changed'){Check::same('enrollment_required',$sessions->begin('tenant','oidc-browser',$remote)->status());}
            if($scenario==='success'){
                Check::same([true],$links->unlinkBatch('tenant','alice',$local->token(),[['issuer'=>'https://issuer.example.test','subject'=>'external-alice']],static function():bool{return true;}));
                Check::same(null,$sessions->verify('tenant','alice',$result->credential()->token()));
                Check::same(true,$localSessions->verify('tenant','alice',$local->token())!==null);
            }
            Check::throws(ConfigurationException::class,static function()use($sessions):void{serialize($sessions);});
        }
    }
}finally{cleanDirectory($directory);}
echo 'PASS OIDC local MFA login: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; real encrypted TOTP/recovery codes, bounded challenge, current authority and separate session\n";
