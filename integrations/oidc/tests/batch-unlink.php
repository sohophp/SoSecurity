<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[1]) && $argv[1]!=='-'){require $argv[1];}
spl_autoload_register(static function(string $name):void{$p='SoSecurity\\Oidc\\';if(strpos($name,$p)===0){require dirname(__DIR__).'/src/'.substr($name,strlen($p)).'.php';}});
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;
function batchRemote(string $name,int $now):VerifiedSubject{
    $r=new ReflectionClass(VerifiedSubject::class);$proof=$r->newInstanceWithoutConstructor();$p=$r->getProperty('read');if(PHP_VERSION_ID<80100){$p->setAccessible(true);}
    $p->setValue($proof,static function()use($name,$now):array{return ['https://issuer.example.test',$name,$now,'sid'];});return $proof;
}
$directory=privateDirectory();
try{
 foreach(in_array($argv[2]??'',['mysql','redis'],true)?[$argv[2]]:['memory','file'] as $backend){
  foreach(['success','limit','oversize','duplicate','shape','deny','throw','expired','identity','relink','missing_created','revoke_guard','partial_guard','references','maximum','foreign'] as $case){
    $clock=new TestClock();$ns='batch-'.bin2hex(random_bytes(8));
    if($backend==='mysql'){
        $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned MySQL only');}
        $store=new MySqlStore(new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]),$ns,$clock);
    }elseif($backend==='redis'){
        $clock->time=time();$socket=getenv('SOSECURITY_TEST_OIDC_REDIS_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-oidc-redis-[A-Za-z0-9_-]+/redis\.sock\z~D',$socket)||!is_file(dirname($socket).'/oidc-test-owner')){throw new RuntimeException('Owned Redis only');}
        $redis=new Redis();$redis->connect($socket,0,1);$store=new RedisStore($redis,$ns,$clock);$store->initialize();
    }else{$store=$backend==='file'?new FileStore($directory,$ns,$clock):new MemoryStore($clock);}
    $account=new Account('tenant','alice','1');$other=new Account('tenant','bob','1');$current=$account;
    $provider=new CallbackIdentityProvider(static function($s,$id)use(&$current,$other){return $id==='bob'?$other:$current;},static function($s,$id)use(&$current,$other){return $id==='bob'?$other:$current;});
    $phaseCalls=0;$currentAllowed=true;
    $guard=static function(string $phase)use(&$phaseCalls,&$currentAllowed,$case):bool{if($phase==='federation_unlink_batch_current'){++$phaseCalls;return $currentAllowed&&($case!=='partial_guard'||$phaseCalls<2);}return true;};
    $sessions=new SessionRegistry($store,$provider,null,$clock);$flow=new AuthenticationFlow($store,$provider,$sessions,$guard,null,$clock);
    $token=$flow->password('tenant','browser','alice','synthetic')->credential()->token();$fence=new LogoutFence($store,$clock);$links=new LinkRegistry($store,$provider,$sessions,$guard,$clock,$fence);
    $one=batchRemote('one',$clock->time);$two=batchRemote('two',$clock->time);$three=batchRemote('three',$clock->time);
    $links->link('tenant','alice',$token,$one);$links->link('tenant','alice',$token,$two);
    $federated=new FederatedSessions($store,$provider,$links,$fence,$guard,null,$clock);$federatedToken=$federated->issue('tenant',$one)->token();
    $targets=[['issuer'=>'https://issuer.example.test','subject'=>'one'],['issuer'=>'https://issuer.example.test','subject'=>'two'],['issuer'=>'https://issuer.example.test','subject'=>'three']];
    if($case==='limit'){$targets=array_fill(0,33,$targets[0]);}
    if($case==='oversize'){$targets=array_fill(0,60000,null);}
    if($case==='duplicate'){$targets[1]=$targets[0];}
    if($case==='shape'){$targets[1]['extra']='no';}
    if($case==='maximum'){for($i=3;$i<32;++$i){$targets[]=['issuer'=>'https://issuer.example.test','subject'=>'missing'.$i];}}
    if($case==='foreign'){$bob=$flow->password('tenant','bob-browser','bob','synthetic')->credential()->token();$links->link('tenant','bob',$bob,$three);}
    $remoteName='one';if($case==='references'){$targets[0]['subject']=&$remoteName;}
    $approvals=0;
    $approve=static function($scope,$subject,array $manifest)use(&$approvals,$case,$clock,&$current,&$currentAllowed,$links,$token,$two,$three,&$remoteName):bool{
        ++$approvals;Check::same('tenant',$scope);Check::same('alice',$subject);Check::same('one',$manifest[0]['subject']);Check::same(true,$manifest[0]['exists']);Check::same(32,strlen($manifest[0]['binding_id']));Check::same(false,$manifest[2]['exists']);
        if($case==='deny'){return false;}if($case==='throw'){throw new RuntimeException('PRIVATE-APPROVAL');}
        if($case==='expired'){$clock->time+=300;}if($case==='identity'){$current=new Account('tenant','alice','2');}
        if($case==='relink'){$links->unlink('tenant','alice',$token,$two);$links->link('tenant','alice',$token,$two);}
        if($case==='missing_created'){$links->link('tenant','alice',$token,$three);}
        if($case==='revoke_guard'){$currentAllowed=false;}if($case==='references'){$remoteName='two';}
        return true;
    };
    $ok=in_array($case,['success','references','maximum'],true);
    if($ok){$result=$links->unlinkBatch('tenant','alice',$token,$targets,$approve);Check::same(count($targets),count($result));Check::same([true,true,false],array_slice($result,0,3));}
    else{try{$links->unlinkBatch('tenant','alice',$token,$targets,$approve);throw new LogicException('Expected refusal');}catch(SecurityException $e){Check::same(null,$e->getPrevious());Check::same(false,strpos((string)$e,'PRIVATE-APPROVAL')!==false);}}
    Check::same(in_array($case,['limit','oversize','duplicate','shape','foreign'],true)?0:1,$approvals);
    // Inspect actual bindings even after deliberately changing the provider or the authentication age.
    $current=$account;
    Check::same($ok||$case==='partial_guard', $links->currentBinding('tenant','https://issuer.example.test','one',$account)===null);
    Check::same($ok, $links->currentBinding('tenant','https://issuer.example.test','two',$account)===null);
    if($ok){Check::same(null,$federated->verify('tenant','alice',$federatedToken));Check::same(true,$sessions->verify('tenant','alice',$token)!==null);}
  }
 }
 echo 'PASS OIDC bounded batch unlink: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
}finally{cleanDirectory($directory);}
