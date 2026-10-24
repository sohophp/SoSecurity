<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Auth\Account;use SoSecurity\Auth\AuthenticationFlow;use SoSecurity\Auth\CallbackIdentityProvider;use SoSecurity\Auth\DeviceRiskDecision;use SoSecurity\Auth\RememberedLogin;use SoSecurity\Auth\RememberResult;use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Storage\AtomicStore;use SoSecurity\Storage\Change;use SoSecurity\Storage\MemoryStore;use SoSecurity\Storage\FileStore;use SoSecurity\Storage\MySqlStore;use SoSecurity\Support\HmacKeys;use SoSecurity\Support\Guard;use SoSecurity\Exception\SecurityException;
/** Test-only observation and after-commit injection; never used as a product backend. */
final class RiskBoundaryStore implements AtomicStore
{
 private $inner;public $inside=false;public $after;public $values=[];public $committed;
 public function __construct(AtomicStore $inner){$this->inner=$inner;}
 public function transact(string $key,callable $callback){
  $value=null;$this->inside=true;
  try{$result=$this->inner->transact($key,static function($old)use($callback,&$value):Change{$change=$callback($old);$value=$change->value();return $change;});}finally{$this->inside=false;}
  $this->values[$key]=$value;
  if($result instanceof RememberResult&&$result->status()==='authenticated'){$this->committed=$result;if($this->after!==null){($this->after)();}}
  return $result;
 }
}
function riskBoundaryCached($action,$reason):DeviceRiskDecision
{
 $raw=serialize(new DeviceRiskDecision('allow','none'));$raw=str_replace('s:5:"allow";',serialize($action),$raw,$a);$raw=str_replace('s:4:"none";',serialize($reason),$raw,$b);if($a!==1||$b!==1){throw new RuntimeException('Unexpected decision encoding');}
 return unserialize($raw,['allowed_classes'=>[DeviceRiskDecision::class]]);
}
$backend=$argv[1]??'memory';$group=$argv[2]??'all';$directory=privateDirectory();$pdo=null;$createdTable=false;
$invalid=['unknown','allow-reason','deny-reason','step-reason','missing','null-action','int-reason','wrong-type','offline'];$late=['late-deny','late-step','late-unknown','late-reason','late-offline','late-expiry','late-identity'];$valid=['allow','deny','step','cached-allow'];$modes=$group==='invalid'?$invalid:($group==='late'?$late:array_merge($invalid,$late,$valid));
try{
 if($backend==='mysql'){
  $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required');}
  $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$ddl=str_replace('CREATE TABLE IF NOT EXISTS sosecurity_state','CREATE TABLE sosecurity_state',MySqlStore::schema(),$replaced);if($replaced!==1){throw new RuntimeException('Expected one owned test table');}$pdo->exec($ddl);$createdTable=true;
 }
 foreach($modes as $mode){
  $clock=new TestClock();$inner=$backend==='mysql'?new MySqlStore($pdo,'risk-boundary-'.$mode,$clock):($backend==='file'?new FileStore($directory,'risk-boundary-'.$mode,$clock):new MemoryStore($clock));$store=new RiskBoundaryStore($inner);$account=new Account('tenant','subject','v1');$riskCalls=0;$lateNow=false;
  $provider=new CallbackIdentityProvider(static function()use(&$account):?Account{return $account;},static function()use(&$account):?Account{return $account;});$guard=static function():bool{return true;};$sessions=new SessionRegistry($store,$provider,null,$clock,30,300,4);$flow=new AuthenticationFlow($store,$provider,$sessions,$guard,null,$clock);
  $risk=static function()use($mode,$store,$clock,&$account,&$riskCalls,&$lateNow){
   Check::same(false,$store->inside);++$riskCalls;
   $pick=$lateNow?substr($mode,5):($mode==='cached-allow'?'cached-allow':(strpos($mode,'late-')===0?'allow':$mode));
   if($pick==='offline'){throw new RuntimeException('PRIVATE-RISK-CACHE-MARKER');}
   if($pick==='wrong-type'){return true;}
   if($pick==='missing'){$name=DeviceRiskDecision::class;return unserialize('O:'.strlen($name).':"'.$name.'":0:{}',['allowed_classes'=>[$name]]);}
   if($pick==='null-action'){return riskBoundaryCached(null,'none');}
   if($pick==='int-reason'){return riskBoundaryCached('allow',1);}
   if($pick==='unknown'){return riskBoundaryCached('unexpected','PRIVATE-RISK-CACHE-MARKER');}
   if($pick==='allow-reason'||$pick==='reason'){return riskBoundaryCached('allow','compromised');}
   if($pick==='deny-reason'){return riskBoundaryCached('deny','none');}
   if($pick==='step-reason'){return riskBoundaryCached('step_up','none');}
   if($pick==='cached-allow'){return riskBoundaryCached('allow','none');}
   if($pick==='deny'){return new DeviceRiskDecision('deny','compromised');}
   if($pick==='step'){return new DeviceRiskDecision('step_up','changed');}
   if($pick==='expiry'){$clock->time+=301;}
   if($pick==='identity'){$account=new Account('tenant','subject','v2');}
   return new DeviceRiskDecision('allow','none');
  };
  $remember=new RememberedLogin($store,$provider,$sessions,new HmacKeys('test',['test'=>str_repeat('k',32)]),$guard,null,$clock,300,2,20,5,$risk);$login=$flow->password('tenant','browser','user','password')->credential();$grant=$remember->issue('tenant','subject',$login->token());$key=Guard::key('auth-sessions','tenant','subject');$before=$store->values[$key];
  if(strpos($mode,'late-')===0){$store->after=static function()use(&$lateNow):void{$lateNow=true;};}
  $result=null;$error=null;try{$result=$remember->resume('tenant',$grant->token());}catch(Throwable $caught){$error=$caught;}
  $rejected=in_array($mode,$invalid,true)||in_array($mode,['late-deny','late-step','late-unknown','late-reason','late-offline'],true);
  echo 'RISK_BOUNDARY '.json_encode(['backend'=>$backend,'mode'=>$mode,'status'=>$result===null?null:$result->status(),'error'=>$error===null?null:get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():null,'risk_calls'=>$riskCalls,'rotation_committed'=>$store->committed!==null]).PHP_EOL;
  if($rejected){
   Check::same(true,$error instanceof SecurityException);Check::same(in_array($mode,['offline','late-offline'],true)?'auth.device_risk_unavailable':'auth.device_risk_denied',$error->reason());Check::same(null,$result);Check::same(null,$error->getPrevious());Check::same(false,strpos((string)$error,'PRIVATE-RISK-CACHE-MARKER')!==false);
   if(strpos($mode,'late-')===0){Check::same(true,$store->committed!==null);Check::same(false,$before===$store->values[$key]);Check::same(1,$store->values[$key]['remember'][$grant->id()]['generation']);}
   else{Check::same(null,$store->committed);Check::same($before,$store->values[$key]);}
  }else{
   Check::same(null,$error);Check::same(in_array($mode,['allow','cached-allow'],true)?'authenticated':($mode==='deny'?'blocked':($mode==='step'?'step_up':'invalid')),$result->status());
   if(in_array($mode,['allow','cached-allow'],true)){Check::same(true,$sessions->verify('tenant','subject',$result->session()->token())!==null);}
  }
  Check::same(strpos($mode,'late-')===0||in_array($mode,['allow','cached-allow'],true)?2:1,$riskCalls);
 }
}finally{if($pdo!==null&&$createdTable){$pdo->exec('DROP TABLE sosecurity_state');}$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS remembered risk boundary '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
