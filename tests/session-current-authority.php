<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
final class CurrentAuthorityStore implements SoSecurity\Storage\AtomicStore {
 private $inner;public $after;
 public function __construct(SoSecurity\Storage\AtomicStore $inner){$this->inner=$inner;}
 public function transact(string $key,callable $callback){$result=$this->inner->transact($key,$callback);if($this->after!==null){$work=$this->after;$this->after=null;$work();}return $result;}
}
final class CurrentAuthorityFactor implements SoSecurity\Auth\SecondFactor {
 public $binding='bound-1';
 public function binding(string $scope,string $subject):?string{return $this->binding;}
 public function verify(string $scope,string $subject,string $expectedBinding,$proof):?string{throw new RuntimeException('No proof verification in this test');}
}
$mysql=($argv[1]??'')==='mysql';$pdo=null;
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}$pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$pdo->exec(SoSecurity\Storage\MySqlStore::schema());}
$directory=privateDirectory();$cases=0;
try{foreach($mysql?['mysql']:['memory','file'] as $backend){foreach(['normal','disabled','missing','version','role','mfa','factor','factor-missing','expired','backwards','identity-expiry','idle','identity-idle'] as $mode){
 $clock=new TestClock();$factor=new CurrentAuthorityFactor();$account=new SoSecurity\Auth\Account('tenant','subject','1',true,['operator']);$onFind=null;
 $find=static function()use(&$account,&$onFind){if($onFind!==null){$work=$onFind;$onFind=null;$work();}return $account;};
 $provider=new SoSecurity\Auth\CallbackIdentityProvider($find,$find);$inner=$backend==='memory'?new SoSecurity\Storage\MemoryStore($clock):new SoSecurity\Storage\FileStore($directory,'current-'.$mode,$clock);if($mysql){$inner=new SoSecurity\Storage\MySqlStore($pdo,'current-'.$mode,$clock);}$store=new CurrentAuthorityStore($inner);
 $registry=new SoSecurity\Auth\SessionRegistry($store,$provider,$factor,$clock,100,500);
 $identity=(new SoSecurity\Auth\IdentityState($provider,$factor))->load('tenant','subject');$epoch=$registry->epoch('tenant','subject');$issued=$registry->register('tenant','subject',$identity['fingerprint'],$epoch,'totp');Check::same(true,$issued!==null);Check::same(true,$registry->verify('tenant','subject',$issued->token())!==null);
 $store->after=static function()use($mode,&$account,$clock,$factor,&$onFind):void{
  if($mode==='disabled'){$account=new SoSecurity\Auth\Account('tenant','subject','1',false,['operator']);}
  elseif($mode==='missing'){$account=null;}
  elseif($mode==='version'){$account=new SoSecurity\Auth\Account('tenant','subject','2',true,['operator']);}
  elseif($mode==='role'){$account=new SoSecurity\Auth\Account('tenant','subject','1',true,['reader']);}
  elseif($mode==='mfa'){$account=new SoSecurity\Auth\Account('tenant','subject','1',true,['operator'],true);}
  elseif($mode==='factor'){$factor->binding='bound-2';}
  elseif($mode==='factor-missing'){$factor->binding=null;}
  elseif($mode==='expired'){$clock->time+=501;}
  elseif($mode==='backwards'){--$clock->time;}
  elseif($mode==='idle'){$clock->time+=101;}
  elseif($mode==='identity-idle'){$onFind=static function()use($clock):void{$clock->time+=101;};}
  elseif($mode==='identity-expiry'){$onFind=static function()use($clock):void{$clock->time+=501;};}
 };
 $result=$registry->verify('tenant','subject',$issued->token());Check::same($mode==='normal',$result!==null);++$cases;
}}
 echo 'PASS session current authority '.$cases.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}finally{if($pdo!==null){$pdo->exec('DROP TABLE sosecurity_state');}cleanDirectory($directory);}
