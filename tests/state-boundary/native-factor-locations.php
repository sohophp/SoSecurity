<?php
declare(strict_types=1);
final class FactorLocationReadStatement extends PDOStatement
{
 public static $reads=0;
 protected function __construct(){}
 public function execute($params=null):bool{++self::$reads;return $params===null?parent::execute():parent::execute($params);}
}
Check::same(true,SoSecurity\Support\SqlStateAccess::pureEntryGuard($pdo));
$wrongGuard=static function():void{};
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$wrongGuard,$boundary):void{SoSecurity\Support\SqlStateAccess::bind($pdo,hash('sha256','owned-wrong-context'),hash('sha256','owned-wrong-binding'),$wrongGuard,$boundary);});
$outside=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$outside,$boundary):void{SoSecurity\Support\SqlStateAccess::bind($outside,hash('sha256','owned-outside-context'),hash('sha256','owned-outside-binding'),$boundary->sqlGuard($pdo),$boundary);});
Check::same(false,SoSecurity\Support\SqlStateAccess::isProtected($outside));unset($outside);
Check::throws(SoSecurity\Storage\StorageException::class,static function()use($pdo):void{SoSecurity\Support\SqlStateAccess::assertActive($pdo);});
$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[FactorLocationReadStatement::class,[]]);
$policy=$sdk->stateAccountPolicy($witness,$source,$sql,$files,'sql','files','account_example',array_combine($authColumns,$authColumns));
$shape=static function(?array $v):?array{return $v===null?null:['account'=>$v['account']->fingerprint(),'fingerprint'=>$v['fingerprint'],'session'=>$v['session']===null?null:$v['session']->id()];};
$before=$witness->inspect(static function():bool{return true;});
$boundary->run('owned.factor.locations',static function():void{throw new RuntimeException('Read-only location check executed effects');},static function(string $expected)use($policy,$token,$shape):bool{
 FactorLocationReadStatement::$reads=0;$cold=$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);$coldReads=FactorLocationReadStatement::$reads;
 FactorLocationReadStatement::$reads=0;$warm=$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);$warmReads=FactorLocationReadStatement::$reads;
 Check::same($shape($cold['actor']),$shape($warm['actor']));Check::same($shape($cold['target']),$shape($warm['target']));
 echo 'FACTOR_LOCATION_READS '.json_encode(['cold'=>$coldReads,'warm'=>$warmReads]).PHP_EOL;
 Check::same($coldReads,2*$warmReads);Check::same(true,$cold['actor']!==null);Check::same(true,$cold['target']!==null);
 $reverse=$policy->credentialPair('tenant','audit-owner',null,'fresh-user',$expected);Check::same($cold['actor']['fingerprint'],$reverse['target']['fingerprint']);Check::same(null,$reverse['target']['session']);
 $same=$policy->credentialPair('tenant','fresh-user',$token,'fresh-user',$expected);Check::same($shape($cold['actor']),$shape($same['actor']));Check::same($same['actor'],$same['target']);
 $invalid=$policy->credentialPair('tenant','fresh-user','invalid','audit-owner',$expected);Check::same(null,$invalid['actor']);Check::same($shape($cold['target']),$shape($invalid['target']));
 $missing=$policy->credentialPair('tenant','fresh-user',$token,'absent-account',$expected);Check::same(null,$missing['target']);Check::same($shape($cold['actor']),$shape($missing['actor']));
 Check::throws(SoSecurity\Storage\StorageException::class,static function()use($policy,$token):void{$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',str_repeat('0',64));});
 // Fault injection changes only an obsolete position, never an authoritative capture.
 $positions=new ReflectionProperty($policy,'factorFiles');if(PHP_VERSION_ID<80100){$positions->setAccessible(true);}$old=$positions->getValue($policy);Check::same(1,count($old));
 $positions->setValue($policy,[hash('sha256','fresh-user')=>str_repeat('0',64).'.json']);
 FactorLocationReadStatement::$reads=0;$stale=$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);$staleReads=FactorLocationReadStatement::$reads;
 Check::same($shape($cold['actor']),$shape($stale['actor']));Check::same($shape($cold['target']),$shape($stale['target']));Check::same($coldReads,$staleReads);Check::same($old,$positions->getValue($policy));
 $seed=[];for($i=0;$i<16;++$i){$seed[hash('sha256','position-budget-'.$i)]=str_repeat('0',64).'.json';}$positions->setValue($policy,$seed);
 $bounded=$policy->credentialView('tenant','fresh-user',$token,$expected);Check::same($shape($cold['actor']),$shape($bounded));Check::same(16,count($positions->getValue($policy)));Check::same(true,isset($positions->getValue($policy)[hash('sha256','fresh-user')]));
 $positions->setValue($policy,$old);
 return false;
});
Check::same($before,$witness->inspect(static function():bool{return true;}));
$observe=static function(callable $read)use($boundary){$value=null;$boundary->run('owned.factor.locations.read',static function():void{throw new RuntimeException('Read-only check executed effects');},static function(string $expected)use($read,&$value):bool{$value=$read($expected);return false;});return $value;};
// Initial enrollment for a second, independently created account exercises all four file selections.
$ownerWorker=$raw->managedRegistered('fresh-site','tenant',$epoch,$keys,$fence,new SoSecurity\Account\FactorWorkerAuthority($pdo,'fresh-site','tenant',$epoch,$keys,$fence,static function(string $action,string $phase,string $scope,string $subject):bool{return $scope==='tenant'&&$subject==='audit-owner'&&in_array($action,['begin','confirm'],true);},new SoSecurity\Account\Policy(),$clock));
$boundary->run('owned.factor.locations.owner.enrollment',static function()use($ownerWorker,$registry,$clock):void{
 $enrollment=$ownerWorker->begin('tenant','audit-owner','Owned second operator');parse_str(parse_url($enrollment->provisioningUri(),PHP_URL_QUERY),$params);
 Check::same(10,count($ownerWorker->confirm('tenant','audit-owner',$enrollment->id(),(new SoSecurity\Mfa\Totp())->codeAt($params['secret'],$clock->time))));Check::same(true,$registry->adopt('audit-owner'));
});
$observe(static function(string $expected)use($policy,$token,$shape):void{
 FactorLocationReadStatement::$reads=0;$first=$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);$firstReads=FactorLocationReadStatement::$reads;
 FactorLocationReadStatement::$reads=0;$next=$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);$nextReads=FactorLocationReadStatement::$reads;
 Check::same(true,$next['target']['account']->mfaRequired());Check::same($shape($first['actor']),$shape($next['actor']));Check::same($shape($first['target']),$shape($next['target']));Check::same($firstReads,2*$nextReads);
 echo 'TWO_FACTOR_LOCATION_READS '.json_encode(['discovery'=>$firstReads,'warm'=>$nextReads]).PHP_EOL;
});
$current=$observe(static function(string $expected)use($policy,$token):?array{return $policy->credentialView('tenant','fresh-user',$token,$expected);});
$clock->time=$current['session']->expiresAt()+1;
Check::same(null,$observe(static function(string $expected)use($policy,$token):?array{return $policy->credentialView('tenant','fresh-user',$token,$expected);}));
Check::same($current['fingerprint'],$observe(static function(string $expected)use($policy):?array{return $policy->credentialView('tenant','fresh-user',null,$expected);})['fingerprint']);
$boundary->run('owned.factor.locations.roles',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);});
$changed=$observe(static function(string $expected)use($policy):?array{return $policy->credentialView('tenant','fresh-user',null,$expected);});Check::same([],$changed['account']->roles());Check::same(false,hash_equals($current['fingerprint'],$changed['fingerprint']));
$boundary->run('owned.factor.locations.corrupt',static function()use($store):void{$store->transact(SoSecurity\Support\Guard::key('mfa-totp','tenant','fresh-user'),static function($frame):SoSecurity\Storage\Change{$frame['seal']=str_repeat('0',64);return new SoSecurity\Storage\Change($frame,0,null);});});
try{$observe(static function(string $expected)use($policy):?array{return $policy->credentialView('tenant','fresh-user',null,$expected);});throw new RuntimeException('Old factor bytes reused');}catch(SoSecurity\Storage\StorageException $error){Check::same('mfa.managed_corrupt',$error->reason());}
$boundary->run('owned.factor.locations.disable',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET status=? WHERE subject=?')->execute(['disabled','fresh-user']);});
Check::same(null,$observe(static function(string $expected)use($policy):?array{return $policy->credentialView('tenant','fresh-user',null,$expected);}));
echo 'PASS native factor file selections '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
