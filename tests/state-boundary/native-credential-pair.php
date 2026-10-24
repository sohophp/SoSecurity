<?php
declare(strict_types=1);
final class NativeCredentialReadStatement extends PDOStatement
{
 public static $reads=0;
 protected function __construct(){}
 public function execute($params=null):bool{++self::$reads;return $params===null?parent::execute():parent::execute($params);}
}
$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[NativeCredentialReadStatement::class,[]]);
$shape=static function(?array $v):?array{return $v===null?null:['account'=>$v['account']->fingerprint(),'fingerprint'=>$v['fingerprint'],'session'=>$v['session']===null?null:$v['session']->id()];};
$before=$witness->inspect(static function():bool{return true;});
$boundary->run('owned.credentials.pair',static function():void{throw new RuntimeException('Read-only check executed effects');},static function(string $expected)use($policy,$token,$shape):bool{
 NativeCredentialReadStatement::$reads=0;$actor=$policy->credentialView('tenant','fresh-user',$token,$expected);$target=$policy->credentialView('tenant','audit-owner',null,$expected);$separate=NativeCredentialReadStatement::$reads;
 NativeCredentialReadStatement::$reads=0;
 $pair=$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);$combined=NativeCredentialReadStatement::$reads;
 Check::same($shape($actor),$shape($pair['actor']));Check::same($shape($target),$shape($pair['target']));echo 'READ_COUNTS '.json_encode(['separate'=>$separate,'paired'=>$combined]).PHP_EOL;Check::same(true,$combined<$separate);
 $same=$policy->credentialPair('tenant','fresh-user',$token,'fresh-user',$expected);Check::same($shape($actor),$shape($same['actor']));Check::same($same['actor'],$same['target']);
 $missing=$policy->credentialPair('tenant','fresh-user',$token,'absent-account',$expected);Check::same($shape($actor),$shape($missing['actor']));Check::same(null,$missing['target']);
 $invalid=$policy->credentialPair('tenant','fresh-user','invalid','audit-owner',$expected);Check::same(null,$invalid['actor']);Check::same($shape($target),$shape($invalid['target']));
 $reverse=$policy->credentialPair('tenant','audit-owner',null,'fresh-user',$expected);Check::same($shape($target),$shape($reverse['actor']));Check::same($actor['fingerprint'],$reverse['target']['fingerprint']);Check::same(null,$reverse['target']['session']);
 Check::throws(SoSecurity\Storage\StorageException::class,static function()use($policy,$token):void{$policy->credentialPair('tenant','fresh-user',$token,'audit-owner',str_repeat('0',64));});
 Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($policy,$token,$expected):void{$policy->credentialPair('wrong-scope','fresh-user',$token,'audit-owner',$expected);});
 return false;
});
Check::same($before,$witness->inspect(static function():bool{return true;}));echo 'PASS native credential pair '.Check::$assertions.PHP_EOL;

// A stricter registry configuration must also bound the captured proof's advertised lifetime.
$ownedDependencies=new ReflectionProperty($policy,'dependencies');if(PHP_VERSION_ID<80100){$ownedDependencies->setAccessible(true);}
$ownedProfile=($ownedDependencies->getValue($policy))();
$shortRegistry=new SoSecurity\Auth\SessionRegistry($store,$provider,$sdk->managedSecondFactor(),$clock,60,60,16,$boundary);
$shortPolicy=new SoSecurity\Account\StateAccountPolicy($witness,$source,$sql,$files,'sql','files','account_example',array_combine($authColumns,$authColumns),$store,$shortRegistry,$sdk->managedSecondFactor(),$ownedProfile[9],'fresh-site','tenant',$epoch,$keys);
$boundary->run('owned.credentials.short-lifetime',static function():void{throw new RuntimeException('Read-only lifetime check executed effects');},static function(string $expected)use($shortPolicy,$token):bool{
 $view=$shortPolicy->credentialView('tenant','fresh-user',$token,$expected);Check::same(true,$view!==null&&$view['session']!==null);
 $session=$view['session'];Check::same($session->createdAt()+60,$session->expiresAt());return false;
});
$clock->time+=59;
$boundary->run('owned.credentials.short-lifetime-edge',static function():void{throw new RuntimeException('Read-only lifetime check executed effects');},static function(string $expected)use($shortPolicy,$token):bool{
 $pair=$shortPolicy->credentialPair('tenant','fresh-user',$token,'fresh-user',$expected);
 Check::same(true,$pair['actor']!==null);Check::same($pair['actor'],$pair['target']);
 Check::same($pair['actor']['session']->createdAt()+60,$pair['actor']['session']->expiresAt());return false;
});
++$clock->time;
$boundary->run('owned.credentials.short-lifetime-expired',static function():void{throw new RuntimeException('Read-only lifetime check executed effects');},static function(string $expected)use($shortPolicy,$token):bool{
 Check::same(null,$shortPolicy->credentialView('tenant','fresh-user',$token,$expected));return false;
});
echo 'PASS captured session current absolute lifetime'.PHP_EOL;
