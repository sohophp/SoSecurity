<?php
declare(strict_types=1);
final class CredentialColdStatement extends PDOStatement {
 public static $reads=0;
 protected function __construct(){}
 public function execute($params=null):bool{++self::$reads;return $params===null?parent::execute():parent::execute($params);}
}
$ownedClockNative=$clock instanceof SoSecurity\Support\SystemClock;$ownedOpaque=getenv('SOSECURITY_TEST_CREDENTIAL_OPAQUE')==='1';$ownedOptimized=$ownedClockNative&&!$ownedOpaque;
if(!$ownedOptimized){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[CredentialColdStatement::class,[]]);}
$ownedCount=$ownedOptimized?($mysql?static function()use($pdo):?int{$q=$pdo->query("SHOW SESSION STATUS LIKE 'Com_stmt_execute'");try{return (int)$q->fetchColumn(1);}finally{$q->closeCursor();}}:static function():?int{return null;}):static function():?int{return CredentialColdStatement::$reads;};
$measure=static function(callable $read)use($ownedCount):array{$start=$ownedCount();$value=$read();$end=$ownedCount();return [$value,$start===null?null:$end-$start];};
$checkReads=static function(?int $cold,?int $warm)use($ownedOptimized):void{if($cold===null){return;}if($ownedOptimized){Check::same($warm,$cold);}else{Check::same(true,$cold>$warm);}};

$fresh=$sdk->stateAccountPolicy($witness,$source,$sql,$files,'sql','files','account_example',array_combine($authColumns,$authColumns));
$shape=static function(array $p):array{$r=[];foreach($p as $k=>$v){$r[$k]=$v===null?null:[$v['account']->fingerprint(),$v['fingerprint'],$v['session']===null?null:$v['session']->id()];}return $r;};
$before=$witness->inspect(static function():bool{return true;});
$boundary->run('owned.credential.cold',static function():void{throw new RuntimeException('Read-only test executed effects');},static function(string $expected)use($fresh,$token,$shape,$measure,$checkReads,$ownedOptimized,$clock,$pdo):bool{
 [$cold,$coldReads]=$measure(static function()use($fresh,$token,$expected){return $fresh->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);});
 [$warm,$warmReads]=$measure(static function()use($fresh,$token,$expected){return $fresh->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);});
 Check::same($shape($cold),$shape($warm));Check::same(true,$cold['actor']!==null&&$cold['target']!==null);
 echo 'OBSERVATION credential cold '.json_encode(['cold'=>$coldReads,'warm'=>$warmReads,'native_inputs'=>$ownedOptimized,'clock'=>get_class($clock),'pdo'=>get_class($pdo),'policy_source'=>(new ReflectionClass($fresh))->getFileName(),'php'=>PHP_VERSION]).PHP_EOL;
 $checkReads($coldReads,$warmReads);return false;
});
$make=static function()use($sdk,$witness,$source,$sql,$files,$authColumns){return $sdk->stateAccountPolicy($witness,$source,$sql,$files,'sql','files','account_example',array_combine($authColumns,$authColumns));};
$inspectProperty=static function($object,string $name){$property=new ReflectionProperty($object,$name);if(PHP_VERSION_ID<80100){$property->setAccessible(true);}return $property;};
$profile=($inspectProperty($fresh,'dependencies')->getValue($fresh))();
$actorReference=$profile[9]->stateReference('tenant','fresh-user',$profile[17]);$otherReference=$profile[9]->stateReference('tenant','audit-owner',$profile[17]);
Check::same(true,is_array($actorReference)&&is_array($otherReference));
foreach(['same','reverse','missing','invalid-token','wrong-hint','orphan-hint','stale','scope'] as $ownedMode){
 $candidate=$make();
 if($ownedMode==='wrong-hint'){$inspectProperty($candidate,'factorFiles')->setValue($candidate,[hash('sha256','fresh-user')=>$otherReference['file']]);}
 if($ownedMode==='orphan-hint'){$inspectProperty($candidate,'factorFiles')->setValue($candidate,[hash('sha256','audit-owner')=>$actorReference['file']]);}
 $boundary->run('owned.credential.hint',static function():void{throw new RuntimeException('Read-only hint test executed effects');},static function(string $expected)use($candidate,$ownedMode,$token,$shape,$fresh,$inspectProperty,$measure,$checkReads):bool{
  $base=$fresh->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);CredentialColdStatement::$reads=0;
  if($ownedMode==='same'){[$a,$cold]=$measure(static function()use($candidate,$token,$expected){return $candidate->credentialPair('tenant','fresh-user',$token,'fresh-user',$expected);});[$b,$warm]=$measure(static function()use($candidate,$token,$expected){return $candidate->credentialPair('tenant','fresh-user',$token,'fresh-user',$expected);});$checkReads($cold,$warm);Check::same($shape($a),$shape($b));Check::same($a['actor'],$a['target']);}
  elseif($ownedMode==='reverse'){[$a,$cold]=$measure(static function()use($candidate,$expected){return $candidate->credentialPair('tenant','audit-owner',null,'fresh-user',$expected);});[$b,$warm]=$measure(static function()use($candidate,$expected){return $candidate->credentialPair('tenant','audit-owner',null,'fresh-user',$expected);});$checkReads($cold,$warm);Check::same($shape($a),$shape($b));Check::same($base['actor']['fingerprint'],$a['target']['fingerprint']);}
  elseif($ownedMode==='missing'){$a=$candidate->credentialPair('tenant','fresh-user',$token,'absent-account',$expected);Check::same(null,$a['target']);Check::same($base['actor']['fingerprint'],$a['actor']['fingerprint']);}
  elseif($ownedMode==='invalid-token'){$a=$candidate->credentialPair('tenant','fresh-user','invalid','audit-owner',$expected);Check::same(null,$a['actor']);Check::same($base['target']['fingerprint'],$a['target']['fingerprint']);Check::same(0,count($inspectProperty($candidate,'factorFiles')->getValue($candidate)));}
  elseif($ownedMode==='wrong-hint'){[$a,$cold]=$measure(static function()use($candidate,$token,$expected){return $candidate->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);});[$b,$warm]=$measure(static function()use($candidate,$token,$expected){return $candidate->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);});if($cold!==null){Check::same(true,$cold>$warm);}Check::same($shape($base),$shape($a));Check::same($shape($a),$shape($b));}
  elseif($ownedMode==='orphan-hint'){$a=$candidate->credentialPair('tenant','fresh-user',$token,'audit-owner',$expected);Check::same($shape($base),$shape($a));Check::same(false,$a['target']['account']->mfaRequired());Check::same(false,array_key_exists(hash('sha256','audit-owner'),$inspectProperty($candidate,'factorFiles')->getValue($candidate)));}
  elseif($ownedMode==='stale'){Check::throws(SoSecurity\Storage\StorageException::class,static function()use($candidate,$token):void{$candidate->credentialPair('tenant','fresh-user',$token,'audit-owner',str_repeat('0',64));});}
  else{Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($candidate,$token,$expected):void{$candidate->credentialPair('wrong-scope','fresh-user',$token,'audit-owner',$expected);});}
  echo 'PASS credential hint '.$ownedMode.' PHP '.PHP_VERSION.PHP_EOL;return false;
 });
}
Check::same($before,$witness->inspect(static function():bool{return true;}));echo 'PASS credential cold capture '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
