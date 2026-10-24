<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Authorization as A;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
$directory=privateDirectory();$pdo=null;
try{
 $pdo=new PDO('sqlite:'.$directory.'/policy.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-policy',['policy_table'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>1]]);
 $calls=0;$first=new class($calls) implements A\SnapshotEvaluator{
  private $calls;public function __construct(&$calls){$this->calls=&$calls;}
  public function selectors(SoSecurity\Auth\Account $actor,string $action,A\Resource $resource,array $requestedFields):array{return [];}
 public function decide(SoSecurity\Auth\Account $actor,string $action,A\Resource $resource,array $requestedFields,array $facts):?A\Decision{++$this->calls;return null;}
 };
 $second=new class implements A\SnapshotEvaluator{public function selectors(SoSecurity\Auth\Account $actor,string $action,A\Resource $resource,array $requestedFields):array{return [];}
 public function decide(SoSecurity\Auth\Account $actor,string $action,A\Resource $resource,array $requestedFields,array $facts):?A\Decision{return null;}};
 $profile=hash('sha256','equivalent-owned-policy-implementation-v1');$a=new A\SnapshotPolicy($first,$source,$profile);$b=new A\SnapshotPolicy($second,$source,$profile);
 // The explicit implementation/configuration digest must not acquire an anonymous class path or source line.
 Check::same($a->fingerprint(),$b->fingerprint());Check::same(0,$calls);
 Check::same(false,$a->fingerprint()===(new A\SnapshotPolicy($first,$source,hash('sha256','changed-profile')))->fingerprint());
 foreach(['',str_repeat('a',63),str_repeat('A',64)] as $invalid){Check::throws(ConfigurationException::class,static function()use($first,$source,$invalid):void{new A\SnapshotPolicy($first,$source,$invalid);});}
 Check::throws(\TypeError::class,static function()use($a,$source,$profile):void{new A\SnapshotPolicy($a,$source,$profile);});Check::throws(ConfigurationException::class,static function()use($a):void{serialize($a);});Check::throws(ConfigurationException::class,static function()use($a):void{$a->profile='replacement';});
 $actor=new SoSecurity\Auth\Account('tenant','owner','v1');$resource=new A\Resource('tenant','record','item','v1');Check::throws(ConfigurationException::class,static function()use($a,$actor,$resource):void{$a->decide($actor,'read',$resource);});Check::same(0,$calls);
}finally{$pdo=null;gc_collect_cycles();cleanDirectory($directory);}
echo 'PASS snapshot policy declaration '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
