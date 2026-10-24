<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SoSecurity\Account\CompositeStateSnapshot;
use SoSecurity\Account\FenceStateSnapshot;
use SoSecurity\Account\LocalEpochFence;
use SoSecurity\Account\LocalStatePersistence;
use SoSecurity\Account\LocalStateWitness;
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Account\StateBoundary;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;
$directory=privateDirectory();
try{
    foreach(['witness','fence'] as $name){mkdir($directory.'/'.$name,0700);}
    $pdo=new PDO('sqlite:'.$directory.'/fresh.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');
    $pdo->exec('CREATE TABLE fresh_business(id INTEGER NOT NULL PRIMARY KEY, value TEXT NOT NULL)');
    $sql=new SqlStateSnapshot($pdo,'fresh-empty-sql',['fresh_business'=>['columns'=>['id'=>'int','value'=>'bytes:64'],'primary'=>['id'],'where'=>[],'maximum_rows'=>10]],10000);
    $fences=new FenceStateSnapshot($pdo,'fresh-empty-fence',$directory.'/fence',2,10000);
    $source=new CompositeStateSnapshot($pdo,['sql'=>$sql,'fences'=>$fences],10000);
    $keys=new HmacKeys('fresh',['fresh'=>str_repeat('f',32)]);
    $witness=new LocalStateWitness($pdo,$directory.'/witness','fresh-site','fresh-scope',str_repeat('e',64),$keys,$source,new LocalStatePersistence($directory.'/witness',10000),10000,2);
    Check::same([],glob($directory.'/fence/*.fence'));
    $witness->initialize($source->digest());
    $boundary=new StateBoundary($witness,static function():bool{return true;});
    $fence=new LocalEpochFence($directory.'/fence','fresh-site','fresh-scope',str_repeat('e',64),$keys,new LocalStatePersistence($directory.'/fence',10000),10000,$boundary);
    Check::same(true,$fence->boundToStateBoundary($boundary));
    Check::throws(StorageException::class,static function()use($fence):void{$fence->initialize();});
    Check::same([],glob($directory.'/fence/*.fence'));
    $boundary->run('fresh.provision',static function()use($fence):void{$fence->initialize();});
    Check::same(1,count(glob($directory.'/fence/*.fence')));
    $state=$witness->inspect(static function():bool{return true;});Check::same('current',$state['status']);Check::same($source->digest(),$state['digest']);
    $calls=0;
    Check::throws(StorageException::class,static function()use($fence,&$calls):void{$fence->work(static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);
    Check::same('owned-result',$boundary->run('fresh.work',static function()use($fence,$pdo,&$calls):string{return $fence->work(static function()use($pdo,&$calls):string{++$calls;$pdo->exec("INSERT INTO fresh_business VALUES(1,'owned')");return 'owned-result';});}));
    Check::same(1,$calls);Check::same('owned',$pdo->query('SELECT value FROM fresh_business WHERE id=1')->fetchColumn());
    $state=$witness->inspect(static function():bool{return true;});Check::same('current',$state['status']);Check::same($source->digest(),$state['digest']);
    echo 'PASS fresh first-provision boundary: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; empty authority only, no predecessor, no rotation, no account recovery'.PHP_EOL;
}finally{foreach(['witness','fence'] as $name){if(is_dir($directory.'/'.$name)){cleanDirectory($directory.'/'.$name);}}cleanDirectory($directory);}
