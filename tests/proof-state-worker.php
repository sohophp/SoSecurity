<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
$v=json_decode(stream_get_contents(STDIN),true);$directory=$v['directory'];
if(!is_string($directory)||strpos($directory,sys_get_temp_dir().'/sosecurity-test-')!==0||!is_file($directory.'/proof-worker-owner')){throw new RuntimeException('Owned proof worker required.');}
$pdo=new PDO('sqlite:'.$directory.'/state.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$clock=new TestClock();
$store=new SoSecurity\Storage\FileStore($directory.'/files','proof-state:tokens',$clock);
$sql=new A\SqlStateSnapshot($pdo,'proof-owned-permissions',['proof_owned_permissions'=>['columns'=>['id'=>'int','enabled'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>1]],30000);
$files=new A\FileStateSnapshot($pdo,'proof-owned-files',$directory.'/files',$directory.'/scratch',2,30000);$source=new A\CompositeStateSnapshot($pdo,['permissions'=>$sql,'files'=>$files],30000);
$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('w',32)]);$witness=new A\LocalStateWitness($pdo,$directory.'/witness','proof-state','tenant',str_repeat('e',64),$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$boundary=new A\StateBoundary($witness,static function():bool{return true;});
$state=new A\StateProofConnection($boundary,$witness,$source,$files,'files',$store,'proof-state','tenant',str_repeat('e',64),$clock,static function(string $action,string $authorityScope,string $scope,string $binding)use($pdo){return $authorityScope==='tenant'&&$scope==='form'&&$binding==='browser'&&(int)$pdo->query('SELECT enabled FROM proof_owned_permissions WHERE id=1')->fetchColumn()===1?'actual-browser':null;});
echo (new SoSecurity\Csrf\CsrfTokens($store,7200,16,$clock,$state))->verify('form','browser',$v['token'],true)?'1':'0';
