<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
$c=json_decode(stream_get_contents(STDIN),true);$directory=$c['directory']??null;
if(!is_string($directory)||strpos($directory,'/tmp/sosecurity-')!==0||!is_dir($directory)||is_link($directory)||!is_file($directory.'/api-key-worker-owner')){throw new RuntimeException('Owned API key test directory required.');}$mysql=$c['mysql']===true;
if($mysql){$socket=$c['socket'];if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
elseif(!is_file($directory.'/state.sqlite')){throw new RuntimeException('Owned SQLite source required.');}
$pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/state.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$clock=new TestClock();$store=new SoSecurity\Storage\FileStore($directory.'/files','api-state:shared',$clock);
$sql=new A\SqlStateSnapshot($pdo,'api-owned-permissions',['api_owned_permissions'=>['columns'=>['id'=>'int','enabled'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>1]],30000);$files=new A\FileStateSnapshot($pdo,'api-owned-files',$directory.'/files',$directory.'/scratch',2,30000);$source=new A\CompositeStateSnapshot($pdo,['permissions'=>$sql,'files'=>$files],30000);
$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('w',32)]);$witness=new A\LocalStateWitness($pdo,$directory.'/witness','api-state','tenant',str_repeat('e',64),$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$boundary=new A\StateBoundary($witness,static function():bool{return true;});
$state=new A\StateApiKeyConnection($boundary,$witness,$source,$files,'files',$store,'api-state','tenant',str_repeat('e',64),$clock,static function(string $action,string $scope,string $subject)use($pdo){return $scope==='tenant'&&$subject==='client'&&(int)$pdo->query('SELECT enabled FROM api_owned_permissions WHERE id=1')->fetchColumn()===1?'operator':null;});
$api=SoSecurity\Security::fromArray(['site'=>'api-state'],[],$clock)->apiKeys($state);
try{$credential=$api->issue('client',['read'],10);echo json_encode(['issued'=>true]),PHP_EOL;}
catch(SoSecurity\Exception\SecurityException $error){if($error->reason()!=='api.capacity'){throw $error;}echo json_encode(['issued'=>false,'reason'=>'api.capacity']),PHP_EOL;}
