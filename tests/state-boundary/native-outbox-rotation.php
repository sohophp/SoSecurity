<?php
declare(strict_types=1);
use SoSecurity\Account as A;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Outbox\Message;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
$queuePolicy=new SoSecurity\Outbox\Policy();
$oldQueue=new SqlOutbox($pdo,'fresh-site',$epoch,$keys,static function():bool{return true;},$queuePolicy,$clock,static function():bool{return true;});
$boundary->run('fresh.rotation.seed',static function()use($oldQueue,$pdo,$clock):void{
 foreach(['native-rotation','foreign'] as $producer){$oldQueue->initialize('tenant',$producer,'admin');}
 $pdo->beginTransaction();try{foreach(['one','two','foreign'] as $name){$producer=$name==='foreign'?'foreign':'native-rotation';$oldQueue->enqueue(new Message('tenant',$producer,Message::identifier('owned-'.$name,$clock->time),'owned','event',$name,'owned-body-'.$name),'admin');}$pdo->commit();}catch(Throwable $error){if($pdo->inTransaction()){$pdo->rollBack();}throw $error;}
});
$rotationKeys=new SoSecurity\Support\HmacKeys('rotation',['fresh'=>str_repeat('k',32),'rotation'=>str_repeat('r',32)]);
$queueGuard=static function(string &$action,string &$phase,string &$scope)use($manager):bool{$completion=$phase==='return'?'complete':$phase;return $manager($action,$completion,$scope);};
$queueConfig=$config;$queueConfig['outbox']=['connection'=>'db','epoch'=>$epoch,'integrity_keys'=>'rotation_keys','authority'=>'rotation_allow','management_guard'=>'rotation_manage'];
$queueServices=$services+['rotation_keys'=>$rotationKeys,'rotation_allow'=>static function():bool{return true;},'rotation_manage'=>$queueGuard];
$queue=SoSecurity\Security::fromArray($queueConfig,$queueServices,$clock)->outbox($accountConnection);
$getPermission=static function(int $limit=1,string $after='')use($queue,&$token):A\StatePermission{return new A\StatePermission('outbox.rotate','tenant','fresh-user',$queue->rotationTarget('tenant','native-rotation','admin',$limit,$after),$token,['maintainer'],1,300,true,false,['password']);};
$permission=$getPermission();$before=$witness->inspect(static function():bool{return true;});
Check::same(null,$queue->rotateFor($policy,$permission,'tenant','native-rotation','admin',1));Check::same($before,$witness->inspect(static function():bool{return true;}));
Check::throws(StorageException::class,static function()use($oldQueue):void{$oldQueue->rotate('tenant','native-rotation','admin');});
$boundary->run('fresh.rotation.roles',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=?')->execute(['["maintainer"]']);});
$clock->time+=$queuePolicy->messageAge()+1;
$login=$auth->password('tenant','fresh-rotation-browser','fresh@example.test',$password);Check::same('authenticated',$login->status());$token=$login->credential()->token();$permission=$getPermission();
$before=$witness->inspect(static function():bool{return true;});$managementAllowed=false;Check::same(null,$queue->rotateFor($policy,$permission,'tenant','native-rotation','admin',1));Check::same($before,$witness->inspect(static function():bool{return true;}));$managementAllowed=true;
foreach([['tenant','foreign','admin',1],['tenant','native-rotation','other',1],['tenant','native-rotation','admin',2]] as $args){Check::throws(ConfigurationException::class,static function()use($queue,$policy,$permission,$args){$queue->rotateFor($policy,$permission,...$args);});Check::same($before,$witness->inspect(static function():bool{return true;}));}
$oldNative=new SqlOutbox($pdo,'fresh-site',$epoch,$keys,static function():bool{return true;},$queuePolicy,$clock,$queueGuard,$accountConnection);
Check::throws(ConfigurationException::class,static function()use($oldNative,$policy,$permission){$oldNative->rotateFor($policy,$permission,'tenant','native-rotation','admin',1);});Check::same($before,$witness->inspect(static function():bool{return true;}));
$rows=static function()use($pdo):array{$rows=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC);foreach($rows as &$row){unset($row['seal_key'],$row['seal']);}unset($row);return $rows;};$original=$rows();$accountsBefore=$pdo->query('SELECT * FROM account_example ORDER BY scope,subject')->fetchAll(PDO::FETCH_ASSOC);
$nested=static function()use($queue,$policy,$permission):void{Check::throws(ConfigurationException::class,static function()use($queue,$policy,$permission){$queue->rotateFor($policy,$permission,'tenant','native-rotation','admin',1);});};
$page=$queue->rotateFor($policy,$permission,'tenant','native-rotation','admin',1);Check::same(null,$nested);Check::same(1,$page['rekeyed']);Check::same('outbox.rotate',$witness->inspect(static function():bool{return true;})['intent']['action']);Check::same($original,$rows());
$after=$page['next_cursor'];$page=$queue->rotateFor($policy,$getPermission(1,$after),'tenant','native-rotation','admin',1,$after);Check::same(1,$page['rekeyed']);Check::same($original,$rows());
Check::same($accountsBefore,$pdo->query('SELECT * FROM account_example ORDER BY scope,subject')->fetchAll(PDO::FETCH_ASSOC));
$raw=$pdo->query('SELECT payload_body,seal_key FROM sosecurity_outbox_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC);foreach($raw as $row){Check::same($row['payload_body']==='owned-body-foreign'?'fresh':'rotation',$row['seal_key']);}
$late=true;try{$queue->rotateFor($policy,$getPermission(),'tenant','native-rotation','admin',1);throw new RuntimeException('Late rotation role loss accepted');}catch(StorageException $error){Check::same('account.completion_unknown',$error->reason());}
Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);Check::same($original,$rows());
echo 'PASS native outbox rotation: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').'; no lease, delivery, retry or reconciliation'.PHP_EOL;
