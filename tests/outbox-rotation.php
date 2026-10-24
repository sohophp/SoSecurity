<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Storage\StorageException;
$mysql=($argv[1]??'')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)!==1||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required');}}
function rotationRows(OutboxEnvironment $e):array{$rows=$e->rows();foreach($rows as &$row){unset($row['seal_key'],$row['seal']);}unset($row);return $rows;}
foreach(['normal','request','before','commit','cleanup','throw'] as $mode){outboxCase($mysql,static function(OutboxEnvironment $e)use($mode):void{
 $old=$e->service();$old->initialize('tenant','orders','admin');$m=$e->message();$e->append($old,$m);$e->append($old,$e->message('event-2','second','order-2'));
 $e->clock->time+=$e->policy->messageAge()+1;$before=rotationRows($e);$raw=$e->rows();$allowed=true;$committed=false;$phases=[];
 $guard=static function(string &$action,string &$phase,string &$scope,string &$producer,string &$actor,array &$metadata)use($mode,&$allowed,&$phases):bool{$phases[]=$phase;$result=$allowed&&!(($mode==='request'&&$phase==='request')||($mode==='before'&&$phase==='commit'));if($mode==='throw'&&$phase==='return'){throw new RuntimeException('private-rotation-authority');}$action='mutated';$phase='mutated';$scope='mutated';$producer='mutated';$actor='mutated';$metadata=[];return $result;};
 $new=new HmacKeys('new',['old'=>str_repeat('o',32),'new'=>str_repeat('n',32)]);
 $rotator=new SqlOutbox($e->pdo,'outbox-test',$e->epoch,$new,static function():bool{return true;},$e->policy,$e->clock,$guard);
 $e->pdo->afterCommit=static function()use($mode,&$committed,&$allowed):void{$committed=true;if($mode==='commit'){$allowed=false;}};
 $e->pdo->afterExec=static function(string $sql)use($mode,&$committed,&$allowed):void{if($mode==='cleanup'&&$committed&&(strpos($sql,'PRAGMA busy_timeout=')===0||strpos($sql,'SET SESSION innodb_lock_wait_timeout=')===0)){$allowed=false;}};
 if($mode==='normal'){
  $page=$rotator->rotate('tenant','orders','admin',1);Check::same(1,$page['scanned']);Check::same(1,$page['rekeyed']);Check::same(false,$page['complete']);Check::same($before,rotationRows($e));
  $retired=new SqlOutbox($e->pdo,'outbox-test',$e->epoch,new HmacKeys('new',['new'=>str_repeat('n',32)]),static function():bool{return true;},$e->policy,$e->clock,static function():bool{return true;});
  Check::throws(StorageException::class,static function()use($retired){$retired->rotate('tenant','orders','admin');});
  $next=$rotator->rotate('tenant','orders','admin',1,$page['next_cursor']);Check::same(1,$next['rekeyed']);Check::same(true,$rotator->rotate('tenant','orders','admin',1,$next['next_cursor'])['complete']);Check::same(0,$retired->rotate('tenant','orders','admin')['rekeyed']);Check::same($before,rotationRows($e));
  Check::same(['new'],array_values(array_unique(array_column($e->rows(),'seal_key'))));Check::same(0,$e->business(true));
 }elseif($mode==='before'){Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($rotator){$rotator->rotate('tenant','orders','admin');});Check::same(false,$committed);Check::same($raw,$e->rows());}
 elseif($mode==='request'){Check::same(null,$rotator->rotate('tenant','orders','admin'));Check::same(false,$committed);Check::same($raw,$e->rows());}
 else{try{$rotator->rotate('tenant','orders','admin');throw new RuntimeException('Late rotation authority loss accepted');}catch(StorageException $error){Check::same('outbox.completion_unknown',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}Check::same(true,$committed);Check::same($before,rotationRows($e));Check::same(['new'],array_values(array_unique(array_column($e->rows(),'seal_key'))));}
 $e->pdo->afterCommit=null;$e->pdo->afterExec=null;
});}
echo 'PASS independent outbox rotation: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
