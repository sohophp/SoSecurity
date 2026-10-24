<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';require __DIR__.'/idempotency-support.php';
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class QueuedCleanupStatement extends InboxTestStatement
{
 public static $component='';public static $stage='';public static $fault='';public static $counts=0;public static $closes=0;
 private function target():bool {
  if(!preg_match('/\A(INSERT INTO|UPDATE) (?:main\.)?sosecurity_(outbox|idempotency)_(roots|records)\b/',$this->queryString,$m)){return false;}
  return $m[2]===self::$component&&($m[3]==='roots'?'root':'record').($m[1]==='INSERT INTO'?'-insert':'-update')===self::$stage;
 }
 public function rowCount():int {
  if($this->target()){++self::$counts;if(in_array(self::$fault,['count-throw','combined'],true)){throw new RuntimeException('owned-private-queued-count');}if(self::$fault==='count-negative'){return -1;}}
  return parent::rowCount();
 }
 public function closeCursor():bool {
  if($this->target()){++self::$closes;if(in_array(self::$fault,['close-throw','combined'],true)){throw new RuntimeException('owned-private-queued-close');}if(self::$fault==='close-false'){return false;}}
  return parent::closeCursor();
 }
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use owned disposable SQL only.');}
$failures=[];$cases=0;$negative=0;$positive=0;
foreach(['outbox','idempotency'] as $component){foreach(['root-insert','record-insert','root-update','record-update'] as $stage){foreach(['close-false','close-throw','count-throw','count-negative','combined','none'] as $fault){
 $e=null;$label=$component.'/'.$stage.'/'.$fault;
 try{
  QueuedCleanupStatement::$stage='';$e=$component==='outbox'?new OutboxEnvironment($mysql):new IdempotencyEnvironment($mysql);
  $e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[QueuedCleanupStatement::class,[$e->pdo]]);$s=$e->service();
  if($stage!=='root-insert'){if($component==='outbox'){$s->initialize('tenant','orders','admin');if($stage==='record-update'){$e->append($s,$e->message());}}else{$s->initialize('tenant','alice','orders.create');}}
  $snapshot=static function()use($e,$component):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM sosecurity_'.$component.'_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$e->pdo->query('SELECT * FROM sosecurity_'.$component.'_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC),$component==='outbox'?$e->business():$e->count()]));};$before=$snapshot();
  QueuedCleanupStatement::$component=$component;QueuedCleanupStatement::$stage=$stage;QueuedCleanupStatement::$fault=$fault;QueuedCleanupStatement::$counts=0;QueuedCleanupStatement::$closes=0;$caught=null;$result=null;
  try{
   if($stage==='root-insert'){$result=$component==='outbox'?$s->initialize('tenant','orders','admin'):$s->initialize('tenant','alice','orders.create');}
   elseif($component==='idempotency'){$result=$s->execute($e->request(),$e->handler());}
   elseif($stage==='record-update'){$result=$s->claimInitialMessage('tenant','orders','worker',$e->message()->id());}
   else{
    $e->pdo->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
    try{$e->pdo->exec('INSERT INTO outbox_test_business VALUES(1)');$result=$s->enqueue($e->message(),'alice');$e->pdo->exec('COMMIT');}catch(Throwable $error){$e->pdo->exec('ROLLBACK');throw $error;}
   }
  }catch(SecurityException $error){$caught=$error;}
  QueuedCleanupStatement::$stage='';
  if($fault==='none'){
   Check::same(null,$caught);Check::same(true,$result!==null&&$result!==false);Check::same(false,$before===$snapshot());
   Check::same($stage==='root-insert'?0:1,count($component==='outbox'?$e->rows():$e->records()));
   Check::same($component==='idempotency'&&$stage!=='root-insert'?1:($component==='outbox'&&in_array($stage,['record-insert','root-update'],true)?1:0),$component==='outbox'?$e->business():$e->count());++$positive;
  }else{
   Check::same(true,$caught instanceof SecurityException);Check::same(null,$result);Check::same(false,strpos((string)$caught,'owned-private-queued-')!==false);$chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
   Check::same($before,$snapshot());Check::same(1,QueuedCleanupStatement::$counts);Check::same(1,QueuedCleanupStatement::$closes);
   $property=new ReflectionProperty($s,'unit');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}$unit=$property->getValue($s);
   try{$unit->query('SELECT 1');throw new RuntimeException('Uncertain SQL unit reused');}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}++$negative;
  }
  Check::same(false,$e->pdo->inTransaction());++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$label,'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','class'=>get_class($error),'duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{QueuedCleanupStatement::$stage='';if($e!==null){$e->close();}}
}}}
echo json_encode(['cases'=>$cases,'negative'=>$negative,'positive'=>$positive,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;
if($failures){throw new RuntimeException('Queued write cleanup failures retained.');}
echo 'PASS queued write cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
