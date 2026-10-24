<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';require __DIR__.'/idempotency-support.php';
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class QueuedPageCleanupStatement extends InboxTestStatement {
 public static $armed=false;public static $fault='';public static $hits=0;
 public function closeCursor():bool {if(self::$armed&&strpos($this->queryString,'SELECT ')===0&&strpos($this->queryString,':after_')!==false){++self::$hits;if(self::$fault==='throw'){throw new RuntimeException('owned-private-queued-page');}return false;}return parent::closeCursor();}
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use owned disposable SQL only.');}
$cases=0;$faultCases=0;$normalCases=0;$failures=[];
foreach(['candidates','maintain','rotate','idempotency'] as $action){foreach(['empty','populated'] as $population){foreach(['false','throw'] as $fault){$e=null;
 try{
  $idem=$action==='idempotency';$component=$idem?'idempotency':'outbox';$e=$idem?new IdempotencyEnvironment($mysql):new OutboxEnvironment($mysql);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[QueuedPageCleanupStatement::class,[$e->pdo]]);$s=$e->service();
  if($idem){$s->initialize('tenant','alice','orders.create');if($population==='populated'){$s->execute($e->request(),$e->handler());}}else{$s->initialize('tenant','orders','admin');if($population==='populated'){$e->append($s,$e->message());}}
  $snapshot=static function()use($e,$component,$idem):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM sosecurity_'.$component.'_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$idem?$e->records():$e->rows(),$idem?$e->count():$e->business()]));};$before=$snapshot();$calls=$idem?$e->handlerCalls:0;
  QueuedPageCleanupStatement::$armed=true;QueuedPageCleanupStatement::$fault=$fault;QueuedPageCleanupStatement::$hits=0;$caught=null;$returned=false;
  try{$result=$idem?$s->maintain('tenant','alice','orders.create'):$s->$action('tenant','orders','admin');$returned=true;}catch(SecurityException $error){$caught=$error;}
  QueuedPageCleanupStatement::$armed=false;Check::same(true,$caught instanceof SecurityException);Check::same(false,$returned);Check::same('sql.cleanup',$caught->reason());Check::same(1,QueuedPageCleanupStatement::$hits);Check::same($before,$snapshot());Check::same(false,$e->pdo->inTransaction());Check::same(false,strpos((string)$caught,'owned-private-queued-page')!==false);
  $chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
  $property=new ReflectionProperty($s,'unit');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}try{$property->getValue($s)->query('SELECT 1');throw new RuntimeException('Uncertain page unit reused');}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}
  if($idem){Check::same($calls,$e->handlerCalls);}++$cases;++$faultCases;
 }catch(Throwable $error){$failures[]=['case'=>$action.'/'.$population.'/'.$fault,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{QueuedPageCleanupStatement::$armed=false;if($e!==null){$e->close();}}
}}foreach(['normal','revoked'] as $mode){$e=null;
 try{
  $idem=$action==='idempotency';$e=$idem?new IdempotencyEnvironment($mysql):new OutboxEnvironment($mysql);$s=$e->service();
  if($idem){$s->initialize('tenant','alice','orders.create');$s->execute($e->request(),$e->handler());}else{$s->initialize('tenant','orders','admin');$e->append($s,$e->message());}
  $e->allowed=$mode==='normal';$e->managed=$mode==='normal';$result=$idem?$s->maintain('tenant','alice','orders.create'):$s->$action('tenant','orders','admin');
  if($mode==='revoked'){Check::same(null,$result);}else{Check::same(true,is_array($result));Check::same(true,$result['complete']);if($action==='candidates'){Check::same(1,count($result['records']));Check::same(1,$result['next_cursor']);}else{Check::same(1,$result['scanned']);Check::same(0,$result['rekeyed']);if($idem){Check::same(0,$result['compacted']);}elseif($action==='maintain'){Check::same(0,$result['purged']);Check::same(0,$result['retired']);}}}
  if($idem){Check::same(1,$e->handlerCalls);Check::same(1,$e->count());}else{Check::same('pending',$e->rows()[0]['status']);}Check::same(false,$e->pdo->inTransaction());++$cases;++$normalCases;
 }catch(Throwable $error){$failures[]=['case'=>$action.'/'.$mode,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion'];}
 finally{if($e!==null){$e->close();}}
}}
echo json_encode(['cases'=>$cases,'fault_cases'=>$faultCases,'normal_and_denial_cases'=>$normalCases,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;if($failures){throw new RuntimeException('Queued page cleanup failures retained');}echo 'PASS queued page cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
