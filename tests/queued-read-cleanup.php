<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';require __DIR__.'/idempotency-support.php';
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class QueuedReadCleanupStatement extends InboxTestStatement
{
 public static $component='';public static $stage='';public static $fault='';public static $hits=0;
 private function target():bool {
  $sql=$this->queryString;if(strpos($sql,'SELECT ')!==0||self::$stage===''){return false;}
  $root=preg_match('/FROM (?:main\.)?sosecurity_'.self::$component.'_roots WHERE namespace=:namespace/',$sql)===1;
  if(in_array(self::$stage,['root-empty','root-present'],true)){return $root;}
  if(!preg_match('/FROM (?:main\.)?sosecurity_'.self::$component.'_records WHERE namespace=:namespace/',$sql)){return false;}
  if(self::$stage==='body'){return strpos($sql,':bytes')!==false;}
  if(self::$stage==='record'){return strpos($sql,' AND key_hash=:key_hash')!==false&&strpos($sql,':bytes')===false;}
  if(self::$stage==='history'){return strpos($sql,'SELECT 1 FROM ')!==0&&strpos($sql,' AND key_hash=:key_hash')===false&&strpos($sql,'ORDER BY ')!==false;}
  if(self::$stage==='orphan'){return strpos($sql,'SELECT 1 FROM ')===0&&strpos($sql,'aggregate_hash')===false;}
  return self::$stage==='predecessor'&&strpos($sql,'SELECT 1 FROM ')===0&&strpos($sql,'aggregate_hash')!==false;
 }
 public function closeCursor():bool {
  if($this->target()){++self::$hits;if(self::$fault==='throw'){throw new RuntimeException('owned-private-queued-read');}return false;}
  return parent::closeCursor();
 }
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use owned disposable SQL only.');}
$cases=0;$faultCases=0;$normalCases=0;$failures=[];
foreach(['outbox','idempotency'] as $component){
 $stages=['root-empty','root-present','history','record','body','orphan'];if($component==='outbox'){$stages[]='predecessor';}
 foreach($stages as $stage){foreach(['false','throw'] as $fault){$e=null;$label=$component.'/'.$stage.'/'.$fault;
  try{
   QueuedReadCleanupStatement::$stage='';$e=$component==='outbox'?new OutboxEnvironment($mysql):new IdempotencyEnvironment($mysql);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[QueuedReadCleanupStatement::class,[$e->pdo]]);$s=$e->service();
   if(!in_array($stage,['root-empty','orphan'],true)){
    if($component==='outbox'){$s->initialize('tenant','orders','admin');if($stage!=='root-present'){$e->append($s,$e->message());}}
    else{$s->initialize('tenant','alice','orders.create');if($stage!=='root-present'){$s->execute($e->request(),$e->handler());}}
   }
   $snapshot=static function()use($e,$component):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM sosecurity_'.$component.'_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$component==='outbox'?$e->rows():$e->records(),$component==='outbox'?$e->business():$e->count()]));};$before=$snapshot();$handlerCalls=$component==='idempotency'?$e->handlerCalls:0;
   QueuedReadCleanupStatement::$component=$component;QueuedReadCleanupStatement::$stage=$stage;QueuedReadCleanupStatement::$fault=$fault;QueuedReadCleanupStatement::$hits=0;$caught=null;$returned=false;
   try{
    if(in_array($stage,['root-empty','root-present','orphan'],true)){if($component==='outbox'){$s->initialize('tenant','orders','admin');}else{$s->initialize('tenant','alice','orders.create');}}
    elseif($component==='outbox'){$s->claimInitialMessage('tenant','orders','worker',$e->message()->id());}
    else{$s->lookup($e->request());}
    $returned=true;
   }catch(SecurityException $error){$caught=$error;}
   QueuedReadCleanupStatement::$stage='';Check::same(true,$caught instanceof SecurityException);Check::same(false,$returned);Check::same('sql.cleanup',$caught->reason());Check::same(false,strpos((string)$caught,'owned-private-queued-read')!==false);Check::same(1,QueuedReadCleanupStatement::$hits);Check::same($before,$snapshot());
   $chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
   $property=new ReflectionProperty($s,'unit');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}try{$property->getValue($s)->query('SELECT 1');throw new RuntimeException('Uncertain read unit reused');}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}
   if($component==='idempotency'){Check::same($handlerCalls,$e->handlerCalls);}Check::same(false,$e->pdo->inTransaction());++$faultCases;++$cases;
  }catch(Throwable $error){$failures[]=['case'=>$label,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
  finally{QueuedReadCleanupStatement::$stage='';if($e!==null){$e->close();}}
 }}
 foreach(['normal','revoked'] as $mode){$e=null;
  try{
   $e=$component==='outbox'?new OutboxEnvironment($mysql):new IdempotencyEnvironment($mysql);$s=$e->service();
   if($component==='outbox'){$s->initialize('tenant','orders','admin');$m=$e->message('owned-read-body');$e->append($s,$m);$e->allowed=$mode==='normal';$claim=$s->claimInitialMessage('tenant','orders','worker',$m->id());if($mode==='normal'){Check::same($m->body(),$claim->message()->body());Check::same(1,$claim->status()->attempts());}else{Check::same(null,$claim);Check::same('pending',$e->rows()[0]['status']);}}
   else{$s->initialize('tenant','alice','orders.create');$first=$s->execute($e->request(),$e->handler());Check::same(false,$first->replayed());$e->allowed=$mode==='normal';$lookup=$s->lookup($e->request());if($mode==='normal'){Check::same(true,$lookup->replayed());Check::same($first->response()->body(),$lookup->response()->body());}else{Check::same(null,$lookup);}Check::same(1,$e->handlerCalls);Check::same(1,$e->count());}
   Check::same(false,$e->pdo->inTransaction());++$normalCases;++$cases;
  }catch(Throwable $error){$failures[]=['case'=>$component.'/'.$mode,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion'];}
  finally{if($e!==null){$e->close();}}
 }
}
echo json_encode(['cases'=>$cases,'fault_cases'=>$faultCases,'normal_and_denial_cases'=>$normalCases,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;if($failures){throw new RuntimeException('Queued read cleanup failures retained');}echo 'PASS queued read cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
