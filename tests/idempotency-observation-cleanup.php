<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/idempotency-support.php';
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
function observationInvoke($s,string $method,array $arguments){$m=new ReflectionMethod($s,$method);if(PHP_VERSION_ID<80100){$m->setAccessible(true);}return $m->invokeArgs($s,$arguments);}
function observationProperty($s,string $name){$p=new ReflectionProperty($s,$name);if(PHP_VERSION_ID<80100){$p->setAccessible(true);}return $p->getValue($s);}
final class IdempotencyObservationStatement extends InboxTestStatement {
 public static $stage='';public static $fault='';public static $hits=0;public static $executor;public static $unit;
 public function closeCursor():bool {
  $sql=$this->queryString;$stage=self::$stage;$hit=false;
  if(strpos($stage,'orphan')===0){$hit=preg_match('/\ASELECT 1 FROM (?:main\.)?sosecurity_idempotency_records WHERE namespace=:namespace LIMIT 1\z/',$sql)===1;}
  elseif(strpos($stage,'roots-count')===0){$hit=preg_match('/\ASELECT COUNT\(\*\) FROM (?:main\.)?sosecurity_idempotency_roots\z/',$sql)===1;}
  elseif(strpos($stage,'request-count')===0){$hit=preg_match('/\ASELECT COUNT\(\*\) FROM (?:main\.)?sosecurity_idempotency_records\z/',$sql)===1;}
  elseif(strpos($stage,'maintenance')===0){$hit=strpos($sql,'SELECT ')===0&&strpos($sql,'sosecurity_idempotency_records WHERE namespace=:namespace AND key_hash>:after_key ORDER BY ')!==false;}
  if($stage!==''&&$hit){++self::$hits;if(self::$fault!=='normal'){self::$unit=observationProperty(self::$executor,'unit');if(self::$fault==='throw'){throw new RuntimeException('owned-private-idempotency-observation');}return false;}}
  return parent::closeCursor();
 }
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use owned disposable SQL only.');}
$stages=['orphan-empty','orphan-present','roots-count-empty','roots-count-other','maintenance-empty','maintenance-populated','request-count-empty','request-count-other'];$cases=0;$faultCases=0;$normalCases=0;$failures=[];
foreach(array_merge($stages,['roots-count-skip','request-count-skip']) as $stage){foreach(in_array($stage,$stages,true)?['false','throw','normal']:['normal'] as $fault){$e=null;
 try{
  $e=new IdempotencyEnvironment($mysql);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[IdempotencyObservationStatement::class,[$e->pdo]]);$s=$e->service();
  if($stage==='roots-count-other'){$s->initialize('other','alice','orders.create');}
  elseif(strpos($stage,'maintenance')===0||strpos($stage,'request-count')===0||$stage==='orphan-present'||$stage==='roots-count-skip'){$s->initialize('tenant','alice','orders.create');if(in_array($stage,['maintenance-populated','request-count-other','request-count-skip','orphan-present'],true)){$s->execute($e->request(),$e->handler());}}
  if($stage==='orphan-present'){$e->pdo->exec('DELETE FROM sosecurity_idempotency_roots');}
  $namespace=observationInvoke($s,'namespace',['tenant','alice','orders.create']);$original=observationProperty($s,'unit');$calls=$e->handlerCalls;
  $snapshot=static function()use($e):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM sosecurity_idempotency_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$e->records(),$e->count()]));};$before=$snapshot();
  IdempotencyObservationStatement::$stage=$stage;IdempotencyObservationStatement::$fault=$fault;IdempotencyObservationStatement::$hits=0;IdempotencyObservationStatement::$executor=$s;IdempotencyObservationStatement::$unit=null;$caught=null;$returned=false;$result=null;
  try{
   if(strpos($stage,'request-count')===0){$request=$stage==='request-count-other'?$e->request('request-key-00000002','order-2'):$e->request();$result=observationInvoke($s,'requestObservation',[$request,new SoSecurity\Support\Deadline(30000)]);}
   else{$result=observationInvoke($s,'maintenanceObservation',[strpos($stage,'maintenance')===0?'maintain':'initialize',$namespace,1,'',new SoSecurity\Support\Deadline(30000)]);}
   $returned=true;
  }catch(SecurityException $error){$caught=$error;}
  IdempotencyObservationStatement::$stage='';Check::same($original,observationProperty($s,'unit'));Check::same(false,observationProperty($s,'observing'));Check::same($before,$snapshot());Check::same($calls,$e->handlerCalls);Check::same(false,$e->pdo->inTransaction());
  if($fault!=='normal'){
   Check::same(false,$returned);Check::same(true,$caught instanceof SecurityException);Check::same('sql.cleanup',$caught->reason());Check::same(1,IdempotencyObservationStatement::$hits);Check::same(false,strpos((string)$caught,'owned-private-idempotency-observation')!==false);
   $chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
   $unit=IdempotencyObservationStatement::$unit;Check::same(true,$unit instanceof SoSecurity\Support\SqlTransaction);Check::same(true,$unit->isObservation());try{$unit->query('SELECT 1');throw new RuntimeException('Uncertain observation unit reused');}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}++$faultCases;
  }else{
   Check::same(substr($stage,-5)==='-skip'?0:1,IdempotencyObservationStatement::$hits);
   if($stage==='orphan-present'){Check::same(false,$returned);Check::same('idempotency.history',$caught->reason());}
   else{Check::same(true,$returned);Check::same(null,$caught);$total=in_array($stage,['roots-count-other','request-count-other'],true)?1:0;Check::same($total,$result['total']);if($stage==='request-count-skip'){Check::same('done',$result['row']['status']);}elseif(strpos($stage,'request-count')===0){Check::same(null,$result['row']);}}
   ++$normalCases;
  }
  ++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$stage.'/'.$fault,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{IdempotencyObservationStatement::$stage='';IdempotencyObservationStatement::$executor=null;IdempotencyObservationStatement::$unit=null;if($e!==null){$e->close();}}
}}
echo json_encode(['cases'=>$cases,'fault_cases'=>$faultCases,'normal_and_skip_cases'=>$normalCases,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;if($failures){throw new RuntimeException('Idempotency observation failures retained');}echo 'PASS idempotency observation cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
