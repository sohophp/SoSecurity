<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/audit-sql-support.php';
use SoSecurity\Audit\SqlSink;
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class AuditCleanupStatement extends PDOStatement {
 public static $stage='';public static $fault='';public static $pdo;public static $sink;public static $unit;public static $closeHits=0;public static $countHits=0;public static $actualCount=null;
 protected function __construct(){}
 private function selected():bool {
  $sql=$this->queryString;$stage=self::$stage;if($stage===''){return false;}
  if(in_array($stage,['root-empty','root-existing'],true)){return strpos($sql,'SELECT ')===0&&strpos($sql,'sosecurity_audit_roots WHERE site=:site')!==false;}
  if($stage==='site-count'){return strpos($sql,'SELECT COUNT(*) FROM (SELECT sequence_no FROM ')===0;}
  if($stage==='total-count'){return strpos($sql,'SELECT COUNT(*) FROM (SELECT site FROM ')===0;}
  if($stage==='prune-page'){return strpos($sql,'SELECT sequence_no FROM ')===0&&strpos($sql,'sosecurity_audit_records WHERE site=:site AND expires_at<=:now')!==false;}
  if($stage==='history-page'){return strpos($sql,'SELECT ')===0&&strpos($sql,'sequence_no>:after')!==false;}
  if($stage==='root-insert'){return strpos($sql,'INSERT INTO ')===0&&strpos($sql,'sosecurity_audit_roots')!==false;}
  if($stage==='record-insert'){return strpos($sql,'INSERT INTO ')===0&&strpos($sql,'sosecurity_audit_records')!==false;}
  if($stage==='record-delete'){return strpos($sql,'DELETE FROM ')===0&&strpos($sql,'sosecurity_audit_records')!==false;}
  return $stage==='root-update'&&strpos($sql,'UPDATE ')===0&&strpos($sql,'sosecurity_audit_roots')!==false;
 }
 private function capture():void {if(self::$unit===null){$p=new ReflectionProperty(self::$sink,'unit');if(PHP_VERSION_ID<80100){$p->setAccessible(true);}self::$unit=$p->getValue(self::$sink);}}
 public function execute($parameters=null):bool {
  if($this->selected()&&self::$stage==='record-delete'&&self::$fault==='count-zero'){self::$pdo->exec('DELETE FROM sosecurity_audit_records');}
  return $parameters===null?parent::execute():parent::execute($parameters);
 }
 public function rowCount():int {
  $actual=parent::rowCount();if($this->selected()){++self::$countHits;self::$actualCount=$actual;$this->capture();if(self::$fault==='count-throw'){throw new RuntimeException('owned-private-audit-result');}if(self::$fault==='count-negative'){return -1;}if(self::$fault==='count-zero'){return 0;}if(self::$fault==='count-many'){return 2;}}return $actual;
 }
 public function closeCursor():bool {
  if($this->selected()){++self::$closeHits;$this->capture();if(self::$fault==='close-false'){return false;}if(self::$fault==='close-throw'){throw new RuntimeException('owned-private-audit-close');}}return parent::closeCursor();
 }
}
$mysql=($argv[1]??'sqlite')==='mysql';$cases=0;$faultCases=0;$normalCases=0;$failures=[];$spec=[];
foreach(['root-empty','root-existing','site-count','prune-page','history-page','total-count'] as $stage){foreach(['close-false','close-throw'] as $fault){$spec[]=[$stage,$fault];}}
foreach(['root-insert','record-insert','record-delete','root-update'] as $stage){foreach(['close-false','close-throw','count-throw','count-negative','count-many'] as $fault){$spec[]=[$stage,$fault];}if($stage!=='root-update'){$spec[]=[$stage,'count-zero'];}}
foreach($spec as $pair){list($stage,$fault)=$pair;$e=null;
 try{
  $e=new AuditSqlEnvironment($mysql);$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[AuditCleanupStatement::class,[]]);$sink=new SqlSink($e->pdo,'owned-audit-cleanup',3,60,$e->clock,1000,static function():bool{return true;},static function():bool{return true;});
  if(!in_array($stage,['root-empty','root-insert'],true)){$sink->initialize();if(in_array($stage,['prune-page','history-page','record-delete'],true)){$sink(auditSqlRecord());}}if(in_array($stage,['prune-page','record-delete'],true)){$e->clock->time+=60;}
  $snapshot=static function()use($e):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM sosecurity_audit_roots ORDER BY site')->fetchAll(PDO::FETCH_ASSOC),$e->pdo->query('SELECT * FROM sosecurity_audit_records ORDER BY site,sequence_no')->fetchAll(PDO::FETCH_ASSOC)]));};$before=$snapshot();
  AuditCleanupStatement::$stage=$stage;AuditCleanupStatement::$fault=$fault;AuditCleanupStatement::$pdo=$e->pdo;AuditCleanupStatement::$sink=$sink;AuditCleanupStatement::$unit=null;AuditCleanupStatement::$closeHits=0;AuditCleanupStatement::$countHits=0;AuditCleanupStatement::$actualCount=null;$returned=false;$caught=null;
  try{if(in_array($stage,['root-empty','root-insert'],true)){$sink->initialize();}elseif(in_array($stage,['root-existing','history-page'],true)){$sink->records();}elseif(in_array($stage,['prune-page','record-delete'],true)){$sink->prune();}elseif($stage==='total-count'){$p=new ReflectionProperty($sink,'unit');$m=new ReflectionMethod($sink,'total');if(PHP_VERSION_ID<80100){$p->setAccessible(true);$m->setAccessible(true);}$u=$p->getValue($sink);$u->run(static function()use($m,$sink){return $m->invoke($sink,3);});}else{$sink(auditSqlRecord());}$returned=true;}catch(SecurityException $error){$caught=$error;}
  AuditCleanupStatement::$stage='';$reason=in_array($fault,['count-zero','count-many'],true)?'audit.sql_corrupt':'sql.cleanup';
  Check::same(false,$returned);Check::same(true,$caught instanceof SecurityException);Check::same($reason,$caught->reason());Check::same($before,$snapshot());Check::same(false,$e->pdo->inTransaction());Check::same(1,AuditCleanupStatement::$closeHits);Check::same(false,strpos((string)$caught,'owned-private-audit-')!==false);
  $chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
  if(in_array($reason,['sql.cleanup','sql.unavailable'],true)){$unit=AuditCleanupStatement::$unit;Check::same(true,$unit instanceof SoSecurity\Support\SqlTransaction);try{$unit->query('SELECT 1');throw new RuntimeException('Uncertain audit unit reused');}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}}
  if($stage==='record-delete'&&$fault==='count-zero'){Check::same(0,AuditCleanupStatement::$actualCount);Check::same(1,$e->count());}++$faultCases;++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$stage.'/'.$fault,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{AuditCleanupStatement::$stage='';AuditCleanupStatement::$pdo=null;AuditCleanupStatement::$sink=null;AuditCleanupStatement::$unit=null;if($e!==null){$e->close();}}
}
foreach(['lifecycle','noop','read-denied','prune-denied','read-commit-denied','prune-commit-denied','full-page'] as $mode){$e=null;
 try{
  $e=new AuditSqlEnvironment($mysql);$allow=true;$calls=0;$guard=static function()use(&$allow,&$calls,$mode):bool{++$calls;return $allow&&(!in_array($mode,['read-commit-denied','prune-commit-denied'],true)||$calls===1);};$sink=new SqlSink($e->pdo,'owned-audit-normal',100,60,$e->clock,1000,$guard,$guard);$sink->initialize();$sink(auditSqlRecord('first.event'));
  if($mode==='lifecycle'){$sink->initialize();$sink(auditSqlRecord('second.event'));Check::same(2,count($sink->records()));Check::same(1,$sink->records(0,1)[0]['sequence']);Check::same(2,$sink->records(1,1)[0]['sequence']);$e->clock->time+=60;Check::same(1,$sink->prune(1));$sink(auditSqlRecord('third.event'));$rows=$sink->records();Check::same(1,count($rows));Check::same(3,$rows[0]['sequence']);Check::same('third.event',$rows[0]['record']['event']);}
  elseif($mode==='noop'){$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[AuditCleanupStatement::class,[]]);AuditCleanupStatement::$stage='root-update';AuditCleanupStatement::$fault='normal';AuditCleanupStatement::$sink=$sink;AuditCleanupStatement::$unit=null;AuditCleanupStatement::$actualCount=null;Check::same(0,$sink->prune());AuditCleanupStatement::$stage='';Check::same($mysql?0:1,AuditCleanupStatement::$actualCount);Check::same(1,$e->count());Check::same(1,count($sink->records()));}
  elseif($mode==='full-page'){for($i=1;$i<100;++$i){$record=auditSqlRecord();$record['scope']=str_repeat('\\',256);$record['subject']=str_repeat('a',64);$sink($record);}Check::same(100,count($sink->records(0,100)));Check::same(true,memory_get_peak_usage(true)<=8388608);}
  else{$before=$e->pdo->query('SELECT * FROM sosecurity_audit_roots')->fetchAll(PDO::FETCH_ASSOC);$calls=0;if(strpos($mode,'commit')===false){$allow=false;}if(strpos($mode,'prune')===0){$e->clock->time+=60;}Check::throws(SecurityException::class,static function()use($sink,$mode){if(strpos($mode,'read')===0){$sink->records();}else{$sink->prune();}});Check::same(1,$e->count());Check::same($before,$e->pdo->query('SELECT * FROM sosecurity_audit_roots')->fetchAll(PDO::FETCH_ASSOC));}
  Check::same(false,$e->pdo->inTransaction());++$normalCases;++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$mode,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{AuditCleanupStatement::$stage='';AuditCleanupStatement::$pdo=null;AuditCleanupStatement::$sink=null;AuditCleanupStatement::$unit=null;if($e!==null){$e->close();}}
}
echo json_encode(['cases'=>$cases,'fault_cases'=>$faultCases,'normal_and_denial_cases'=>$normalCases,'failures'=>$failures,'assertions'=>Check::$assertions,'peak_bytes'=>memory_get_peak_usage(true)]).PHP_EOL;if($failures){throw new RuntimeException('SQL audit cleanup failures retained');}echo 'PASS SQL audit cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
