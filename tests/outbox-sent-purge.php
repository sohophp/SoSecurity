<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
use SoSecurity\Exception\SecurityException;
ini_set('zend.exception_ignore_args','0');
final class SentPurgeStatement extends InboxTestStatement
{
 public static $armed=false;public static $mode='';public static $counts=0;public static $closes=0;
 private function target():bool{return self::$armed&&preg_match('/\ADELETE FROM (?:main\.)?sosecurity_outbox_records WHERE /',$this->queryString)===1;}
 public function rowCount():int {
  if($this->target()){++self::$counts;if(in_array(self::$mode,['count-throw','combined'],true)){throw new RuntimeException('owned-private-sent-count');}if(self::$mode==='count-negative'){return -1;}}
  return parent::rowCount();
 }
 public function closeCursor():bool {
  if($this->target()){++self::$closes;if(in_array(self::$mode,['close-throw','combined'],true)){throw new RuntimeException('owned-private-sent-close');}if(self::$mode==='close-false'){return false;}}
  return parent::closeCursor();
 }
}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Use owned disposable SQL only.');}
$cases=0;$failures=[];
foreach(['close-false','close-throw','count-throw','count-negative','combined','zero','corrupt','normal','not-expired','request-deny','commit-deny','return-deny'] as $mode){
 $e=null;
 try{
  SentPurgeStatement::$armed=false;$e=new OutboxEnvironment($mysql,new SoSecurity\Outbox\Policy(['message_age'=>3,'recovery_age'=>10,'retention_seconds'=>0,'lease_seconds'=>1,'maximum_entries'=>1]));$e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[SentPurgeStatement::class,[$e->pdo]]);$s=$e->service();
  $s->initialize('tenant','orders','admin');$message=$e->message();$e->append($s,$message);$claim=$s->claimInitialMessage('tenant','orders','worker',$message->id());Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
  if($mode==='corrupt'){$e->pdo->exec('UPDATE sosecurity_outbox_records SET sent_at=sent_at+1');}
  $snapshot=static function()use($e):string{return hash('sha256',json_encode([$e->pdo->query('SELECT * FROM sosecurity_outbox_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC),$e->rows()]));};$before=$snapshot();$beforeRows=$e->rows();
  if($mode!=='not-expired'){$e->clock->time+=3;}
  $fired=false;if($mode==='zero'){$e->pdo->beforeStatement=static function(string $sql)use($e,&$fired):void{if(!$fired&&preg_match('/\ADELETE FROM (?:main\.)?sosecurity_outbox_records WHERE /',$sql)){$fired=true;$e->pdo->exec('DELETE FROM sosecurity_outbox_records');}};}
  if(in_array($mode,['request-deny','commit-deny','return-deny'],true)){$denied=substr($mode,0,-5);$e->onManagement=static function(string $action,string $phase)use($denied):bool{return $action!=='maintain'||$phase!==$denied;};}
  SentPurgeStatement::$armed=true;SentPurgeStatement::$mode=$mode;SentPurgeStatement::$counts=0;SentPurgeStatement::$closes=0;$result=null;$caught=null;
  try{$result=$s->maintain('tenant','orders','admin',1);}catch(SecurityException $error){$caught=$error;}
  SentPurgeStatement::$armed=false;$e->pdo->beforeStatement=null;
  if($mode==='normal'||$mode==='return-deny'){
   Check::same(0,$e->count());Check::same(false,$snapshot()===$before);
   if($mode==='normal'){Check::same(null,$caught);Check::same(1,$result['purged']);Check::same(1,$result['scanned']);}
   else{Check::same(true,$caught instanceof SecurityException);Check::same('outbox.denied',$caught->reason());Check::same(null,$result);}
   $property=new ReflectionProperty($s,'unit');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}Check::same(true,$property->getValue($s)->committed());
   if($mode==='normal'){try{$e->append($s,$message);throw new RuntimeException('Expired sent ID revived');}catch(SecurityException $error){Check::same('outbox.expired',$error->reason());}$fresh=$e->message('owned-after-purge');$next=$e->append($s,$fresh);Check::same(2,$next->order());Check::same($fresh->id(),$next->id());Check::same(1,$e->count());}
  }elseif($mode==='not-expired'){
   Check::same(null,$caught);Check::same(0,$result['purged']);Check::same($beforeRows,$e->rows());
  }elseif($mode==='request-deny'){
   Check::same(null,$caught);Check::same(null,$result);Check::same($before,$snapshot());
  }else{
   Check::same(true,$caught instanceof SecurityException);Check::same(null,$result);Check::same($before,$snapshot());Check::same(false,strpos((string)$caught,'owned-private-sent-')!==false);
   Check::same(in_array($mode,['zero','corrupt'],true)?'outbox.corrupt':($mode==='commit-deny'?'outbox.denied':'sql.cleanup'),$caught->reason());
   if(!in_array($mode,['zero','corrupt','commit-deny'],true)){
    $chain=$caught;$depth=0;while($chain!==null){Check::same(true,++$depth<=8);Check::same(SoSecurity\Storage\StorageException::class,get_class($chain));$chain=$chain->getPrevious();}
    $property=new ReflectionProperty($s,'unit');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}try{$property->getValue($s)->query('SELECT 1');throw new RuntimeException('Uncertain sent purge unit reused');}catch(SecurityException $error){Check::same('sql.cleanup',$error->reason());}
   }
  }
  $expect=in_array($mode,['not-expired','request-deny','corrupt'],true)?0:1;Check::same($expect,SentPurgeStatement::$counts);Check::same($expect,SentPurgeStatement::$closes);Check::same($mode==='zero',$fired);Check::same(false,$e->pdo->inTransaction());++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$mode,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{SentPurgeStatement::$armed=false;if($e!==null){$e->close();}}
}
echo json_encode(['cases'=>$cases,'failures'=>$failures,'assertions'=>Check::$assertions]).PHP_EOL;if($failures){throw new RuntimeException('Sent purge failures retained');}echo 'PASS sent outbox purge '.($mysql?'mysql':'sqlite').PHP_EOL;
