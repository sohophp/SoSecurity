<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Exception\SecurityException;
final class ProcessingReadStatement extends InboxTestStatement
{
 public static $needle='';public static $fault='';public static $closes=0;public static $pending=[];
 private function selected():bool{return self::$needle!==''&&strpos($this->queryString,self::$needle)!==false;}
 private function reading():void{if($this->selected()&&in_array(self::$fault,['read','read-close'],true)){throw new RuntimeException('PRIVATE-PROCESSING-READ');}}
 public function fetchAll($mode=null,$className=null,$ctorArgs=null,...$extra):array{$this->reading();return parent::fetchAll(...func_get_args());}
 #[\ReturnTypeWillChange]
 public function fetch($mode=PDO::FETCH_DEFAULT,$orientation=PDO::FETCH_ORI_NEXT,$offset=0){$this->reading();return parent::fetch($mode,$orientation,$offset);}
 #[\ReturnTypeWillChange]
 public function fetchColumn($column=0){$this->reading();return parent::fetchColumn($column);}
 public function closeCursor():bool{if($this->selected()){++self::$closes;self::$pending[]=$this;if(self::$fault==='throw'){throw new RuntimeException('PRIVATE-PROCESSING-CLOSE');}if(in_array(self::$fault,['false','read-close'],true)){return false;}}return parent::closeCursor();}
 private function releaseOwnedCursor():void{parent::closeCursor();}
 public static function drain():void{foreach(self::$pending as $q){$q->releaseOwnedCursor();}self::$pending=[];}
}
function processingReadInvoke($object,string $method,array $args){$m=new ReflectionMethod($object,$method);if(PHP_VERSION_ID<80100){$m->setAccessible(true);}return $m->invokeArgs($object,$args);}
function processingReadProperty($object,string $name, $value=null,bool $write=false){$p=new ReflectionProperty($object,$name);if(PHP_VERSION_ID<80100){$p->setAccessible(true);}if($write){$p->setValue($object,$value);return null;}return $p->getValue($object);}
$mysql=($argv[1]??'sqlite')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner'))){throw new RuntimeException('Owned SQL required');}
$cases=0;$failures=[];
foreach(['status','source','payload'] as $operation){foreach(['false','throw','read-close','read','normal'] as $fault){$e=null;$caught=null;
 try{
  $e=new InboxEnvironment($mysql);$receipt=$e->receive();Check::same(true,$receipt instanceof SoSecurity\Webhook\Receipt);$before=$e->snapshot();$guards=0;
  $e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');foreach(explode(';',file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql')) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
  $processor=new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(){throw new RuntimeException('No mapper for private reads');},static function(){throw new RuntimeException('No association for private reads');},static function()use(&$guards){++$guards;return true;},null,$e->clock);
  processingReadProperty($processor,'deadline',new SoSecurity\Support\Deadline(30000),true);$source=processingReadInvoke($processor,'source',[$receipt->id(),false]);
  $e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ProcessingReadStatement::class,[$e->pdo]]);ProcessingReadStatement::$needle=$operation==='status'?'sosecurity_webhook_processing WHERE':($operation==='source'?' AS bytes FROM ':'SELECT payload FROM ');ProcessingReadStatement::$fault=$fault;ProcessingReadStatement::$closes=0;$result=null;
  try{$result=$operation==='status'?$processor->status($receipt->id(),'owned-worker'):processingReadInvoke($processor,$operation,$operation==='source'?[$receipt->id(),false]:[$source]);}catch(SecurityException $error){$caught=$error;}
  ProcessingReadStatement::$needle='';
  if($fault==='normal'){Check::same(null,$caught);if($operation==='status'){Check::same(null,$result);}elseif($operation==='payload'){Check::same($e->body(),$result);}else{Check::same($source,$result);}}
  else{Check::same(true,$caught instanceof SecurityException);$reason=$fault==='read'?'webhook.inbox_unavailable':($operation==='status'?'webhook.processing_cleanup':'webhook.inbox_cleanup');Check::same($reason,$caught->reason());$current=$caught;$depth=0;while($current!==null){Check::same(true,++$depth<=8);Check::same(true,$current instanceof SecurityException);Check::same(false,strpos($current->getMessage(),'PRIVATE-PROCESSING')!==false);$current=$current->getPrevious();}Check::same($fault!=='read',processingReadProperty($processor,'failed'));
   if($fault!=='read'){$calls=$guards;$second=null;try{$processor->status($receipt->id(),'owned-worker');}catch(SecurityException $error){$second=$error;}Check::same(true,$second instanceof SecurityException);Check::same('webhook.processing_cleanup',$second->reason());Check::same($calls,$guards);}
  }
  Check::same(1,ProcessingReadStatement::$closes);Check::same($before,$e->snapshot());Check::same(0,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_processing')->fetchColumn());Check::same(false,$e->pdo->inTransaction());Check::same(true,memory_get_peak_usage(true)<=8388608);++$cases;
 }catch(Throwable $error){$failures[]=['case'=>$operation.'/'.$fault,'class'=>get_class($error),'reason'=>$error instanceof SecurityException?$error->reason():'test.assertion','caught_reason'=>$caught instanceof SecurityException?$caught->reason():null,'close_calls'=>ProcessingReadStatement::$closes,'assertion'=>$error instanceof SecurityException?null:$error->getMessage(),'duration_backwards'=>strpos($error->getMessage(),'Security duration clock moved backwards;')===0];}
 finally{ProcessingReadStatement::$needle='';ProcessingReadStatement::drain();if($e!==null){$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');$e->close();}}
}}
echo json_encode(['cases'=>$cases,'failures'=>$failures,'assertions'=>Check::$assertions,'peak_bytes'=>memory_get_peak_usage(true)]).PHP_EOL;if($failures){throw new RuntimeException('Processing read cleanup failures retained');}echo 'PASS processing read cleanup '.($mysql?'mysql':'sqlite').PHP_EOL;
